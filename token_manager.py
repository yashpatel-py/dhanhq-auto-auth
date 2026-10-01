"""
Automatic Dhan token management.

Handles:
  1. Generate new access token via PIN + TOTP (daily)
  2. Renew token before expiry
  3. Validate token is still working
  4. Persist token to disk (.dhan_token.json)

Token lifecycle:
  - Dhan access tokens expire daily (end of day or ~24h)
  - On each trading day start, generate a fresh token
  - Before each API call batch, validate & renew if needed

Concurrency:
  Several processes start independently and all call get_valid_token()
  (skew_hunter's scheduler / dashboard / watchdog, swing_dual_momentum's
  tracker). Dhan issues ONE live access token per client, so two
  simultaneous logins mean the second silently invalidates the first and
  whichever bot cached the older token starts failing mid-session. A
  cross-process lock file serialises the mutating paths so exactly one
  process logs in and the others reuse the token it writes.
"""
import base64
import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from datetime import datetime, date
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")
logger = logging.getLogger("auth.token_manager")

# Shared package: credentials and the daily token live INSIDE this
# directory so every strategy under strategy_by_ai/ uses the same ones.
_PKG_DIR = os.path.abspath(os.path.dirname(__file__))
CREDS_FILE = os.path.join(_PKG_DIR, ".dhan_credentials.json")
TOKEN_FILE = os.path.join(_PKG_DIR, ".dhan_token.json")
LOCK_FILE = os.path.join(_PKG_DIR, ".dhan_token.lock")

# A PIN+TOTP round-trip takes a few seconds, and the retry path waits at most
# one 30s TOTP window. A lock older than this belonged to a process that died
# mid-login, so it is safe to break.
LOCK_STALE_SEC = 180
LOCK_WAIT_SEC = 240

_cached_token: dict | None = None
_token_date: date | None = None
_thread_lock = threading.Lock()   # guards the mutating path within one process


def _load_credentials() -> dict:
    if not os.path.exists(CREDS_FILE):
        raise FileNotFoundError(
            "No credentials found. Run: python credentials_setup.py in strategy_by_ai/yash_dhan_auth"
        )
    with open(CREDS_FILE) as f:
        return json.load(f)


def _save_token(client_id: str, access_token: str) -> None:
    global _cached_token, _token_date
    today_ist = datetime.now(IST).date()
    data = {
        "client_id": client_id,
        "access_token": access_token,
        "generated_at": datetime.now(IST).isoformat(),
        "generated_date": today_ist.isoformat(),
    }
    tmp = TOKEN_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, TOKEN_FILE)

    _cached_token = data
    _token_date = today_ist

    logger.info(f"Token saved (generated {data['generated_at']})")


def _load_saved_token() -> dict | None:
    global _cached_token, _token_date
    today_ist = datetime.now(IST).date()
    if _cached_token and _token_date == today_ist:
        return _cached_token
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE) as f:
                data = json.load(f)
            _cached_token = data
            _token_date = today_ist if data.get("generated_date") == today_ist.isoformat() else None
            return data
        except (json.JSONDecodeError, IOError):
            pass
    return None


def _invalidate_cache() -> None:
    """Drop the in-process cache so the next read comes from disk.

    Needed after taking the cross-process lock: another process may have
    written a fresh token while we were queued behind it.
    """
    global _cached_token, _token_date
    _cached_token = None
    _token_date = None


def _is_from_today(saved: dict | None) -> bool:
    return bool(saved) and saved.get("generated_date") == datetime.now(IST).date().isoformat()


@contextmanager
def _login_lock(wait: int = LOCK_WAIT_SEC):
    """Serialise token generation/renewal across processes AND threads.

    O_CREAT|O_EXCL is atomic on Windows and POSIX alike, so the create either
    wins outright or tells us somebody else holds the lock.
    """
    with _thread_lock:
        deadline = time.time() + wait
        fd = None
        while True:
            try:
                fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, f"{os.getpid()} {datetime.now(IST).isoformat()}\n".encode())
                break
            except FileExistsError:
                try:
                    age = time.time() - os.path.getmtime(LOCK_FILE)
                except OSError:
                    continue        # holder released it between the two calls
                if age > LOCK_STALE_SEC:
                    logger.warning(f"Breaking stale token lock ({age:.0f}s old)")
                    try:
                        os.unlink(LOCK_FILE)
                    except OSError:
                        pass
                    continue
                if time.time() > deadline:
                    raise RuntimeError(
                        f"Timed out after {wait}s waiting for another process to finish "
                        f"Dhan login (lock: {LOCK_FILE})"
                    )
                time.sleep(1.0)
        try:
            yield
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(LOCK_FILE)
            except OSError:
                pass


def _sdk_call(what: str, fn, *args, **kwargs) -> tuple[bool, object]:
    """Call a DhanLogin method, normalising its two failure styles.

    dhanhq 2.2.0 RAISES on any non-200 response (see dhanhq/auth.py) rather
    than returning the error body. Without this wrapper every `if not resp` /
    `resp.get("remarks")` branch below is dead code and the documented
    fallbacks (renew -> fresh TOTP) never run, so a token Dhan rejects takes
    the whole day down until .dhan_token.json is deleted by hand.

    Returns (ok, payload) where payload is the response dict or an error string.
    """
    try:
        resp = fn(*args, **kwargs)
    except Exception as e:
        logger.debug(f"{what}: {e}")
        return False, str(e)
    if not resp:
        return False, "No response"
    return True, resp


def _extract_token(resp) -> str | None:
    if not isinstance(resp, dict):
        return None
    return resp.get("accessToken") or (resp.get("data") or {}).get("access_token")


def token_type(access_token: str) -> str:
    """How Dhan says the token was issued, from its own (unencrypted) claims.

    "APP"  — generated through the PIN+TOTP endpoint, i.e. by this package.
    "SELF" — generated by hand on web.dhan.co ("Generate Access Token").
    ""     — unreadable. Reading the claims needs no secret and makes no call.
    """
    try:
        part = access_token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        return str(claims.get("tokenConsumerType") or "")
    except Exception:
        return ""


def generate_token() -> tuple[str, str]:
    """Generate a fresh access token using PIN + TOTP. Returns (client_id, access_token).

    Retries once with a fresh TOTP code if the first code is rejected due to the
    30-second window expiring during the network round-trip.
    """
    import pyotp
    from dhanhq import DhanLogin

    creds = _load_credentials()
    client_id = creds["client_id"]
    pin = creds["pin"]
    totp_secret = creds["totp_secret"]
    totp = pyotp.TOTP(totp_secret)

    last_error: str = "No response"
    for totp_attempt in range(1, 3):   # At most 2 attempts (handles window boundary)
        otp_code = totp.now()
        logger.info(
            f"Generating token for {client_id} "
            f"(TOTP attempt {totp_attempt}/2, code={otp_code[-3:]}***)..."
        )

        login = DhanLogin(client_id)
        ok, resp = _sdk_call("generate_token", login.generate_token, pin=pin, totp=otp_code)

        if ok:
            access_token = _extract_token(resp)
            if access_token:
                _save_token(client_id, access_token)
                logger.info("New access token generated successfully")
                return client_id, access_token
            error_msg = str(resp.get("remarks", resp)) if isinstance(resp, dict) else str(resp)
        else:
            error_msg = str(resp)

        last_error = error_msg

        # TOTP rejected — possibly expired during the network round-trip, which
        # Dhan reports as a generic auth failure (DH-901). Wait for the next
        # 30-second window and retry exactly once.
        upper = error_msg.upper()
        if totp_attempt < 2 and any(
            k in upper for k in ("TOTP", "OTP", "DH-901", "INVALID_AUTHENTICATION")
        ):
            remaining = 30 - (int(time.time()) % 30)
            # If we're near the end of the current window, skip past it entirely
            wait = remaining + 1 if remaining > 2 else remaining + 31
            logger.warning(
                f"TOTP rejected (code may have expired, {remaining}s remaining in window) "
                f"— waiting {wait}s for fresh code..."
            )
            time.sleep(wait)
            continue

        break  # Non-TOTP error — no point retrying

    raise RuntimeError(f"Token generation failed: {last_error}")


def renew_token() -> tuple[str, str]:
    """Renew an existing token. Returns (client_id, access_token).

    Falls back to a fresh PIN+TOTP login whenever renewal cannot deliver a
    token — including when Dhan rejects the old one outright (DH-901), which
    is the common case for a token that was revoked rather than merely aged.
    """
    from dhanhq import DhanLogin

    saved = _load_saved_token()
    if not saved:
        logger.warning("No existing token to renew — generating fresh one")
        return generate_token()

    client_id = saved["client_id"]
    old_token = saved["access_token"]

    # Dhan renews only tokens made on web.dhan.co. A PIN+TOTP token (type
    # "APP") is refused every time with DH-905 "Renewal of token not allowed
    # for this token type" (seen 2026-10-02), so asking is a wasted call and
    # an error in every log. Log in again instead.
    if token_type(old_token) == "APP":
        logger.info("PIN+TOTP tokens cannot be renewed — logging in again")
        return generate_token()

    logger.info("Renewing access token...")
    login = DhanLogin(client_id)
    ok, resp = _sdk_call("renew_token", login.renew_token, old_token)

    if not ok:
        logger.warning(f"Token renewal failed ({resp}) — generating fresh token")
        return generate_token()

    new_token = _extract_token(resp)
    if not new_token:
        logger.warning(f"Token renewal failed: {resp} — generating fresh token")
        return generate_token()

    _save_token(client_id, new_token)
    logger.info("Token renewed successfully")
    return client_id, new_token


def validate_token(client_id: str, access_token: str) -> bool:
    """Check if the token is still valid by hitting user_profile."""
    from dhanhq import DhanLogin
    login = DhanLogin(client_id)
    ok, resp = _sdk_call("user_profile", login.user_profile, access_token)
    if ok and isinstance(resp, dict) and (
        resp.get("status") == "success" or resp.get("dhanClientId")
    ):
        return True
    logger.warning(f"Token validation failed: {resp}")
    return False


# HDFCBANK on NSE: liquid, always listed, cheap to quote.
_PROBE_SECURITY = {"NSE_EQ": [1333]}


def data_access(client_id: str, access_token: str) -> tuple[bool, str]:
    """Does Dhan serve MARKET DATA to this token? (ok, reason). Read-only.

    validate_token() only proves the login: on 2026-10-01 from 23:30 IST Dhan
    accepted the token for profile and funds while refusing every data call
    with 806 "Data APIs not Subscribed" / DH-902, although the profile said
    dataPlan "Active". That is an entitlement on Dhan's side, which no new
    login changes — so this is a diagnostic, and get_valid_token() never
    logs in again because of it (a re-login would only rotate the token
    under every other strategy).
    """
    import requests
    try:
        r = requests.post("https://api.dhan.co/v2/marketfeed/ltp", timeout=15,
                          json=_PROBE_SECURITY,
                          headers={"access-token": access_token, "client-id": client_id,
                                   "Content-Type": "application/json",
                                   "Accept": "application/json"})
    except Exception as e:
        return False, f"no answer from Dhan: {e}"
    body = r.text.strip()
    if r.status_code == 200 and '"success"' in body:
        return True, "market data served"
    if "806" in body or "DH-902" in body or "not Subscribed" in body:
        return False, ("Dhan refuses market data to this account (806 / DH-902) — "
                       "an entitlement on Dhan's side, not a login problem")
    return False, f"HTTP {r.status_code}: {body[:160]}"


def _refresh_locked() -> tuple[str, str]:
    """Renew-or-generate. Caller must hold the login lock."""
    saved = _load_saved_token()

    if saved:
        if _is_from_today(saved):
            logger.info("Today's token is invalid — renewing")
            return renew_token()
        logger.info(
            f"Token is from {saved.get('generated_date', '')}, generating fresh one for today"
        )
        try:
            return generate_token()
        except Exception as e:
            logger.warning(f"Fresh generation failed: {e} — trying renewal")
            return renew_token()

    logger.info("No saved token — generating new one")
    return generate_token()


def get_valid_token() -> tuple[str, str]:
    """
    Main entry point: returns a valid (client_id, access_token).

    Logic:
      1. If we have a token from today, validate it
      2. If valid, return it
      3. If invalid or expired, take the cross-process lock and re-check
         (another strategy may have just refreshed it)
      4. Still no good -> renew, and fall back to a fresh TOTP login
    """
    saved = _load_saved_token()
    if _is_from_today(saved) and validate_token(saved["client_id"], saved["access_token"]):
        logger.debug("Existing token is valid")
        return saved["client_id"], saved["access_token"]

    # Mutating path — only one process may log in at a time.
    with _login_lock():
        _invalidate_cache()
        saved = _load_saved_token()
        if _is_from_today(saved) and validate_token(saved["client_id"], saved["access_token"]):
            logger.info("Another process refreshed the token while we waited — reusing it")
            return saved["client_id"], saved["access_token"]
        return _refresh_locked()


def force_refresh() -> tuple[str, str]:
    """Discard the current token and obtain a new one.

    For mid-session recovery: if Dhan starts returning DH-901 on a token that
    was working, call this rather than restarting the strategy.
    """
    with _login_lock():
        _invalidate_cache()
        return _refresh_locked()


def get_valid_token_with_retry(max_retries: int = 3, delay: int = 30) -> tuple[str, str]:
    """get_valid_token with retries for robustness."""
    for attempt in range(1, max_retries + 1):
        try:
            return get_valid_token()
        except Exception as e:
            logger.error(f"Token attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                logger.info(f"Retrying in {delay}s...")
                time.sleep(delay)
    raise RuntimeError(f"Failed to obtain valid token after {max_retries} attempts")
