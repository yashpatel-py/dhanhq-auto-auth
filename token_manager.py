"""
Automatic Dhan token management — one login, every strategy.

What it does:
  1. Logs in once a day with PIN + TOTP (auth.dhan.co/app/generateAccessToken)
     and stores the token in .dhan_token.json next to this file.
  2. Hands that token to every strategy (get_valid_token / get_client).
  3. Checks the token with Dhan (/v2/profile) at most once every
     VALIDATION_TTL_SEC per process, and logs in again only when Dhan
     REJECTS it — never because Dhan was merely unreachable.
  4. Serialises logins across processes AND threads with a lock file, so two
     strategies starting together perform exactly one login.

Facts about Dhan tokens this file is built around (docs v2 "Authentication",
plus what this account has actually returned):
  * A PIN+TOTP token ("APP" in its JWT claims) is valid 24 h from issue and
    CANNOT be renewed: /v2/RenewToken answers DH-905 "Renewal of token not
    allowed for this token type". Only tokens made by hand on web.dhan.co
    ("SELF") renew.
  * Dhan keeps ONE live token per client. A new login invalidates the old
    token for every other process, so the mutating path is locked and always
    re-reads the disk first.
  * Dhan refuses a second PIN+TOTP login within ~2 minutes of the previous
    one ("Token can be generated once every 2 minutes", seen 2026-09-22).
  * Login and Data-API entitlement are SEPARATE. /profile can say
    dataPlan "Active" while every data call answers 806 / DH-902 (Dhan-side
    outage on 2026-10-01, reported by several users on madefortrade.in topic
    94453). No login fixes that — see data_access() / capabilities.py.

Tokens are keyed on the IST calendar date on purpose: a token minted on day D
is always valid past midnight of D, so "from today" guarantees the token
spans the whole trading day; the JWT `exp` is checked too, as a belt.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import threading
import time
from contextlib import contextmanager
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

import requests

IST = ZoneInfo("Asia/Kolkata")
logger = logging.getLogger("auth.token_manager")

# Shared package: credentials and the daily token live INSIDE this
# directory so every strategy under strategy_by_ai/ uses the same ones.
_PKG_DIR = os.path.abspath(os.path.dirname(__file__))
CREDS_FILE = os.path.join(_PKG_DIR, ".dhan_credentials.json")
TOKEN_FILE = os.path.join(_PKG_DIR, ".dhan_token.json")
LOCK_FILE = os.path.join(_PKG_DIR, ".dhan_token.lock")

AUTH_BASE = "https://auth.dhan.co"
API_BASE = "https://api.dhan.co/v2"
HTTP_TIMEOUT = 30            # the SDK's DhanLogin has NO timeout; a hung login would hold the lock forever

# A PIN+TOTP round-trip takes a few seconds and the retry path waits at most
# one 30 s TOTP window. A lock older than this belonged to a process that
# died mid-login, so it is safe to break. A live holder touches the lock
# before every long sleep, so it is never mistaken for a dead one.
LOCK_STALE_SEC = 180
LOCK_WAIT_SEC = 300

VALIDATION_TTL_SEC = 120     # re-ask /profile about the same token at most this often (per process)
MINT_GAP_SEC = 120           # Dhan: "Token can be generated once every 2 minutes"
EXPIRY_MARGIN_SEC = 300      # treat a token as dead 5 min before its JWT exp

# Set this (=1) on a machine that must NEVER log in — e.g. the laptop while
# the server runs the strategies. Dhan keeps one live token per client, so a
# login here would invalidate the server's token mid-session. With it set,
# the token on disk is used as long as it is from today and Dhan accepts it;
# otherwise LoginDisabled is raised instead of a login being attempted.
NO_LOGIN_ENV = "YASH_DHAN_AUTH_NO_LOGIN"

_cached_token: dict | None = None
_token_date: date | None = None
_thread_lock = threading.RLock()          # guards the mutating path within one process
_validated: dict[str, float] = {}         # access_token -> time.time() it last passed /profile
_last_profile: dict | None = None         # last /profile body Dhan returned for the live token
_client = None                            # cached dhanhq facade (get_client)
_client_token: str | None = None


# ══════════════════════════════════════════════════════════════════════════
# errors
# ══════════════════════════════════════════════════════════════════════════
class TokenError(RuntimeError):
    """Base class for everything this module raises on purpose."""


class CredentialsRejected(TokenError):
    """Dhan refused the Client ID / PIN / TOTP. Retrying cannot help and
    only risks a lockout — fix .dhan_credentials.json (credentials_setup.py)."""


class TokenMintThrottled(TokenError):
    """A token was minted less than ~2 minutes ago (by us or another
    process). Wait `retry_after` seconds, then re-read the disk first."""

    def __init__(self, msg: str, retry_after: int = MINT_GAP_SEC):
        super().__init__(msg)
        self.retry_after = retry_after


class DhanUnreachable(TokenError):
    """Network error, timeout, 429 or 5xx — Dhan did not answer the question.
    Says nothing about the token."""


class LoginDisabled(TokenError):
    """YASH_DHAN_AUTH_NO_LOGIN=1 is set on this machine and no usable token is
    on disk. Not retried — nothing here can change it."""


def login_disabled() -> bool:
    return os.environ.get(NO_LOGIN_ENV, "").strip().lower() in ("1", "true", "yes")


def _refuse_login(what: str) -> None:
    if login_disabled():
        raise LoginDisabled(
            f"{what} refused: {NO_LOGIN_ENV}=1 on this machine (the strategies run on the "
            f"server, and a login here would invalidate its token). For a read-only session "
            f"copy today's .dhan_token.json from the server to {TOKEN_FILE}; to make this "
            f"machine the one that logs in, unset {NO_LOGIN_ENV}.")


# ══════════════════════════════════════════════════════════════════════════
# credentials + token file
# ══════════════════════════════════════════════════════════════════════════
def _load_credentials() -> dict:
    if not os.path.exists(CREDS_FILE):
        raise FileNotFoundError(
            "No credentials found. Run: python credentials_setup.py in strategy_by_ai/yash_dhan_auth"
        )
    with open(CREDS_FILE) as f:
        creds = json.load(f)
    missing = [k for k in ("client_id", "pin", "totp_secret") if not creds.get(k)]
    if missing:
        raise CredentialsRejected(f"{CREDS_FILE} is missing {missing} — re-run credentials_setup.py")
    return creds


def restrict_permissions(path: str) -> None:
    """Best effort: make `path` readable by the current user only.

    POSIX: chmod 600. Windows: grant the current user full control, and only
    once that succeeded strip inherited ACEs (never the other way round, so a
    failed lookup can never lock the file). Set YASH_DHAN_AUTH_NO_ACL=1 to
    skip. Failures are logged at debug level and never raised.
    """
    if os.environ.get("YASH_DHAN_AUTH_NO_ACL") or not os.path.exists(path):
        return
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
            return
        user = os.environ.get("USERNAME")
        if not user:
            return
        flags = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
        g = subprocess.run(["icacls", path, "/grant:r", f"{user}:F"],
                           capture_output=True, timeout=15, **flags)
        if g.returncode == 0:
            subprocess.run(["icacls", path, "/inheritance:r"],
                           capture_output=True, timeout=15, **flags)
    except Exception as e:                       # noqa: BLE001 — cosmetic hardening only
        logger.debug(f"restrict_permissions({path}): {e}")


def _now_ist() -> datetime:
    return datetime.now(IST)


def _today_ist() -> date:
    return _now_ist().date()


def token_claims(access_token: str) -> dict:
    """The token's own (unencrypted) JWT claims. No secret, no network call.

    Dhan tokens carry: iss, iat, exp (unix seconds), tokenConsumerType
    ("APP" = PIN+TOTP, "SELF" = made by hand on web.dhan.co), dhanClientId.
    Returns {} if the string is not a JWT.
    """
    try:
        part = access_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:
        return {}


def token_type(access_token: str) -> str:
    """"APP" (PIN+TOTP, i.e. this package), "SELF" (web.dhan.co), or "" if unreadable."""
    return str(token_claims(access_token).get("tokenConsumerType") or "")


def token_expiry(access_token: str) -> datetime | None:
    """When Dhan will stop accepting the token (IST), from its JWT `exp`."""
    exp = token_claims(access_token).get("exp")
    try:
        return datetime.fromtimestamp(int(exp), tz=timezone.utc).astimezone(IST)
    except (TypeError, ValueError):
        return None


def _save_token(client_id: str, access_token: str, expiry_time: str | None = None) -> None:
    global _cached_token, _token_date
    now = _now_ist()
    exp = token_expiry(access_token)
    data = {
        "client_id": client_id,
        "access_token": access_token,
        "token_type": token_type(access_token),
        "generated_at": now.isoformat(),
        "generated_date": now.date().isoformat(),
        # JWT exp first (what Dhan enforces), the login response's expiryTime as a fallback
        "expires_at": exp.isoformat() if exp else (expiry_time or None),
    }
    tmp = TOKEN_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, TOKEN_FILE)
    restrict_permissions(TOKEN_FILE)

    _cached_token = data
    _token_date = now.date()
    _validated[access_token] = time.time()       # Dhan just issued it — it is valid right now

    logger.info(f"Token saved (generated {data['generated_at']}, expires {data['expires_at']})")


def _load_saved_token() -> dict | None:
    global _cached_token, _token_date
    today = _today_ist()
    if _cached_token and _token_date == today:
        return _cached_token
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE) as f:
                data = json.load(f)
            if not isinstance(data, dict) or not data.get("access_token") or not data.get("client_id"):
                return None
            _cached_token = data
            _token_date = today if data.get("generated_date") == today.isoformat() else None
            return data
        except Exception as e:                   # noqa: BLE001 — half-written file, OneDrive lock, bad JSON
            logger.debug(f"Could not read {TOKEN_FILE}: {e}")
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
    return bool(saved) and saved.get("generated_date") == _today_ist().isoformat()


def _usable(saved: dict | None) -> bool:
    """From today AND (offline) not within EXPIRY_MARGIN_SEC of its JWT exp."""
    if not _is_from_today(saved):
        return False
    exp = token_expiry(saved["access_token"])
    return exp is None or (exp - _now_ist()).total_seconds() > EXPIRY_MARGIN_SEC


def token_info() -> dict | None:
    """What is on disk, decoded offline — no network call, no secret printed.

    Keys: client_id, token_type, generated_at, generated_date, expires_at,
    seconds_left, is_today, usable, path. None if there is no token file.
    """
    saved = _load_saved_token()
    if not saved:
        return None
    tok = saved["access_token"]
    exp = token_expiry(tok)
    return {
        "client_id": saved["client_id"],
        "token_type": token_type(tok) or saved.get("token_type", ""),
        "generated_at": saved.get("generated_at"),
        "generated_date": saved.get("generated_date"),
        "expires_at": exp.isoformat() if exp else saved.get("expires_at"),
        "seconds_left": int((exp - _now_ist()).total_seconds()) if exp else None,
        "is_today": _is_from_today(saved),
        "usable": _usable(saved),
        "path": TOKEN_FILE,
    }


# ══════════════════════════════════════════════════════════════════════════
# cross-process lock
# ══════════════════════════════════════════════════════════════════════════
def _touch_lock() -> None:
    """Refresh the lock's mtime so a live holder is never broken as stale."""
    try:
        os.utime(LOCK_FILE, None)
    except OSError:
        pass


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
                os.write(fd, f"{os.getpid()} {_now_ist().isoformat()}\n".encode())
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
                    raise TokenError(
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


# ══════════════════════════════════════════════════════════════════════════
# HTTP — direct, with timeouts (dhanhq.DhanLogin has none and raises on non-200)
# ══════════════════════════════════════════════════════════════════════════
def _request(method: str, url: str, **kw) -> requests.Response:
    kw.setdefault("timeout", HTTP_TIMEOUT)
    try:
        return requests.request(method, url, **kw)
    except requests.RequestException as e:
        raise DhanUnreachable(f"{method} {url.split('?')[0]}: {type(e).__name__}: {e}") from e


def _json(resp: requests.Response):
    try:
        return resp.json()
    except ValueError:
        return {"raw": resp.text[:300]}


def _error_text(body, resp: requests.Response) -> str:
    """One readable line out of Dhan's several error shapes."""
    if isinstance(body, dict):
        code = body.get("errorCode") or body.get("error_code") or ""
        typ = body.get("errorType") or body.get("error_type") or ""
        msg = (body.get("errorMessage") or body.get("error_message")
               or body.get("remarks") or body.get("message") or body.get("raw") or "")
        if not (code or typ or msg):
            # data-API style {"806": "Data APIs not subscribed"}
            msg = "; ".join(f"{k}: {v}" for k, v in body.items())
        return f"HTTP {resp.status_code} {code} {typ}: {msg}".replace("  ", " ").strip()
    return f"HTTP {resp.status_code}: {str(body)[:200]}"


def _extract_token(body) -> str | None:
    if not isinstance(body, dict):
        return None
    return body.get("accessToken") or (body.get("data") or {}).get("access_token")


def _classify_login_error(status: int, text: str) -> str:
    """'throttled' | 'rejected' | 'unreachable' | 'other'."""
    low = text.lower()
    if "minute" in low and any(k in low for k in ("once", "generated", "wait", "try again")):
        return "throttled"
    if status == 429 or status >= 500:
        return "unreachable"
    if "dh-905" in low or "input_exception" in low:
        return "other"                           # our request was malformed — "pin is required" is not a wrong PIN
    if status in (401, 403) or "dh-901" in low or "invalid_authentication" in low or \
            any(k in low for k in ("totp", "otp", "pin", "invalid credential", "unauthori")):
        return "rejected"
    return "other"


def _classify_profile(status: int, body) -> str:
    """'valid' | 'rejected' | 'unreachable'."""
    if status == 200 and isinstance(body, dict) and (body.get("dhanClientId") or body.get("status") == "success"):
        return "valid"
    if status == 429 or status >= 500:
        return "unreachable"
    return "rejected"


# ══════════════════════════════════════════════════════════════════════════
# login / renew / check
# ══════════════════════════════════════════════════════════════════════════
def generate_token() -> tuple[str, str]:
    """Log in with PIN + TOTP. Returns (client_id, access_token).

    One login, and ONE retry in the next 30 s window only if Dhan rejected
    the code (clock drift / code expired in transit). Nothing else is
    retried here: a wrong PIN raises CredentialsRejected, a login inside
    Dhan's 2-minute gap raises TokenMintThrottled, a network error raises
    DhanUnreachable — the caller decides what waiting is worth.
    """
    import pyotp

    _refuse_login("PIN+TOTP login")
    creds = _load_credentials()
    client_id = str(creds["client_id"])
    totp = pyotp.TOTP(creds["totp_secret"].replace(" ", "").upper())

    kind, last = "other", "no response"
    for attempt in (1, 2):
        # Never send a code that is about to roll over while in transit.
        remaining = 30 - (time.time() % 30)
        if remaining < 4:
            time.sleep(remaining + 0.5)
        code = totp.now()
        logger.info(f"Logging in to Dhan for {client_id} (TOTP attempt {attempt}/2)")
        resp = _request("POST", f"{AUTH_BASE}/app/generateAccessToken",
                        params={"dhanClientId": client_id, "pin": str(creds["pin"]), "totp": code})
        body = _json(resp)
        token = _extract_token(body)
        if resp.status_code == 200 and token:
            _save_token(client_id, token, body.get("expiryTime") if isinstance(body, dict) else None)
            logger.info("New access token generated successfully")
            return client_id, token

        last = _error_text(body, resp)
        kind = _classify_login_error(resp.status_code, last)
        if kind == "throttled":
            raise TokenMintThrottled(f"Dhan refused the login: {last}")
        if kind == "unreachable":
            raise DhanUnreachable(f"Dhan did not answer the login: {last}")
        if kind == "rejected" and attempt == 1:
            wait = 30 - (time.time() % 30) + 1
            logger.warning(f"Login rejected ({last}) — retrying once with the next TOTP code in {wait:.0f}s")
            _touch_lock()
            time.sleep(wait)
            continue
        break

    if kind == "rejected":
        raise CredentialsRejected(
            f"Dhan rejected the PIN/TOTP twice: {last}. "
            f"Check .dhan_credentials.json (python credentials_setup.py)")
    raise TokenError(f"Token generation failed: {last}")


def renew_token() -> tuple[str, str]:
    """Renew the stored token. Returns (client_id, access_token).

    Only a token made by hand on web.dhan.co ("SELF") can be renewed; the
    PIN+TOTP tokens this package makes ("APP") are refused with DH-905, so
    for them this simply logs in again.
    """
    saved = _load_saved_token()
    if not saved:
        logger.warning("No existing token to renew — generating a fresh one")
        return generate_token()

    client_id, old = saved["client_id"], saved["access_token"]
    if token_type(old) != "SELF":
        logger.info("PIN+TOTP tokens cannot be renewed — logging in again")
        return generate_token()

    _refuse_login("Token renewal")           # renewal expires the current token just like a login
    logger.info("Renewing access token...")
    resp = _request("GET", f"{API_BASE}/RenewToken",
                    headers={"access-token": old, "dhanClientId": client_id, "Accept": "application/json"})
    body = _json(resp)
    new = _extract_token(body) if resp.status_code == 200 else None
    if not new:
        logger.warning(f"Token renewal failed ({_error_text(body, resp)}) — logging in again")
        return generate_token()
    _save_token(client_id, new, body.get("expiryTime"))
    logger.info("Token renewed successfully")
    return client_id, new


def check_token(client_id: str, access_token: str) -> tuple[str, dict | str]:
    """Ask Dhan (/v2/profile) about a token. Returns (status, detail):

      ("valid", profile_dict)      Dhan accepts it; dict has tokenValidity,
                                   activeSegment, ddpi, mtf, dataPlan, dataValidity
      ("rejected", reason)         Dhan refuses it (DH-901 etc.) — log in again
      ("unreachable", reason)      timeout / network / 429 / 5xx — unknown, do NOT log in

    Separating the last two is the whole point: on 'unreachable' a new login
    would fail just the same, and would only rotate the token under every
    other strategy once Dhan came back.
    """
    global _last_profile
    try:
        resp = _request("GET", f"{API_BASE}/profile", timeout=15,
                        headers={"access-token": access_token, "client-id": client_id,
                                 "Accept": "application/json"})
    except DhanUnreachable as e:
        return "unreachable", str(e)
    body = _json(resp)
    status = _classify_profile(resp.status_code, body)
    if status == "valid":
        _validated[access_token] = time.time()
        _last_profile = body
        return "valid", body
    return status, _error_text(body, resp)


def validate_token(client_id: str, access_token: str) -> bool:
    """True only if Dhan explicitly accepts the token (see check_token)."""
    status, detail = check_token(client_id, access_token)
    if status != "valid":
        logger.warning(f"Token validation {status}: {detail}")
    return status == "valid"


def _recently_validated(access_token: str) -> bool:
    return time.time() - _validated.get(access_token, 0.0) < VALIDATION_TTL_SEC


def account_status(client_id: str | None = None, access_token: str | None = None) -> dict:
    """/v2/profile for the live token: tokenValidity, activeSegment, ddpi, mtf,
    dataPlan, dataValidity. Raises TokenError if Dhan rejects or is unreachable."""
    if client_id is None or access_token is None:
        client_id, access_token = get_valid_token()
    status, detail = check_token(client_id, access_token)
    if status != "valid":
        raise TokenError(f"profile {status}: {detail}")
    return {k: v for k, v in detail.items()} if isinstance(detail, dict) else {}


# HDFCBANK on NSE: liquid, always listed, cheap to quote.
_PROBE_SECURITY = {"NSE_EQ": [1333]}


def data_access(client_id: str, access_token: str) -> tuple[bool, str]:
    """Does Dhan serve MARKET DATA to this token right now? (ok, reason).

    validate_token() only proves the login: on 2026-10-01 from 23:30 IST Dhan
    accepted the token for profile and funds while refusing every data call
    with 806 "Data APIs not Subscribed" / DH-902, although the profile said
    dataPlan "Active" (several users, madefortrade.in topic 94453). That is
    an entitlement on Dhan's side, which no new login changes — so this is a
    diagnostic, and get_valid_token() never logs in again because of it.
    For all six data capabilities see capabilities.check_capabilities().
    """
    try:
        r = _request("POST", f"{API_BASE}/marketfeed/ltp", timeout=15, json=_PROBE_SECURITY,
                     headers=rest_headers(client_id, access_token))
    except DhanUnreachable as e:
        return False, f"no answer from Dhan: {e}"
    body = r.text.strip()
    if r.status_code == 200 and '"success"' in body:
        return True, "market data served"
    if r.status_code == 429 or '"805"' in body or "DH-904" in body:
        return False, "rate limited (805 / DH-904) — not an entitlement answer; try again in a second"
    if "806" in body or "DH-902" in body or "not Subscribed" in body:
        return False, ("Dhan refuses market data to this account (806 / DH-902) — "
                       "an entitlement on Dhan's side, not a login problem")
    return False, f"HTTP {r.status_code}: {body[:160]}"


# ══════════════════════════════════════════════════════════════════════════
# the entry points
# ══════════════════════════════════════════════════════════════════════════
def _refresh_locked() -> tuple[str, str]:
    """Obtain a new token. Caller must hold the login lock."""
    saved = _load_saved_token()
    if saved and _is_from_today(saved):
        logger.info("Today's token is no longer accepted — logging in again")
        if token_type(saved["access_token"]) == "SELF":
            return renew_token()
    elif saved:
        logger.info(f"Token is from {saved.get('generated_date', '?')} — logging in for today")
    else:
        logger.info("No saved token — logging in")
    return generate_token()


def get_valid_token() -> tuple[str, str]:
    """
    Main entry point: returns a valid (client_id, access_token).

      1. Today's token on disk, Dhan accepts it (checked at most once per
         VALIDATION_TTL_SEC per process) -> returned. The common path.
      2. Dhan unreachable while checking -> today's token is returned anyway
         (a login would fail too, and would only rotate the token under the
         other strategies when Dhan comes back).
      3. Token missing / from an earlier day / rejected -> take the
         cross-process lock, re-read the disk (another strategy may have just
         logged in) and reuse that; otherwise log in with PIN + TOTP.
    """
    saved = _load_saved_token()
    rejected: str | None = None
    if _usable(saved):
        cid, tok = saved["client_id"], saved["access_token"]
        if _recently_validated(tok):
            return cid, tok
        status, detail = check_token(cid, tok)
        if status == "valid":
            logger.debug("Existing token is valid")
            return cid, tok
        if status == "unreachable":
            logger.warning(f"Dhan unreachable while checking the token ({detail}) — keeping today's token")
            return cid, tok
        logger.info(f"Dhan rejected today's token ({detail})")
        rejected = tok
        _validated.pop(tok, None)

    # Mutating path — only one process may log in at a time.
    with _login_lock():
        _invalidate_cache()
        saved = _load_saved_token()
        if _usable(saved) and saved["access_token"] != rejected:
            cid, tok = saved["client_id"], saved["access_token"]
            status, detail = check_token(cid, tok)
            if status == "valid":
                logger.info("Another process refreshed the token while we waited — reusing it")
                return cid, tok
            if status == "unreachable":
                logger.warning(f"Dhan unreachable ({detail}) — keeping the token on disk")
                return cid, tok
        return _refresh_locked()


def force_refresh(bad_token: str | None = None) -> tuple[str, str]:
    """Replace a token Dhan has started rejecting mid-session (DH-901 / 807 / 809).

    Pass the token you were using as `bad_token`: if another strategy has
    ALREADY replaced it, that newer token is reused instead of logging in a
    second time (which Dhan would refuse inside its 2-minute gap anyway, and
    which would invalidate the token the other strategy just got).
    Without `bad_token` a new login is always performed.
    """
    with _login_lock():
        _invalidate_cache()
        if bad_token:
            _validated.pop(bad_token, None)
            saved = _load_saved_token()
            if _usable(saved) and saved["access_token"] != bad_token:
                cid, tok = saved["client_id"], saved["access_token"]
                if check_token(cid, tok)[0] == "valid":
                    logger.info("Token on disk is already newer than the rejected one — reusing it")
                    return cid, tok
        return _refresh_locked()


def get_valid_token_with_retry(max_retries: int = 3, delay: int = 30) -> tuple[str, str]:
    """get_valid_token with retries. Waits out Dhan's 2-minute mint gap, and
    does NOT retry a rejected PIN/TOTP (that only risks a lockout)."""
    last: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            return get_valid_token()
        except (CredentialsRejected, LoginDisabled):
            raise
        except TokenMintThrottled as e:
            last, wait = e, max(delay, e.retry_after + 5)
        except Exception as e:                   # noqa: BLE001
            last, wait = e, delay
        logger.error(f"Token attempt {attempt}/{max_retries} failed: {last}")
        if attempt < max_retries:
            logger.info(f"Retrying in {wait}s...")
            time.sleep(wait)
    raise TokenError(f"Failed to obtain valid token after {max_retries} attempts: {last}")


# ══════════════════════════════════════════════════════════════════════════
# ready-made clients — so a strategy never builds its own
# ══════════════════════════════════════════════════════════════════════════
def rest_headers(client_id: str | None = None, access_token: str | None = None) -> dict:
    """Headers for a raw requests call to https://api.dhan.co/v2/... ."""
    if client_id is None or access_token is None:
        client_id, access_token = get_valid_token_with_retry()
    return {"access-token": access_token, "client-id": client_id,
            "Content-Type": "application/json", "Accept": "application/json"}


def get_context():
    """A fresh dhanhq.DhanContext for today's token."""
    from dhanhq import DhanContext
    cid, tok = get_valid_token_with_retry()
    return DhanContext(cid, tok)


def get_client():
    """The dhanhq facade — orders, portfolio, funds, statements, market
    quotes, historical + expired-options data, option chain — on today's
    token. Cached per token: call it every time instead of keeping your own
    copy, and it rebuilds itself the moment the token changes.
    """
    global _client, _client_token
    from dhanhq import DhanContext, dhanhq
    cid, tok = get_valid_token_with_retry()
    if _client is None or tok != _client_token:
        _client = dhanhq(DhanContext(cid, tok))
        _client_token = tok
    return _client


def market_feed(instruments, **kwargs):
    """dhanhq.MarketFeed (wss://api-feed.dhan.co) on today's token.

    instruments: [(MarketFeed.NSE, "1333", MarketFeed.Full), ...] — the
    security id as a STRING. Up to 5 sockets per account across ALL your
    strategies, 5000 instruments each, 100 per subscribe message.
    """
    from dhanhq import MarketFeed
    return MarketFeed(get_context(), instruments, **kwargs)


def depth_feed(instruments, level: int = 20):
    """dhanhq.FullDepth on today's token — 20 levels (≤50 instruments per
    socket) or 200 levels (ONE instrument per socket). NSE equity and F&O
    only. The SDK's own connect() prints the socket URL — token included — to
    stdout; this subclass does not.
    """
    from dhanhq import FullDepth

    class _QuietFullDepth(FullDepth):
        async def connect(self):
            import websockets
            if not self.ws or self.ws.state == websockets.protocol.State.CLOSED:
                url = f"{self.ws_url}?token={self.access_token}&clientId={self.client_id}&authType=2"
                self.ws = await websockets.connect(url)
                await self.subscribe_instruments()
            else:
                try:
                    await self.ws.ping()
                except websockets.ConnectionClosed:
                    self.ws = None
                    await self.connect()

    return _QuietFullDepth(get_context(), instruments, depth_level=level)
