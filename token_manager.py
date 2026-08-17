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
"""
import json
import logging
import os
import time
from datetime import datetime, date
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")
logger = logging.getLogger("auth.token_manager")

# Shared package: credentials and the daily token live INSIDE this
# directory so every strategy under strategy_by_ai/ uses the same ones.
_PKG_DIR = os.path.abspath(os.path.dirname(__file__))
CREDS_FILE = os.path.join(_PKG_DIR, ".dhan_credentials.json")
TOKEN_FILE = os.path.join(_PKG_DIR, ".dhan_token.json")

_cached_token: dict | None = None
_token_date: date | None = None


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
        resp = login.generate_token(pin=pin, totp=otp_code)

        if not resp:
            raise RuntimeError("Token generation failed: No response")

        access_token = (
            resp.get("accessToken")
            or (resp.get("data") or {}).get("access_token")
        )
        if access_token:
            _save_token(client_id, access_token)
            logger.info("New access token generated successfully")
            return client_id, access_token

        error_msg = str(resp.get("remarks", resp))
        last_error = error_msg

        # TOTP rejected — possibly expired during network round-trip.
        # Wait for the next 30-second window and retry exactly once.
        if totp_attempt < 2 and (
            "TOTP" in error_msg.upper() or "OTP" in error_msg.upper()
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
    """Renew an existing token. Returns (client_id, access_token)."""
    from dhanhq import DhanLogin

    saved = _load_saved_token()
    if not saved:
        logger.warning("No existing token to renew — generating fresh one")
        return generate_token()

    client_id = saved["client_id"]
    old_token = saved["access_token"]

    logger.info("Renewing access token...")
    login = DhanLogin(client_id)
    resp = login.renew_token(old_token)

    if not resp:
        logger.warning("Token renewal failed: no response — generating fresh token")
        return generate_token()

    new_token = (
        resp.get("accessToken")
        or (resp.get("data") or {}).get("access_token")
    )
    if not new_token:
        logger.warning(f"Token renewal failed: {resp} — generating fresh token")
        return generate_token()

    _save_token(client_id, new_token)
    logger.info("Token renewed successfully")
    return client_id, new_token


def validate_token(client_id: str, access_token: str) -> bool:
    """Check if the token is still valid by hitting user_profile."""
    from dhanhq import DhanLogin
    try:
        login = DhanLogin(client_id)
        resp = login.user_profile(access_token)
        if resp and (resp.get("status") == "success" or resp.get("dhanClientId")):
            return True
        logger.warning(f"Token validation failed: {resp}")
    except Exception as e:
        logger.warning(f"Token validation error: {e}")
    return False


def get_valid_token() -> tuple[str, str]:
    """
    Main entry point: returns a valid (client_id, access_token).

    Logic:
      1. If we have a token from today, validate it
      2. If valid, return it
      3. If invalid or expired, try renew
      4. If renew fails, generate fresh via TOTP
    """
    saved = _load_saved_token()

    if saved:
        client_id = saved["client_id"]
        access_token = saved["access_token"]
        token_date = saved.get("generated_date", "")

        if token_date == datetime.now(IST).date().isoformat():
            if validate_token(client_id, access_token):
                logger.debug("Existing token is valid")
                return client_id, access_token
            else:
                logger.info("Today's token is invalid — renewing")
                return renew_token()
        else:
            logger.info(f"Token is from {token_date}, generating fresh one for today")
            try:
                return generate_token()
            except Exception as e:
                logger.warning(f"Fresh generation failed: {e} — trying renewal")
                return renew_token()

    logger.info("No saved token — generating new one")
    return generate_token()


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
