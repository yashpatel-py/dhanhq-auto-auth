"""
One-time setup: saves Dhan credentials for automatic token generation.

    python credentials_setup.py                # interactive; refuses to overwrite silently
    python credentials_setup.py --test-login   # ...then performs one real PIN+TOTP login

The TOTP secret is the base32 string Dhan shows when you enable TOTP
(web.dhan.co -> DhanHQ Trading APIs -> Setup TOTP), the same one you scan
into an authenticator app. It never changes unless you redo that setup.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys

_PKG_DIR = os.path.abspath(os.path.dirname(__file__))
_PARENT = os.path.abspath(os.path.join(_PKG_DIR, ".."))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

CREDS_FILE = os.path.join(_PKG_DIR, ".dhan_credentials.json")


def _ask(prompt: str, hidden: bool = False) -> str:
    return (getpass.getpass(prompt) if hidden else input(prompt)).strip()


def setup(test_login: bool = False) -> int:
    print("=" * 55)
    print("  Dhan Credentials Setup — run this ONCE per machine")
    print("=" * 55)
    print()
    print("  Saves your credentials locally so every strategy can")
    print("  auto-generate the daily access token.")
    print()
    print("  You need:")
    print("    1. Client ID   (web.dhan.co -> My Profile; a 10-digit number)")
    print("    2. Login PIN   (the 6-digit Dhan PIN)")
    print("    3. TOTP Secret (web.dhan.co -> DhanHQ Trading APIs -> Setup TOTP)")
    print()

    if os.path.exists(CREDS_FILE):
        print(f"  A credentials file already exists:\n    {CREDS_FILE}")
        if _ask("  Overwrite it? Type 'yes' to continue: ").lower() != "yes":
            print("  Left untouched.")
            return 1
        print()

    client_id = _ask("  Client ID    : ")
    pin = _ask("  Login PIN    : ", hidden=True)
    totp_secret = _ask("  TOTP Secret  : ", hidden=True).replace(" ", "").upper()

    if not all([client_id, pin, totp_secret]):
        print("\n  Error: all fields are required.")
        return 1
    if not client_id.isdigit():
        print("\n  Error: the Client ID is numeric (e.g. 1100003626).")
        return 1
    if not re.fullmatch(r"\d{4,6}", pin):
        print("\n  Error: the PIN is 4–6 digits.")
        return 1

    try:
        import pyotp
        code = pyotp.TOTP(totp_secret).now()
        if not re.fullmatch(r"\d{6}", code):
            raise ValueError("did not produce a 6-digit code")
        print("\n  TOTP secret decodes and produces 6-digit codes — looks valid.")
    except Exception as e:                       # noqa: BLE001
        print(f"\n  Warning: TOTP secret may be invalid: {e}")
        if _ask("  Save anyway? (y/n): ").lower() != "y":
            return 1

    creds = {"client_id": client_id, "pin": pin, "totp_secret": totp_secret}
    tmp = CREDS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(creds, f, indent=2)
    os.replace(tmp, CREDS_FILE)

    from yash_dhan_auth.token_manager import restrict_permissions
    restrict_permissions(CREDS_FILE)

    print(f"\n  Credentials saved: {CREDS_FILE}")
    print("  Every strategy will auto-generate today's token on first use.")
    print()
    print("  IMPORTANT: this file holds your PIN and TOTP secret in plain text.")
    print("  It is git-ignored; never copy it through git, chat or email.")

    if not test_login:
        print("\n  Next: python verify.py   (or re-run with --test-login to log in now)")
        return 0

    print("\n  Logging in once to prove the credentials work...")
    print("  (this invalidates any token another process is using right now)")
    from yash_dhan_auth.token_manager import CredentialsRejected, force_refresh, token_info
    try:
        force_refresh()
    except CredentialsRejected as e:
        print(f"\n  Dhan REJECTED the credentials: {e}")
        return 1
    except Exception as e:                       # noqa: BLE001
        print(f"\n  Login did not complete: {e}")
        return 1
    info = token_info() or {}
    print(f"  Login OK — token type {info.get('token_type')}, expires {info.get('expires_at')}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test-login", action="store_true",
                    help="after saving, perform one real PIN+TOTP login to prove the credentials")
    sys.exit(setup(test_login=ap.parse_args().test_login))
