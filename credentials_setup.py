"""
One-time setup: saves Dhan credentials for automatic token generation.

Usage:
    python credentials_setup.py
"""
import json
import os
import getpass

CREDS_FILE = os.path.join(os.path.dirname(__file__), ".dhan_credentials.json")


def setup():
    print("=" * 55)
    print("  Dhan Credentials Setup — run this ONCE")
    print("=" * 55)
    print()
    print("  This saves your credentials locally so the bot can")
    print("  auto-generate access tokens every day.")
    print()
    print("  You need:")
    print("    1. Client ID  (from DhanHQ portal)")
    print("    2. Login PIN  (your 4/6-digit PIN)")
    print("    3. TOTP Secret (enable TOTP in Dhan Security settings)")
    print()

    client_id = input("  Client ID    : ").strip()
    pin = getpass.getpass("  Login PIN    : ").strip()
    totp_secret = getpass.getpass("  TOTP Secret  : ").strip()

    if not all([client_id, pin, totp_secret]):
        print("\n  Error: all fields are required.")
        return

    totp_secret = totp_secret.replace(" ", "").upper()

    try:
        import pyotp
        totp = pyotp.TOTP(totp_secret)
        code = totp.now()
        print(f"\n  TOTP test: generated code {code} — looks valid.")
    except Exception as e:
        print(f"\n  Warning: TOTP secret may be invalid: {e}")
        confirm = input("  Save anyway? (y/n): ").strip().lower()
        if confirm != "y":
            return

    creds = {
        "client_id": client_id,
        "pin": pin,
        "totp_secret": totp_secret,
    }

    filepath = os.path.abspath(CREDS_FILE)
    with open(filepath, "w") as f:
        json.dump(creds, f, indent=2)

    print(f"\n  Credentials saved: {filepath}")
    print("  The bot will auto-generate tokens at startup.")
    print()
    print("  IMPORTANT: Keep .dhan_credentials.json safe!")
    print("  It's already in .gitignore.")


if __name__ == "__main__":
    setup()
