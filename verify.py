"""Prove that ONE Dhan login serves every strategy under strategy_by_ai/.

    python verify.py            # full check (may perform a real login)
    python verify.py --no-login # fail instead of logging in if no valid token

Checks, in order:
  1. credentials + token files are where the shared package expects them
  2. get_valid_token() returns a token Dhan actually accepts (user_profile)
  3. skew_hunter, in its OWN process, resolves the same token file and token
  4. swing_dual_momentum, in its OWN process, resolves the same token
  5. neither strategy triggered a second login (the token is unchanged)

Step 3/4 run as subprocesses on purpose: that is how the strategies really
run, and it is the only way to catch two of them logging in separately and
invalidating each other's token.

Read-only against Dhan — never places an order.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

_PKG_DIR = os.path.abspath(os.path.dirname(__file__))
_PARENT = os.path.abspath(os.path.join(_PKG_DIR, ".."))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from yash_dhan_auth import CREDS_FILE, TOKEN_FILE, validate_token   # noqa: E402

OK, BAD = "  [ OK ]", "  [FAIL]"
_results: list[bool] = []


def check(label: str, passed: bool, detail: str = "") -> bool:
    _results.append(passed)
    print(f"{OK if passed else BAD} {label}" + (f"  — {detail}" if detail else ""))
    return passed


def fingerprint(token: str) -> str:
    """Short, non-secret identifier for a token, safe to print/compare."""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


# Printed by each strategy subprocess as the last line of stdout.
_PROBE = """
import json, sys
sys.path.insert(0, {root!r})
import os; os.chdir({root!r})
{importer}
print("PROBE " + json.dumps({{"token_file": tf, "client_id": cid, "token": tok}}))
"""

_SKEW_IMPORT = """
from auth.token_manager import TOKEN_FILE as tf, get_valid_token_with_retry
cid, tok = get_valid_token_with_retry()
"""

# Order matters and mirrors the real strategy: importing dhan_data is what
# puts strategy_by_ai/ on sys.path, so the shared package is only importable
# afterwards. swing exposes the token only through that package.
_SWING_IMPORT = """
import dhan_data
dhan_data.get_client()          # the real client the strategy would trade with
from yash_dhan_auth import TOKEN_FILE as tf, get_valid_token_with_retry
cid, tok = get_valid_token_with_retry()
"""


def probe(name: str, root: str, importer: str) -> dict | None:
    """Run a strategy's own auth path in a separate process."""
    code = _PROBE.format(root=root, importer=importer)
    p = subprocess.run([sys.executable, "-c", code], capture_output=True,
                       text=True, cwd=root, timeout=300)
    for line in reversed(p.stdout.splitlines()):
        if line.startswith("PROBE "):
            return json.loads(line[6:])
    print(f"{BAD} {name}: probe produced no result")
    tail = (p.stderr or p.stdout).strip().splitlines()[-4:]
    for t in tail:
        print(f"         {t}")
    _results.append(False)
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-login", action="store_true",
                    help="fail instead of performing a login")
    args = ap.parse_args()

    print("Shared Dhan auth — verification\n")
    print(f"package : {_PKG_DIR}")
    print(f"creds   : {CREDS_FILE}")
    print(f"token   : {TOKEN_FILE}\n")

    print("1) Shared package")
    check("credentials file present", os.path.exists(CREDS_FILE))
    if not os.path.exists(CREDS_FILE):
        print("\n       Run: python credentials_setup.py")
        return 1

    print("\n2) Token is valid against Dhan")
    if args.no_login:
        if not os.path.exists(TOKEN_FILE):
            check("token file present", False, "--no-login and no token on disk")
            return 1
        saved = json.load(open(TOKEN_FILE))
        cid, tok = saved["client_id"], saved["access_token"]
    else:
        from yash_dhan_auth import get_valid_token_with_retry
        cid, tok = get_valid_token_with_retry()
    check("Dhan accepts the token (user_profile)", validate_token(cid, tok),
          f"client {cid}, token {fingerprint(tok)}")
    base = fingerprint(tok)

    print("\n3) skew_hunter (own process, via its auth/ shim)")
    skew = probe("skew_hunter", os.path.join(_PARENT, "skew_hunter"), _SKEW_IMPORT)
    if skew:
        check("resolves the shared token file",
              os.path.normcase(skew["token_file"]) == os.path.normcase(TOKEN_FILE),
              skew["token_file"])
        check("gets the same token", fingerprint(skew["token"]) == base,
              fingerprint(skew["token"]))
        check("same client id", skew["client_id"] == cid, skew["client_id"])

    print("\n4) swing_dual_momentum (own process, via dhan_data.py)")
    swing = probe("swing_dual_momentum",
                  os.path.join(_PARENT, "swing_dual_momentum"), _SWING_IMPORT)
    if swing:
        check("resolves the shared token file",
              os.path.normcase(swing["token_file"]) == os.path.normcase(TOKEN_FILE),
              swing["token_file"])
        check("gets the same token", fingerprint(swing["token"]) == base,
              fingerprint(swing["token"]))
        check("same client id", swing["client_id"] == cid, swing["client_id"])

    print("\n5) No strategy triggered a second login")
    final = json.load(open(TOKEN_FILE))
    check("token on disk unchanged after both strategies ran",
          fingerprint(final["access_token"]) == base,
          f"{base} (one login serves both)")
    check("token still accepted by Dhan",
          validate_token(final["client_id"], final["access_token"]))

    failed = _results.count(False)
    print("\n" + "─" * 62)
    if failed:
        print(f"{failed} of {len(_results)} checks FAILED")
        return 1
    print(f"All {len(_results)} checks passed — one login authenticates both strategies.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
