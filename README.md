# yash_dhan_auth — one Dhan login for every strategy

This folder is the **single place** where your Dhan credentials live and
where the daily access token is generated, renewed, validated, and stored.
Every strategy under `strategy_by_ai/` uses it — no strategy keeps its own
copy of your PIN/TOTP, and no two bots fight over token generation.

```
strategy_by_ai/
├── yash_dhan_auth/            <- this package (credentials + daily token)
│   ├── .dhan_credentials.json    client id + PIN + TOTP secret  (NEVER commit)
│   ├── .dhan_token.json          today's access token           (NEVER commit)
│   ├── .dhan_token.lock          transient login lock           (NEVER commit)
│   ├── token_manager.py          generate / renew / validate / cache
│   ├── credentials_setup.py      one-time interactive setup
│   ├── verify.py                 prove one login serves every strategy
│   └── __init__.py
├── skew_hunter/               <- uses it via its auth/ shim
├── swing_dual_momentum/       <- uses it via dhan_data.py
└── dhan-nifty-options-paper-strategy/ <- paper-only data client via strategy/dhan_data.py
```

The package itself needs only `dhanhq>=2.2.0` and `pyotp`; it has no
`requirements.txt` of its own, and installing either strategy's requirements
covers it. `verify.py` launches each strategy in a subprocess, so its
strategy checks additionally need whatever those strategies import.

## First-time setup — once per machine

Already done on this machine. Run this only on a **new** machine: it
overwrites `.dhan_credentials.json`, so re-running it here would replace
working credentials.

```bash
cd C:\Users\yashp\OneDrive\Desktop\strategy_by_ai\yash_dhan_auth
..\.venv\Scripts\python.exe credentials_setup.py
```

Prompts for Client ID, login PIN, and TOTP secret (the last two are hidden
as you type — that is `getpass`, not a frozen terminal). It generates a test
TOTP code to confirm the secret is valid, then writes
`.dhan_credentials.json` here.

That is the only manual step. Tokens are generated automatically from then
on — you never run a "log in" command as part of daily use.

## Check it's working

```bash
cd C:\Users\yashp\OneDrive\Desktop\strategy_by_ai\yash_dhan_auth
..\.venv\Scripts\python.exe verify.py
```

Runs each strategy's own auth path in its own subprocess — the way they
really run — and asserts that all of them land on the same token file, the
same token, and the same client id, and that running them did not trigger a
second login. Expect `All 13 checks passed`. Add `--no-login` to check the
stored token without ever performing a login.

## What actually happens on a call

`get_valid_token_with_retry()` is the entry point every strategy uses. In
order:

1. **Token from today on disk, and Dhan accepts it** → returned as-is. This
   is the common path; no network login.
2. **Token missing, from an earlier day, or rejected** → take
   `.dhan_token.lock`, then re-check (another strategy may have just
   refreshed it while we queued) and reuse if so.
3. **Still no good** → renew, falling back to a fresh PIN+TOTP login if Dhan
   refuses the renewal too.

"From today" means the IST calendar date the token was generated. Dhan's own
tokens run roughly 24h from issue (`user_profile` reports `tokenValidity`),
so keying on the date is deliberately the more conservative of the two — it
refreshes at the day boundary rather than riding a token to its true expiry.

## Using it in ANY new strategy — the recipe

Your strategy lives in `strategy_by_ai/<your_strategy>/`. Add this once
(e.g. in a `dhan_data.py`):

```python
import os, sys

# make the shared package importable (parent folder = strategy_by_ai)
_PARENT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from yash_dhan_auth import get_valid_token_with_retry
from dhanhq import DhanContext, dhanhq

_client = None

def get_client() -> dhanhq:
    """Authenticated Dhan client — token handled for you."""
    global _client
    if _client is None:
        cid, token = get_valid_token_with_retry()
        _client = dhanhq(DhanContext(cid, token))
    return _client
```

Then anywhere in the strategy:

```python
from dhan_data import get_client
chain = get_client().option_chain(...)      # or historical_daily_data, orders, ...
```

Note the import order this creates: it is `import dhan_data` that puts
`strategy_by_ai/` on `sys.path`, so anything importing `yash_dhan_auth`
directly must do so *after* that first import.

That's the whole integration. The full public API:

```python
from yash_dhan_auth import (
    get_valid_token_with_retry,  # (cid, token) with retries — use this one
    get_valid_token,             # same, single attempt
    force_refresh,               # discard current token, get a new one
    validate_token,              # (cid, token) -> bool, via user_profile
    generate_token,              # force a fresh PIN+TOTP login
    renew_token,                 # renew, falling back to generate
    TOKEN_FILE,                  # path to today's token json
    CREDS_FILE,                  # path to the credentials json
)
```

## Running both strategies at once

Each strategy has its own watchdog and its own dashboard port
(`skew_hunter` 8080, `swing_dual_momentum` 8081), and
`strategy_by_ai/watchdog_all.py` runs both under one supervisor.

Starting them together is safe: the lock in rule 2 means the first process
performs the login and the second reuses the token it wrote, so two
strategies starting seconds apart still produce exactly one Dhan login.
`watchdog_all.py` additionally staggers its starts by a few seconds so the
second one finds a finished token rather than waiting on a TOTP round-trip.

## Moving to a new machine (e.g. VPS → laptop)

The **code** travels through GitHub; the **secrets** travel by hand — that
is the whole point of the split.

```bash
# on the new machine
cd <wherever>/strategy_by_ai
git clone https://github.com/yashpatel-py/yash-dhan-auth.git yash_dhan_auth
git clone https://github.com/yashpatel-py/skew-hunter-options.git skew_hunter
git clone https://github.com/yashpatel-py/swing-dual-momentum.git swing_dual_momentum
python -m pip install -r skew_hunter/requirements.txt -r swing_dual_momentum/requirements.txt
```

Then EITHER copy `.dhan_credentials.json` from the old machine into
`yash_dhan_auth/` (USB / password manager / encrypted transfer — **not git,
not chat, not email**), OR simply run `python credentials_setup.py` there and
re-enter Client ID + PIN + TOTP secret. Do not copy `.dhan_token.json`; a
fresh token is generated on first use. Do not copy `.dhan_token.lock`
either — it is transient, and a stale one only causes a 180s wait. Also copy
each strategy's `.telegram_config.json` if you want alerts on the new
machine.

Note: only ONE machine should run a given strategy at a time (two schedulers
= two paper ledgers diverging, or two live order streams). The lock here is
per-filesystem; it cannot coordinate across machines.

## Troubleshooting

| Symptom | What it means |
|---|---|
| `DH-901 Invalid_Authentication` | Token rejected. The package now renews or re-logs in by itself — no manual step. If it persists, your TOTP secret probably changed; re-run `credentials_setup.py`. |
| `Timed out waiting for another process to finish Dhan login` | Another strategy held `.dhan_token.lock` for over 4 minutes. Check whether that process is wedged; a lock from a *dead* process is broken automatically after 180s. |
| `Failed to obtain valid token after 3 attempts` | All retries failed. Run `verify.py` to see which step breaks, and check Dhan is not down. |
| `No credentials found` | `.dhan_credentials.json` is missing — this machine was never set up, or the file was moved. |
| `DH-905 Input_Exception` on market data | **Not** an auth problem. Dhan rejecting a data request for a specific instrument; auth is fine if `verify.py` passes. |

## Rules

1. **Never commit** `.dhan_credentials.json` or `.dhan_token.json` — every
   strategy repo's `.gitignore` must exclude them (they live outside the
   repos anyway, in this folder).
2. **Only this package generates tokens.** If a strategy generates its own,
   two TOTP logins in the same 30-second window can collide. All strategies
   share today's token from `.dhan_token.json` here. This is now *enforced*,
   not just requested: `get_valid_token()` takes a `.dhan_token.lock` before
   it logs in, so if two bots start together one performs the login and the
   other waits and reuses its token. A lock left behind by a killed process
   is broken automatically after 180s.
3. If Dhan rejects auth (`DH-901`), the package now recovers on its own —
   it renews, and falls back to a fresh PIN+TOTP login if renewal is also
   refused. Deleting `.dhan_token.json` by hand is no longer needed. To force
   a new token mid-session (rather than restarting a strategy), call
   `force_refresh()`. If the TOTP secret itself changed (re-enabled 2FA),
   re-run `credentials_setup.py`.
4. Existing consumers: `skew_hunter/auth/` is a thin shim re-exporting this
   package (old imports keep working); `swing_dual_momentum/dhan_data.py`
   uses the recipe above; and `dhan-nifty-options-paper-strategy/strategy/dhan_data.py`
   uses it only for historical data and quotes in the paper-only system.
5. `.dhan_credentials.json` holds your PIN and TOTP secret in plaintext.
   That is fine locally, but note this tree currently sits under OneDrive,
   so the file syncs to the cloud — move `strategy_by_ai/` outside OneDrive
   if you would rather it did not.
