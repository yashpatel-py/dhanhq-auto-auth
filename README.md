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
│   ├── token_manager.py          generate / renew / validate / cache
│   ├── credentials_setup.py      one-time interactive setup
│   └── __init__.py
├── skew_hunter/               <- uses it via its auth/ shim
└── swing_dual_momentum/       <- uses it via dhan_data.py
```

## One-time setup (already done on this machine)

```bash
cd C:\Users\Administrator\Desktop\strategy_by_ai\yash_dhan_auth
python credentials_setup.py
```

Prompts for Client ID, login PIN, and TOTP secret; verifies the TOTP; writes
`.dhan_credentials.json` here. Tokens are then generated automatically —
Dhan tokens expire daily, and `get_valid_token_with_retry()` transparently
reuses today's token, renews it, or generates a fresh one via PIN+TOTP.

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

That's the whole integration. Useful extras:

```python
from yash_dhan_auth import TOKEN_FILE        # path to today's token json
from yash_dhan_auth import validate_token    # check a token against user_profile
```

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
fresh token is generated on first use. Also copy each strategy's
`.telegram_config.json` if you want alerts on the new machine.

Note: only ONE machine should run a given strategy at a time (two schedulers
= two paper ledgers diverging, or two live order streams).

## Rules

1. **Never commit** `.dhan_credentials.json` or `.dhan_token.json` — every
   strategy repo's `.gitignore` must exclude them (they live outside the
   repos anyway, in this folder).
2. **Only this package generates tokens.** If a strategy generates its own,
   two TOTP logins in the same 30-second window can collide. All strategies
   share today's token from `.dhan_token.json` here.
3. If Dhan rejects auth (`DH-901`), delete `.dhan_token.json` and run any
   strategy — a fresh token is generated automatically. If the TOTP secret
   itself changed (re-enabled 2FA), re-run `credentials_setup.py`.
4. Existing consumers: `skew_hunter/auth/` is a thin shim re-exporting this
   package (old imports keep working); `swing_dual_momentum/dhan_data.py`
   uses the recipe above.
