# yash_dhan_auth — one Dhan login for every strategy

This folder is the **single place** where your Dhan credentials live and
where the daily access token is generated, checked, and stored. Every
strategy under `strategy_by_ai/` authenticates through it — no strategy keeps
its own copy of your PIN/TOTP, and no two bots ever fight over token
generation. One login a day serves everything: trading, account, and all six
paid Data-API capabilities.

```
strategy_by_ai/
├── yash_dhan_auth/              <- this package
│   ├── .dhan_credentials.json      client id + PIN + TOTP secret   (NEVER commit)
│   ├── .dhan_token.json            today's access token            (NEVER commit)
│   ├── .dhan_token.lock            transient login lock            (NEVER commit)
│   ├── token_manager.py            login / check / cache / lock / ready-made clients
│   ├── capabilities.py             asks Dhan for each of the six data capabilities
│   ├── credentials_setup.py        one-time interactive setup
│   ├── verify.py                   proves one login serves every strategy + every capability
│   └── tests/                      offline regressions (no network, no secrets)
├── alpha_lab/                   <- uses it: data/dhan_history.py  (historical candles)
├── hma_vwap/                    <- uses it: core/market.py        (option chain, intraday, live feed)
├── premium_harvester/           <- uses it: live/dhan_client.py, data/dhan_tape.py (chain, quotes, expired options)
├── filings_feed/                <- uses it: core/book.py          (holdings / positions)
└── yash_kotak_auth/             <- the Kotak twin of this package
```

Needs `dhanhq>=2.2.0`, `pyotp`, `requests`, `websockets` — all pulled in by
any strategy's `requirements.txt`; the package has none of its own.

---

## 1. First-time setup — once per machine

Already done on this machine. On a **new** machine:

```bash
cd C:\Users\yashp\OneDrive\Desktop\strategy_by_ai\yash_dhan_auth
..\.venv\Scripts\python.exe credentials_setup.py --test-login
```

It asks for **Client ID** (10-digit number, web.dhan.co → My Profile),
**login PIN** (6 digits) and the **TOTP secret** — the base32 string Dhan
shows under *DhanHQ Trading APIs → Setup TOTP*, the same one you scan into an
authenticator app. PIN and secret are hidden while you type (that is
`getpass`, not a frozen terminal). It checks that the secret produces
6-digit codes, writes `.dhan_credentials.json`, restricts the file to your
Windows user, and with `--test-login` performs one real PIN+TOTP login to
prove the three values together. It refuses to overwrite an existing file
unless you type `yes`.

That is the only manual step, ever. From then on tokens are generated,
checked and replaced automatically — you never run a "log in" command.

## 2. Check it is working

```bash
cd C:\Users\yashp\OneDrive\Desktop\strategy_by_ai\yash_dhan_auth
..\.venv\Scripts\python.exe verify.py
```

Five sections:

1. **Shared package** — credentials present; token on disk decoded offline
   (type, issued, expires).
2. **Dhan accepts the token** — `/v2/profile`: token validity, active
   segments, DDPI/MTF, **Data API plan + its expiry**, and whether your
   current IP is whitelisted for order placement.
3. **Data-API capabilities** — each of the six paid capabilities is asked
   for directly (see §4). `[ OK ]` served, `[FAIL]` refused, `[ ?? ]`
   inconclusive — the three WebSocket feeds are silent outside 09:15–15:30
   IST, so run this during market hours when you need a verdict on them.
4. **Strategies** — every sibling folder that imports this package is run
   in its **own process through its own client code** and must land on the
   same token file, the same token and the same client id. Folders without a
   probe are listed so one can be added to `KNOWN` in `verify.py`.
5. **No second login** — the token on disk is unchanged after all of them ran.

Flags: `--no-login` (never log in — fail instead), `--no-ws` (skip the three
WebSocket probes, ~20 s faster), `--quick` (sections 1–2 only).

Expected on a healthy day: `All 17 checks passed`. If section 2 is green and
section 3 is all red with `806 / DH-902`, see Troubleshooting — that is Dhan,
not you.

---

## 3. Use it in ANY strategy — the recipe

Your strategy lives in `strategy_by_ai/<your_strategy>/`. Make the parent
folder importable once (every existing strategy does this at the top of the
module that talks to Dhan):

```python
import os, sys
_PARENT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))   # = strategy_by_ai/
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)
```

Then pick whichever of these you need. **Call them every time you need a
client — never cache `(cid, token)` or a client object yourself.** The
package caches for you, re-checks Dhan at most every 2 minutes, and
rebuilds the client the moment the token changes (daily roll, or a
mid-session replacement).

### A. Everything REST — one line

```python
from yash_dhan_auth import get_client

dhan = get_client()                                        # dhanhq facade on today's token
dhan.get_fund_limits()                                     # account
dhan.get_holdings();  dhan.get_positions()                 # portfolio
dhan.ticker_data({"IDX_I": [13], "NSE_EQ": [1333]})        # real-time price (REST)
dhan.historical_daily_data("13", "IDX_I", "INDEX", "2021-10-01", "2026-10-01")
dhan.intraday_minute_data("13", "IDX_I", "INDEX", "2026-09-25", "2026-10-01", interval=5)
dhan.expiry_list(13, "IDX_I");  dhan.option_chain(13, "IDX_I", "2026-10-07")
dhan.expired_options_data("13", "NSE_FNO", "OPTIDX", "WEEK", 1, "ATM", "CALL",
                          ["open","high","low","close","iv","oi","strike","spot"],
                          "2026-09-01", "2026-09-28", interval=1)
dhan.place_order(...)                                      # orders (needs the whitelisted static IP)
```

Every method returns `{"status": "success"|"failure", "remarks": ..., "data": ...}`
— the SDK never raises on an API error, so always check `status`.

### B. Raw HTTP for an endpoint the SDK lacks

```python
import requests
from yash_dhan_auth import rest_headers
r = requests.post("https://api.dhan.co/v2/marketfeed/quote", json={"NSE_FNO": [49081]},
                  headers=rest_headers(), timeout=15)
```

### C. WebSockets — live prices and market depth

```python
from yash_dhan_auth import market_feed, depth_feed
from dhanhq import MarketFeed

feed = market_feed([(MarketFeed.NSE, "1333", MarketFeed.Full),       # security id as a STRING
                    (MarketFeed.IDX, "13", MarketFeed.Quote)],
                   on_ticks=lambda f, tick: print(tick))
feed.run()                                                  # or feed.start() for a thread

d20  = depth_feed([(1, "1333"), (1, "1333")], level=20)     # ≤50 instruments per socket
d200 = depth_feed([(1, "1333")], level=200)                 # ONE instrument per socket
```

If you run your own feed loop (hma_vwap and premium_harvester do), give it a
token provider so every reconnect uses the **current** token:

```python
from yash_dhan_auth import get_valid_token_with_retry
feed = DhanFeed(cid, tok, instruments, token_provider=lambda: get_valid_token_with_retry()[1])
```

A stale token on a feed looks like this: Dhan **accepts the handshake and the
subscribe, then drops the socket bare (close 1006) with no data** — the same
symptom as a bad instrument list. If that happens during market hours,
re-ask for the token before reconnecting.

Limits that are **shared across all your strategies on this account**: 5
live-feed sockets, 5000 instruments each, 100 per subscribe message; depth
feeds NSE equity/F&O only.

### D. The raw pair, when you must

```python
from yash_dhan_auth import get_valid_token_with_retry
cid, token = get_valid_token_with_retry()
```

---

## 4. The six paid Data-API capabilities — what they map to

| Plan feature (₹499 + GST / month) | `get_client()` method | Endpoint | Limits / notes |
|---|---|---|---|
| **Real-time Price** | `ticker_data`, `ohlc_data`, `quote_data` (REST) · `market_feed()` (WS) | `POST /marketfeed/ltp` `/ohlc` `/quote` · `wss://api-feed.dhan.co` | REST 1 request/s; WS 5 sockets × 5000 instruments |
| **Historical Data for 5 Years** | `historical_daily_data` · `intraday_minute_data` | `POST /charts/historical` · `/charts/intraday` | daily back to inception; intraday ≤90 days per call, intervals 1/5/15/25/60 |
| **20 Market Depth** | `depth_feed(level=20)` | `wss://depth-api-feed.dhan.co/twentydepth` | ≤50 instruments per socket, NSE EQ/F&O |
| **Option Chain on APIs** | `expiry_list` · `option_chain` | `POST /optionchain/expirylist` · `/optionchain` | **1 unique request per 3 s**; response nests `data` twice |
| **Full Market Depth** (200 levels) | `depth_feed(level=200)` | `wss://full-depth-api.dhan.co/twohundreddepth` | 1 instrument per socket |
| **Expired Options Data** | `expired_options_data` | `POST /charts/rollingoption` | ≤30 days per call, up to 5 years back; `expiryCode` is required and **`0` is answered "expiryCode is required" — use `1`** (next weekly) |

Trading and account APIs (orders, super/forever orders, portfolio, funds,
statements, EDIS, kill switch) are free with every Dhan account and need
only the token — except **order placement**, which SEBI requires to come
from your whitelisted static IP (`verify.py` section 2 shows the match).

Every one of these is gated by the **same** entitlement flag on Dhan's side,
and that flag is separate from the login. `verify.py` asks each endpoint so
you see exactly which ones you are getting today.

---

## 5. What actually happens on a call

`get_valid_token()` — the thing every helper above calls — does, in order:

1. **Today's token on disk, Dhan accepts it** → returned. "Today" is the IST
   calendar date it was minted (a token minted on day D is always good past
   midnight, so a same-day token spans the whole trading day); the JWT
   `exp` is also checked offline, with a 5-minute margin. Dhan is asked
   (`/v2/profile`) at most once every **2 minutes per process**, so calling
   this per request costs nothing.
2. **Dhan unreachable while checking** (timeout, 429, 5xx) → today's token is
   returned anyway. A new login would fail just the same, and would only
   rotate the token under the other strategies once Dhan came back.
3. **Token missing, from an earlier day, or rejected** → take
   `.dhan_token.lock`, **re-read the disk** (another strategy may have just
   logged in while we queued) and reuse that token if Dhan accepts it.
4. **Still nothing** → log in with PIN + TOTP. One login, and one retry in
   the next 30-second window only if Dhan rejected the code. A wrong
   PIN/secret raises `CredentialsRejected` and is **not retried** (that only
   risks a lockout); a login inside Dhan's 2-minute gap raises
   `TokenMintThrottled` and `get_valid_token_with_retry` waits it out and
   re-reads the disk first.

### Two kinds of token

Dhan stamps every token with how it was made (`tokenConsumerType`, readable
offline with `token_type(token)`):

| Type | Made by | Valid | Renewable |
|---|---|---|---|
| `APP` | this package's PIN+TOTP login (`auth.dhan.co/app/generateAccessToken`) | 24 h from issue | **no** — `DH-905 Renewal of token not allowed for this token type` |
| `SELF` | you, on web.dhan.co → Access DhanHQ APIs → Generate Access Token | 24 h | yes (`/v2/RenewToken`) |

Everything here uses `APP` tokens. Dhan keeps **one live token per client**:
any new login — including one you do by hand on web.dhan.co — invalidates
the token every running strategy holds. Never paste a token into a chat or a
file: it is a live login to the account for 24 hours.

---

## 6. When Dhan says no mid-session — what each answer means

| Dhan says | Meaning | What your strategy should do |
|---|---|---|
| `DH-901`, WS reason `807` / `809` | the token is dead (expired, or another login replaced it) | `force_refresh(bad_token=<the token you used>)`: if another strategy already replaced it, you get **that** token instead of a second login; then rebuild your client (or just call `get_client()` again) |
| `806` / `DH-902` ("not subscribed … HTTP Status 451") | **entitlement**, not auth — Dhan is refusing Data APIs to the account | do **not** re-login (it changes nothing and rotates everyone's token); back off, alert, check `verify.py` section 2 (`dataPlan`) and Troubleshooting |
| `DH-904`, `805`, HTTP 429 | rate limit | back off; the limits are per account, shared by all your strategies |
| `DH-905` | your request parameters | fix the call — auth is fine |
| `DH-907` | no data for that instrument/range | not an error of yours or of auth |
| WS handshake OK, then bare close `1006`, no packets | stale token (or a market-closed feed) | re-ask `get_valid_token_with_retry()` before reconnecting |

For a long-running process (a server that lives across midnight): keep
calling `get_client()` / `get_valid_token()` at the point of use; both are
cheap and roll to the new day's token on their own. If you must hold the
pair, check `token_info()["is_today"]` on a timer and re-ask when it flips —
never call `force_refresh()` for the daily roll (that is what caused the
2026-09-22 double-login; `get_valid_token()` re-reads the disk, `force_refresh()`
without `bad_token` does not).

---

## 7. Running several strategies at once

Starting them together is safe: the lock in step 3 means the first process
performs the login and the second reuses the token it wrote, so two
strategies starting seconds apart still produce exactly one Dhan login. A
lock left behind by a killed process is broken automatically after 180 s; a
live holder refreshes it, so it is never mistaken for a dead one.

What is **not** per strategy and is shared across everything on the account:
the 5 WebSocket sockets, the REST rate limits, and the single live token.
Only ONE machine should run a given strategy at a time — the lock is
per-filesystem and cannot coordinate across machines, and two machines
logging in would keep invalidating each other's token.

---

## 8. Two machines: the server runs the strategies, the laptop does not log in

Dhan keeps **one live token per client**. The server (primary static IP) and
this laptop (secondary IP) share that one token, so **only one of them may
ever log in** — a login on the laptop invalidates the server's token
mid-session; the server recovers by logging in again (`force_refresh`), which
in turn kills the laptop's token, and so on, each round costing a reconnect
and Dhan's 2-minute gap. The lock file cannot prevent this: it is
per-filesystem.

The rule, enforced by the package:

- **Server** — the only machine that logs in. Nothing to set.
- **Laptop** — set `YASH_DHAN_AUTH_NO_LOGIN=1` (User environment variable,
  once). With it set the package will use the token on disk while it is from
  today and Dhan accepts it, and otherwise raise `LoginDisabled` instead of
  logging in — a strategy, a backtest or `verify.py` started here by mistake
  can no longer touch the server's token.

```powershell
[Environment]::SetEnvironmentVariable("YASH_DHAN_AUTH_NO_LOGIN", "1", "User")
```

When the laptop does need Dhan data for a day (an `alpha_lab` pull, a
`verify.py` run), copy **today's** `.dhan_token.json` from the server into
`yash_dhan_auth/` here and work read-only on it (`verify.py --no-login`); it
dies on its own after 24 h. Copy it over scp / a password manager — never
through git, chat or email.

Swapping roles (laptop becomes the live machine): stop the strategies on
the server first, then unset the variable here. Never run the same strategy
on both — two schedulers mean two paper ledgers diverging, or two live order
streams.

The code is OS-neutral: file locking, atomic writes, IST dates and the
file-permission hardening (`chmod 600` on Linux, per-user ACL on Windows)
all work the same on a Linux VPS and on Windows.

## 9. Moving to a new machine (e.g. VPS → laptop)

The **code** travels through GitHub; the **secrets** travel by hand — that
is the whole point of the split.

```bash
cd <wherever>/strategy_by_ai
git clone https://github.com/yashpatel-py/yash-dhan-auth.git yash_dhan_auth
# ...clone the strategies you run there, then install one of their requirements.txt
```

Then EITHER copy `.dhan_credentials.json` from the old machine into
`yash_dhan_auth/` (USB / password manager / encrypted transfer — **not git,
not chat, not email**), OR run `python credentials_setup.py --test-login`
there and re-enter the three values. Do not copy `.dhan_token.lock`, and copy
`.dhan_token.json` only in the laptop case of §8; the machine that logs in
generates a fresh token on first use.

---

## 10. Troubleshooting

| Symptom | What it means |
|---|---|
| `CredentialsRejected … Dhan rejected the PIN/TOTP twice` | Wrong Client ID, PIN or TOTP secret (a re-enabled 2FA changes the secret). Re-run `credentials_setup.py --test-login`. Nothing retries this on purpose. |
| `TokenMintThrottled … once every 2 minutes` | Something logged in less than 2 minutes ago — usually another strategy, whose token is already on disk. `get_valid_token_with_retry` waits and reuses it; nothing to do. |
| `LoginDisabled … YASH_DHAN_AUTH_NO_LOGIN=1 on this machine` | This is the laptop and there is no usable token on disk. Copy today's `.dhan_token.json` from the server for a read-only session, or — only if the server is stopped — unset the variable. See §8. |
| The server keeps logging in again every few minutes / feeds reconnect in a loop | Some other machine is also logging in with the same client id (a laptop without `YASH_DHAN_AUTH_NO_LOGIN=1`, a token generated by hand on web.dhan.co). One client, one token: stop the other login. |
| `DhanUnreachable` | Network / Dhan down. Today's token keeps being used; no login is attempted until Dhan answers. |
| `Timed out … waiting for another process to finish Dhan login` | Another strategy held `.dhan_token.lock` for over 5 minutes. Check whether that process is wedged. |
| `806 Data APIs not Subscribed` / `DH-902 … HTTP Status 451` on every data call while `verify.py` §2 is green and `dataPlan Active` | Dhan has stopped serving data to the account — an entitlement flag on their side that no login changes (tried on 2026-10-02 with fresh tokens). On 2026-10-01 several users reported the same at the same hour (madefortrade.in topic 94453). Email `apihelp@dhan.co` (cc `help@dhan.co`) with the error, the time it started and your client id; ask for the lost days to be added to `dataValidity`. |
| `DH-905 Input_Exception` on market data | Not auth — Dhan rejecting the parameters of that one request. For `/charts/rollingoption` use `expiryCode=1`. |
| Live feed connects then dies with close `1006`, no packets, during market hours | Stale token. Re-ask the package for the token before reconnecting (`token_provider`). Outside market hours this is normal. |
| `No credentials found` | `.dhan_credentials.json` is missing — this machine was never set up, or the file was moved. |

---

## 11. Rules

1. **Never commit** `.dhan_credentials.json` or `.dhan_token.json`. They are
   git-ignored here and live outside every strategy repo.
2. **Only this package logs in.** A strategy that generates its own token
   invalidates everyone else's. Use `get_client()` / `get_valid_token*()`.
3. **Never cache the token yourself across days.** Ask at the point of use;
   the package's own cache makes that free.
3a. **One machine logs in.** Every other machine that holds these
   credentials sets `YASH_DHAN_AUTH_NO_LOGIN=1` (§8).
4. **Do not log tokens.** `verify.py` prints a SHA-256 fingerprint, never
   the token. The SDK's `FullDepth.connect()` prints its socket URL — token
   included — to stdout; `depth_feed()` here uses a subclass that does not.
   If you build the WebSocket URL yourself, redact it in logs.
5. `.dhan_credentials.json` holds your PIN and TOTP secret in plaintext,
   readable by your Windows user only (set at write time). This tree sits
   under OneDrive, so the file syncs to the cloud — move `strategy_by_ai/`
   outside OneDrive if you would rather it did not.

## 12. Tests

```bash
cd C:\Users\yashp\OneDrive\Desktop\strategy_by_ai\yash_dhan_auth
..\.venv\Scripts\python.exe -m unittest discover tests
```

Offline — every Dhan answer is faked, files live in a temp dir, nothing
sleeps. They pin the behaviours above: unreachable ≠ rejected, one TOTP
retry then stop, the 2-minute gap, lock serialisation, reuse of a token
another process minted, `force_refresh(bad_token=…)`.

## 13. Public API

```python
from yash_dhan_auth import (
    # use these
    get_client,                  # dhanhq facade on today's token, cached per token
    get_valid_token_with_retry,  # (client_id, access_token) with retries
    get_valid_token,             # same, single attempt
    force_refresh,               # force_refresh(bad_token=tok): replace a token Dhan rejects
    market_feed, depth_feed,     # dhanhq MarketFeed / FullDepth(20|200) on today's token
    get_context, rest_headers,   # DhanContext / headers for raw requests calls
    # diagnostics (all read-only)
    token_info,                  # offline: type, issued, expires, seconds_left, is_today, usable
    check_token,                 # (cid, tok) -> ("valid"|"rejected"|"unreachable", detail)
    validate_token,              # (cid, tok) -> bool
    account_status,              # /profile: tokenValidity, activeSegment, dataPlan, dataValidity…
    data_access,                 # (cid, tok) -> (ok, reason): one LTP quote
    check_capabilities,          # (cid, tok) -> [Capability] for all six data capabilities
    market_open_now,
    token_claims, token_type, token_expiry,
    # low level
    generate_token, renew_token, restrict_permissions, login_disabled,
    TokenError, CredentialsRejected, TokenMintThrottled, DhanUnreachable, LoginDisabled,
    TOKEN_FILE, CREDS_FILE, LOCK_FILE, IST,
)
```
