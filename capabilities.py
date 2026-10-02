"""Does Dhan serve every Data-API capability to this token? Read-only probes.

The Data-API plan (₹499 + GST / month) promises six things:

    Real-time Price          REST /marketfeed/{ltp,ohlc,quote}  +  wss://api-feed.dhan.co
    Historical Data 5 Years  REST /charts/historical, /charts/intraday
    20 Market Depth          wss://depth-api-feed.dhan.co/twentydepth
    Option Chain on APIs     REST /optionchain, /optionchain/expirylist
    Full Market Depth        wss://full-depth-api.dhan.co/twohundreddepth   (200 levels)
    Expired Options Data     REST /charts/rollingoption

Login and entitlement are separate on Dhan's side: /profile can say dataPlan
"Active" while every one of these answers 806 / DH-902 (2026-10-01, several
accounts at once — madefortrade.in topic 94453). check_capabilities() asks
each endpoint directly so verify.py can show exactly which of the six the
account is getting, instead of inferring all six from one LTP quote.

Every probe is read-only. REST probes are spaced for Dhan's limits (market
quote 1/s, option chain 1 per 3 s). WebSocket probes connect, subscribe and
wait a few seconds: outside market hours a silent socket proves nothing, so
those come back as `None` ("unknown"), not as failures.
"""
from __future__ import annotations

import asyncio
import json
import struct
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, time as dtime

from .token_manager import API_BASE, IST, DhanUnreachable, _json, _request, rest_headers

NIFTY = 13                   # IDX_I  NIFTY 50
HDFCBANK = 1333              # NSE_EQ HDFCBANK — liquid, always listed

REST_GAP = 1.1               # marketfeed/* and charts/*: 1 request per second
CHAIN_GAP = 3.2              # option chain: 1 unique request per 3 seconds

# Data-API websocket disconnect reasons (Annexure)
WS_REASONS = {805: "too many requests / connections", 806: "Data APIs not subscribed",
              807: "access token expired", 808: "authentication failed", 809: "access token invalid",
              810: "client id invalid"}


@dataclass
class Capability:
    name: str
    endpoint: str
    ok: bool | None            # True served, False refused, None unknown (e.g. market closed)
    detail: str


def market_open_now(now: datetime | None = None) -> bool:
    """NSE cash/F&O regular session, Mon–Fri 09:15–15:30 IST. Ignores holidays."""
    now = now or datetime.now(IST)
    return now.weekday() < 5 and dtime(9, 15) <= now.time() <= dtime(15, 30)


# ══════════════════════════════════════════════════════════════════════════
# REST
# ══════════════════════════════════════════════════════════════════════════
def _rest(headers: dict, path: str, payload: dict, timeout: int = 60) -> tuple[bool | None, str, dict | None]:
    """(ok, detail, body). Entitlement, rate-limit and auth answers are told apart.
    A rate-limit answer is retried once after a pause — it says nothing about
    entitlement, and the first data call of a run often hits one."""
    for attempt in (1, 2):
        try:
            r = _request("POST", f"{API_BASE}{path}", json=payload, headers=headers, timeout=timeout)
        except DhanUnreachable as e:
            return None, f"no answer: {e}", None
        text = r.text
        if (r.status_code == 429 or '"805"' in text or "DH-904" in text) and attempt == 1:
            time.sleep(3.0)
            continue
        break
    body = _json(r)
    if r.status_code == 200:
        return True, "served", body if isinstance(body, dict) else None
    if r.status_code == 429 or '"805"' in text or "DH-904" in text:
        return None, f"rate limited twice (HTTP {r.status_code}) — not an entitlement answer", None
    if "806" in text or "DH-902" in text or "not subscribed" in text.lower():
        return False, f"HTTP {r.status_code}: Data APIs refused (806 / DH-902) — entitlement on Dhan's side", None
    if "DH-901" in text or "807" in text or "809" in text:
        return False, f"HTTP {r.status_code}: token rejected — {text[:120]}", None
    if "DH-905" in text:
        return None, f"HTTP {r.status_code}: Dhan rejected the probe's parameters — {text[:120]}", None
    return False, f"HTTP {r.status_code}: {text[:160]}", None


def _data(body: dict | None) -> dict:
    """Dhan nests `data` once or twice; return the innermost dict."""
    d = body.get("data") if isinstance(body, dict) else None
    if isinstance(d, dict) and isinstance(d.get("data"), dict):
        d = d["data"]
    return d if isinstance(d, dict) else {}


def _rest_capabilities(headers: dict, today: date) -> list[Capability]:
    out: list[Capability] = []

    ok, why, body = _rest(headers, "/marketfeed/ltp", {"NSE_EQ": [HDFCBANK], "IDX_I": [NIFTY]}, timeout=20)
    if ok:
        why = f"served — {len(_data(body).get('NSE_EQ', {})) + len(_data(body).get('IDX_I', {}))} instruments quoted"
    out.append(Capability("Real-time Price (REST market quote)", "POST /marketfeed/ltp", ok, why))
    time.sleep(REST_GAP)

    five_years = today - timedelta(days=5 * 365 + 7)
    ok, why, body = _rest(headers, "/charts/historical", {
        "securityId": str(NIFTY), "exchangeSegment": "IDX_I", "instrument": "INDEX",
        "expiryCode": 0, "oi": False, "fromDate": five_years.isoformat(), "toDate": today.isoformat()})
    if ok:
        ts = _data(body).get("timestamp") or []
        if ts:
            first = datetime.fromtimestamp(ts[0], IST).date()
            span = (today - first).days / 365.25
            why = f"served — {len(ts)} daily candles since {first} ({span:.1f} years)"
            if span < 4.5:
                ok, why = False, why + " — less than the 5 years the plan promises"
        else:
            ok, why = False, "served an empty series"
    out.append(Capability("Historical Data — daily, 5 years (NIFTY)", "POST /charts/historical", ok, why))
    time.sleep(REST_GAP)

    ok, why, body = _rest(headers, "/charts/intraday", {
        "securityId": str(NIFTY), "exchangeSegment": "IDX_I", "instrument": "INDEX", "interval": 5,
        "oi": False, "fromDate": (today - timedelta(days=6)).isoformat(), "toDate": today.isoformat()})
    if ok:
        why = f"served — {len(_data(body).get('timestamp') or [])} 5-minute candles over the last 6 days"
    out.append(Capability("Historical Data — intraday minutes", "POST /charts/intraday", ok, why))
    time.sleep(REST_GAP)

    ok, why, body = _rest(headers, "/optionchain/expirylist", {"UnderlyingScrip": NIFTY, "UnderlyingSeg": "IDX_I"}, timeout=30)
    expiry = None
    if ok:
        exps = body.get("data") if isinstance(body, dict) else None
        if isinstance(exps, list) and exps:
            expiry = exps[0]
            why = f"served — {len(exps)} expiries, nearest {expiry}"
        else:
            ok, why = False, "served no expiries"
    out.append(Capability("Option Chain — expiry list (NIFTY)", "POST /optionchain/expirylist", ok, why))
    if expiry:
        time.sleep(CHAIN_GAP)
        ok, why, body = _rest(headers, "/optionchain",
                              {"UnderlyingScrip": NIFTY, "UnderlyingSeg": "IDX_I", "Expiry": expiry}, timeout=30)
        if ok:
            why = f"served — {len(_data(body).get('oc') or {})} strikes for {expiry}"
        out.append(Capability("Option Chain — full chain with greeks", "POST /optionchain", ok, why))
    else:
        out.append(Capability("Option Chain — full chain with greeks", "POST /optionchain", ok,
                              "skipped — no expiry to ask for"))
    time.sleep(REST_GAP)

    # expiryCode 0 is answered "expiryCode is required" by Dhan (seen 2026-10-02);
    # 1 = the next weekly expiry, which premium_harvester also uses.
    ok, why, body = _rest(headers, "/charts/rollingoption", {
        "securityId": str(NIFTY), "exchangeSegment": "NSE_FNO", "instrument": "OPTIDX",
        "expiryFlag": "WEEK", "expiryCode": 1, "strike": "ATM", "drvOptionType": "CALL",
        "requiredData": ["open", "high", "low", "close", "iv", "oi", "strike", "spot"],
        "fromDate": (today - timedelta(days=12)).isoformat(), "toDate": today.isoformat(), "interval": 5})
    if ok:
        why = f"served — {len(_data(body).get('timestamp') or _data(body).get('close') or [])} ATM-call candles"
    out.append(Capability("Expired Options Data (rolling ATM, NIFTY)", "POST /charts/rollingoption", ok, why))
    return out


# ══════════════════════════════════════════════════════════════════════════
# WebSocket
# ══════════════════════════════════════════════════════════════════════════
def _disconnect_reason(frame: bytes) -> int | None:
    """Data-API feeds announce a kick with a binary packet, response code 50."""
    if isinstance(frame, (bytes, bytearray)) and len(frame) >= 10 and frame[0] == 50:
        try:
            return struct.unpack("<BHBIH", frame[:10])[4]
        except struct.error:
            return None
    return None


async def _ws_probe(url: str, subscribe: dict, wait: float, in_hours: bool) -> tuple[bool | None, str]:
    import websockets

    try:
        async with websockets.connect(url, open_timeout=15) as ws:
            await ws.send(json.dumps(subscribe))
            frames, binary, deadline = 0, 0, time.time() + wait
            try:
                while time.time() < deadline:
                    msg = await asyncio.wait_for(ws.recv(), timeout=max(0.2, deadline - time.time()))
                    frames += 1
                    reason = _disconnect_reason(msg)
                    if reason is not None:
                        return False, f"Dhan disconnected: {reason} {WS_REASONS.get(reason, '')}".strip()
                    if isinstance(msg, (bytes, bytearray)):
                        binary += 1
                        if binary >= 2:
                            return True, f"served — {binary} data packets within {wait:.0f}s"
            except asyncio.TimeoutError:
                pass
            except websockets.ConnectionClosed as e:
                if frames == 0:
                    msg = f"handshake accepted, then dropped (close {e.code}) with no data"
                    return (False, msg + " — during market hours this is a stale token or entitlement refusal") \
                        if in_hours else (None, msg + " — market closed, cannot tell")
                return False, f"closed ({e.code}) after {frames} frames"
            if binary:
                return True, f"served — {binary} data packet(s) within {wait:.0f}s"
            if in_hours:
                return False, f"connected but silent for {wait:.0f}s during market hours"
            return None, f"connected, silent for {wait:.0f}s — market closed, cannot tell"
    except websockets.InvalidStatus as e:
        return False, f"handshake rejected: HTTP {e.response.status_code}"
    except Exception as e:                       # noqa: BLE001
        return False, f"{type(e).__name__}: {str(e)[:120]}"


async def _ws_capabilities(client_id: str, access_token: str, wait: float) -> list[Capability]:
    in_hours = market_open_now()
    q = f"token={access_token}&clientId={client_id}&authType=2"
    live = await _ws_probe(
        f"wss://api-feed.dhan.co?version=2&{q}",
        {"RequestCode": 17, "InstrumentCount": 2,
         "InstrumentList": [{"ExchangeSegment": "NSE_EQ", "SecurityId": str(HDFCBANK)},
                            {"ExchangeSegment": "IDX_I", "SecurityId": str(NIFTY)}]}, wait, in_hours)
    d20 = await _ws_probe(
        f"wss://depth-api-feed.dhan.co/twentydepth?{q}",
        {"RequestCode": 23, "InstrumentCount": 1,
         "InstrumentList": [{"ExchangeSegment": "NSE_EQ", "SecurityId": str(HDFCBANK)}]}, wait, in_hours)
    d200 = await _ws_probe(
        f"wss://full-depth-api.dhan.co/twohundreddepth?{q}",
        {"RequestCode": 23, "ExchangeSegment": "NSE_EQ", "SecurityId": str(HDFCBANK)}, wait, in_hours)
    return [
        Capability("Real-time Price (live WebSocket feed)", "wss://api-feed.dhan.co", *live),
        Capability("20 Market Depth (WebSocket)", "wss://depth-api-feed.dhan.co/twentydepth", *d20),
        Capability("Full Market Depth — 200 levels (WebSocket)", "wss://full-depth-api.dhan.co/twohundreddepth", *d200),
    ]


# ══════════════════════════════════════════════════════════════════════════
def check_capabilities(client_id: str, access_token: str, *, websockets: bool = True,
                       ws_wait: float = 6.0) -> list[Capability]:
    """Probe all six Data-API capabilities with this token. Read-only; ~15 s."""
    headers = rest_headers(client_id, access_token)
    today = datetime.now(IST).date()
    out = _rest_capabilities(headers, today)
    if websockets:
        out += asyncio.run(_ws_capabilities(client_id, access_token, ws_wait))
    return out
