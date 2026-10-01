"""Offline regressions for yash_dhan_auth — no network, no real credentials.

    cd strategy_by_ai\\yash_dhan_auth
    ..\\.venv\\Scripts\\python.exe -m unittest discover tests

Every Dhan answer is faked through token_manager._request; the token, lock
and credentials files live in a temp dir; time.sleep is recorded, not slept.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

_HERE = os.path.abspath(os.path.dirname(__file__))
_PARENT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from yash_dhan_auth import token_manager as tm            # noqa: E402
from yash_dhan_auth import capabilities as caps           # noqa: E402

# The scenarios below deliberately drive the package through a wrong PIN, Dhan
# being down, a stale lock and the 2-minute gap; its warnings about them are
# the expected behaviour, not test noise worth reading.
import logging                                            # noqa: E402
logging.getLogger("auth.token_manager").setLevel(logging.CRITICAL)

SECRET = "JBSWY3DPEHPK3PXP"          # a valid base32 TOTP secret (RFC 6238 test vector)


def jwt(hours_left: float = 20.0, typ: str = "APP", tag: str = "x") -> str:
    """A Dhan-shaped token: header.payload.signature with Dhan's claims."""
    now = int(time.time())
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")   # noqa: E731
    return f"{b64({'alg': 'HS256'})}.{b64({'iss': 'dhan', 'iat': now, 'exp': now + int(hours_left * 3600), 'tokenConsumerType': typ, 'dhanClientId': '1', 'tag': tag})}.sig"


class Resp:
    def __init__(self, status: int, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body) if not isinstance(body, str) else body

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


PROFILE_OK = Resp(200, {"dhanClientId": "1", "tokenValidity": "03/10/2026 02:28", "dataPlan": "Active"})
PROFILE_REJECT = Resp(401, {"errorType": "Invalid_Authentication", "errorCode": "DH-901",
                            "errorMessage": "Client ID or user generated access token is invalid or expired"})


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self._patches = [
            patch.object(tm, "TOKEN_FILE", os.path.join(d, ".dhan_token.json")),
            patch.object(tm, "LOCK_FILE", os.path.join(d, ".dhan_token.lock")),
            patch.object(tm, "CREDS_FILE", os.path.join(d, ".dhan_credentials.json")),
            patch.object(tm, "restrict_permissions", lambda path: None),
        ]
        for p in self._patches:
            p.start()
        with open(tm.CREDS_FILE, "w") as f:
            json.dump({"client_id": "1", "pin": "123456", "totp_secret": SECRET}, f)
        tm._invalidate_cache()
        tm._validated.clear()
        tm._last_profile = None
        tm._client = tm._client_token = None
        self.sleeps: list[float] = []
        self._sleep = patch.object(tm.time, "sleep", lambda s: self.sleeps.append(s))
        self._sleep.start()

    def tearDown(self):
        self._sleep.stop()
        for p in self._patches:
            p.stop()
        self.tmp.cleanup()

    # helpers
    def write_token(self, token: str, cid: str = "1", day_offset: int = 0) -> None:
        day = (datetime.now(tm.IST) + timedelta(days=day_offset)).date().isoformat()
        with open(tm.TOKEN_FILE, "w") as f:
            json.dump({"client_id": cid, "access_token": token, "generated_date": day,
                       "generated_at": f"{day}T09:00:00+05:30"}, f)
        tm._invalidate_cache()

    def disk_token(self) -> str:
        with open(tm.TOKEN_FILE) as f:
            return json.load(f)["access_token"]


# ══════════════════════════════════════════════════════════════════════════
class ClaimsTests(Base):
    def test_claims_type_and_expiry(self):
        t = jwt(hours_left=10, typ="SELF")
        self.assertEqual(tm.token_type(t), "SELF")
        self.assertAlmostEqual((tm.token_expiry(t) - datetime.now(tm.IST)).total_seconds(), 36000, delta=5)
        self.assertEqual(tm.token_type("not-a-jwt"), "")
        self.assertIsNone(tm.token_expiry("not-a-jwt"))

    def test_usable_needs_today_and_expiry_margin(self):
        self.write_token(jwt(10))
        self.assertTrue(tm._usable(tm._load_saved_token()))
        self.write_token(jwt(10), day_offset=-1)
        self.assertFalse(tm._usable(tm._load_saved_token()), "yesterday's token is never reused")
        self.write_token(jwt(hours_left=0.02))
        self.assertFalse(tm._usable(tm._load_saved_token()), "a token 72 s from exp is already dead")

    def test_token_info_is_offline_and_never_holds_the_token(self):
        self.write_token(jwt(5))
        with patch.object(tm, "_request", side_effect=AssertionError("network")):
            info = tm.token_info()
        self.assertTrue(info["usable"])
        self.assertEqual(info["token_type"], "APP")
        self.assertNotIn("access_token", info)
        self.assertGreater(info["seconds_left"], 4 * 3600)

    def test_unreadable_token_file_is_treated_as_absent(self):
        with open(tm.TOKEN_FILE, "w") as f:
            f.write("{")
        self.assertIsNone(tm._load_saved_token())
        with open(tm.TOKEN_FILE, "w") as f:
            json.dump({"client_id": "1"}, f)          # no access_token
        tm._invalidate_cache()
        self.assertIsNone(tm._load_saved_token())


class ClassificationTests(Base):
    def test_login_errors(self):
        c = tm._classify_login_error
        self.assertEqual(c(400, "HTTP 400 : Token can be generated once every 2 minutes"), "throttled")
        self.assertEqual(c(401, "HTTP 401 DH-901 Invalid_Authentication: invalid"), "rejected")
        self.assertEqual(c(400, "HTTP 400 : Invalid TOTP"), "rejected")
        self.assertEqual(c(503, "HTTP 503: gateway"), "unreachable")
        self.assertEqual(c(429, "HTTP 429"), "unreachable")
        self.assertEqual(c(400, "HTTP 400 DH-905 Input_Exception: dhanClientId is required"), "other")

    def test_profile_answers(self):
        self.assertEqual(tm._classify_profile(200, {"dhanClientId": "1"}), "valid")
        self.assertEqual(tm._classify_profile(401, {"errorCode": "DH-901"}), "rejected")
        self.assertEqual(tm._classify_profile(500, {}), "unreachable")
        self.assertEqual(tm._classify_profile(429, {}), "unreachable")

    def test_check_token(self):
        with patch.object(tm, "_request", return_value=PROFILE_OK):
            status, detail = tm.check_token("1", "t")
        self.assertEqual(status, "valid")
        self.assertEqual(detail["dataPlan"], "Active")
        self.assertTrue(tm._recently_validated("t"))
        with patch.object(tm, "_request", return_value=PROFILE_REJECT):
            self.assertEqual(tm.check_token("1", "t")[0], "rejected")
        with patch.object(tm, "_request", side_effect=tm.DhanUnreachable("timeout")):
            self.assertEqual(tm.check_token("1", "t")[0], "unreachable")

    def test_data_access_tells_entitlement_from_rate_limit(self):
        with patch.object(tm, "_request", return_value=Resp(401, {"806": "Data APIs not subscribed"})):
            ok, why = tm.data_access("1", "t")
        self.assertFalse(ok)
        self.assertIn("entitlement", why)
        with patch.object(tm, "_request", return_value=Resp(429, {"805": "Too many requests"})):
            ok, why = tm.data_access("1", "t")
        self.assertFalse(ok)
        self.assertIn("rate limited", why)
        with patch.object(tm, "_request", return_value=Resp(200, {"status": "success", "data": {}})):
            self.assertTrue(tm.data_access("1", "t")[0])


class GenerateTokenTests(Base):
    def test_success_saves_token_and_marks_it_validated(self):
        tok = jwt(24)
        with patch.object(tm, "_request", return_value=Resp(200, {"accessToken": tok, "expiryTime": "x"})) as rq:
            cid, got = tm.generate_token()
        self.assertEqual((cid, got), ("1", tok))
        self.assertEqual(rq.call_count, 1)
        self.assertEqual(rq.call_args.kwargs["params"]["pin"], "123456")
        self.assertRegex(rq.call_args.kwargs["params"]["totp"], r"^\d{6}$")
        with open(tm.TOKEN_FILE) as f:
            saved = json.load(f)
        self.assertEqual(saved["token_type"], "APP")
        self.assertTrue(saved["expires_at"])
        self.assertTrue(tm._recently_validated(tok), "a freshly issued token needs no /profile round-trip")

    def test_rejected_code_is_retried_exactly_once_then_credentials_rejected(self):
        with patch.object(tm, "_request", return_value=PROFILE_REJECT) as rq:
            with self.assertRaises(tm.CredentialsRejected):
                tm.generate_token()
        self.assertEqual(rq.call_count, 2)
        self.assertTrue(any(s > 1 for s in self.sleeps), "waited for the next TOTP window before the retry")
        self.assertFalse(os.path.exists(tm.TOKEN_FILE))

    def test_mint_gap_raises_throttled_without_a_second_login(self):
        body = {"errorMessage": "Token can be generated once every 2 minutes"}
        with patch.object(tm, "_request", return_value=Resp(400, body)) as rq:
            with self.assertRaises(tm.TokenMintThrottled) as cm:
                tm.generate_token()
        self.assertEqual(rq.call_count, 1)
        self.assertEqual(cm.exception.retry_after, tm.MINT_GAP_SEC)

    def test_bad_parameters_are_not_retried(self):
        body = {"errorCode": "DH-905", "errorType": "Input_Exception", "errorMessage": "pin is required"}
        with patch.object(tm, "_request", return_value=Resp(400, body)) as rq:
            with self.assertRaises(tm.TokenError):
                tm.generate_token()
        self.assertEqual(rq.call_count, 1)

    def test_network_failure_is_unreachable(self):
        with patch.object(tm, "_request", side_effect=tm.DhanUnreachable("timeout")):
            with self.assertRaises(tm.DhanUnreachable):
                tm.generate_token()

    def test_missing_credentials(self):
        os.unlink(tm.CREDS_FILE)
        with self.assertRaises(FileNotFoundError):
            tm.generate_token()


class GetValidTokenTests(Base):
    def test_happy_path_validates_once_per_ttl(self):
        tok = jwt(20)
        self.write_token(tok)
        with patch.object(tm, "_request", return_value=PROFILE_OK) as rq, \
                patch.object(tm, "generate_token", side_effect=AssertionError("must not log in")):
            self.assertEqual(tm.get_valid_token(), ("1", tok))
            self.assertEqual(tm.get_valid_token(), ("1", tok))
            self.assertEqual(tm.get_valid_token(), ("1", tok))
        self.assertEqual(rq.call_count, 1, "/profile asked once, then cached for VALIDATION_TTL_SEC")

    def test_dhan_unreachable_keeps_todays_token_and_never_logs_in(self):
        tok = jwt(20)
        self.write_token(tok)
        with patch.object(tm, "_request", side_effect=tm.DhanUnreachable("connection reset")), \
                patch.object(tm, "generate_token", side_effect=AssertionError("must not log in")):
            self.assertEqual(tm.get_valid_token(), ("1", tok))
        self.assertFalse(os.path.exists(tm.LOCK_FILE), "lock released")

    def test_rejected_token_triggers_one_login(self):
        old, new = jwt(20, tag="old"), jwt(24, tag="new")
        self.write_token(old)

        def fake_generate():
            tm._save_token("1", new)
            return "1", new

        with patch.object(tm, "_request", return_value=PROFILE_REJECT) as rq, \
                patch.object(tm, "generate_token", side_effect=fake_generate) as gen:
            self.assertEqual(tm.get_valid_token(), ("1", new))
        self.assertEqual(gen.call_count, 1)
        self.assertEqual(rq.call_count, 1, "the rejected token is not asked about again inside the lock")
        self.assertEqual(self.disk_token(), new)

    def test_yesterdays_token_is_replaced_without_asking_dhan_about_it(self):
        new = jwt(24, tag="new")
        self.write_token(jwt(20, tag="old"), day_offset=-1)

        def fake_generate():
            tm._save_token("1", new)
            return "1", new

        with patch.object(tm, "_request", side_effect=AssertionError("no /profile for a stale token")), \
                patch.object(tm, "generate_token", side_effect=fake_generate):
            self.assertEqual(tm.get_valid_token(), ("1", new))

    def test_reuses_token_another_process_minted_while_we_queued(self):
        old, theirs = jwt(20, tag="old"), jwt(24, tag="theirs")
        self.write_token(old)

        def fake_check(cid, tok):
            if tok == old:
                self.write_token(theirs)           # "another process" rotates the token on disk
                return "rejected", "DH-901"
            return "valid", {"dhanClientId": cid}

        with patch.object(tm, "check_token", side_effect=fake_check), \
                patch.object(tm, "generate_token", side_effect=AssertionError("second login")):
            self.assertEqual(tm.get_valid_token(), ("1", theirs))

    def test_self_token_from_today_is_renewed_not_regenerated(self):
        self.write_token(jwt(20, typ="SELF"))
        with patch.object(tm, "_request", return_value=PROFILE_REJECT), \
                patch.object(tm, "renew_token", return_value=("1", "renewed")) as ren, \
                patch.object(tm, "generate_token", side_effect=AssertionError("login")):
            self.assertEqual(tm.get_valid_token(), ("1", "renewed"))
        self.assertEqual(ren.call_count, 1)


class ForceRefreshTests(Base):
    def test_reuses_newer_token_already_on_disk(self):
        bad, newer = jwt(20, tag="bad"), jwt(24, tag="newer")
        self.write_token(newer)
        with patch.object(tm, "_request", return_value=PROFILE_OK), \
                patch.object(tm, "generate_token", side_effect=AssertionError("second login")):
            self.assertEqual(tm.force_refresh(bad_token=bad), ("1", newer))

    def test_logs_in_when_disk_still_holds_the_bad_token(self):
        bad, new = jwt(20, tag="bad"), jwt(24, tag="new")
        self.write_token(bad)
        tm._validated[bad] = time.time()
        with patch.object(tm, "generate_token", return_value=("1", new)) as gen:
            self.assertEqual(tm.force_refresh(bad_token=bad), ("1", new))
        self.assertEqual(gen.call_count, 1)
        self.assertFalse(tm._recently_validated(bad))

    def test_without_bad_token_always_logs_in(self):
        self.write_token(jwt(20))
        with patch.object(tm, "generate_token", return_value=("1", "n")) as gen:
            tm.force_refresh()
        self.assertEqual(gen.call_count, 1)


class NoLoginMachineTests(Base):
    """YASH_DHAN_AUTH_NO_LOGIN=1 — the laptop while the server runs the strategies."""

    def setUp(self):
        super().setUp()
        self._env = patch.dict(os.environ, {tm.NO_LOGIN_ENV: "1"})
        self._env.start()

    def tearDown(self):
        self._env.stop()
        super().tearDown()

    def test_todays_valid_token_is_still_served(self):
        tok = jwt(20)
        self.write_token(tok)
        with patch.object(tm, "_request", return_value=PROFILE_OK):
            self.assertEqual(tm.get_valid_token(), ("1", tok))

    def test_login_is_refused_without_touching_dhan(self):
        with patch.object(tm, "_request", side_effect=AssertionError("no network")):
            with self.assertRaises(tm.LoginDisabled):
                tm.generate_token()
            self.write_token(jwt(20, typ="SELF"))
            with self.assertRaises(tm.LoginDisabled):
                tm.renew_token()

    def test_stale_token_raises_login_disabled_and_is_not_retried(self):
        self.write_token(jwt(20), day_offset=-1)
        with patch.object(tm, "_request", side_effect=AssertionError("no network")):
            with self.assertRaises(tm.LoginDisabled):
                tm.get_valid_token_with_retry()
        self.assertEqual(self.sleeps, [])
        self.assertFalse(os.path.exists(tm.LOCK_FILE))


class RetryTests(Base):
    def test_credentials_rejected_is_not_retried(self):
        with patch.object(tm, "get_valid_token", side_effect=tm.CredentialsRejected("bad pin")) as g:
            with self.assertRaises(tm.CredentialsRejected):
                tm.get_valid_token_with_retry()
        self.assertEqual(g.call_count, 1)
        self.assertEqual(self.sleeps, [])

    def test_mint_gap_is_waited_out(self):
        with patch.object(tm, "get_valid_token",
                          side_effect=[tm.TokenMintThrottled("gap", retry_after=120), ("1", "t")]):
            self.assertEqual(tm.get_valid_token_with_retry(delay=30), ("1", "t"))
        self.assertEqual(self.sleeps, [125])

    def test_generic_failures_retry_with_delay_then_raise(self):
        with patch.object(tm, "get_valid_token", side_effect=tm.DhanUnreachable("down")):
            with self.assertRaises(tm.TokenError):
                tm.get_valid_token_with_retry(max_retries=3, delay=7)
        self.assertEqual(self.sleeps, [7, 7])


class LockTests(Base):
    def test_stale_lock_is_broken(self):
        with open(tm.LOCK_FILE, "w") as f:
            f.write("dead\n")
        old = time.time() - tm.LOCK_STALE_SEC - 5
        os.utime(tm.LOCK_FILE, (old, old))
        with tm._login_lock(wait=5):
            self.assertTrue(os.path.exists(tm.LOCK_FILE))
        self.assertFalse(os.path.exists(tm.LOCK_FILE))

    def test_live_lock_serialises_threads(self):
        self._sleep.stop()                        # real sleeping needed here
        try:
            order: list[str] = []

            def worker(name):
                with tm._login_lock(wait=10):
                    order.append(f"{name}-in")
                    time.sleep(0.3)
                    order.append(f"{name}-out")

            a, b = threading.Thread(target=worker, args=("a",)), threading.Thread(target=worker, args=("b",))
            a.start(); time.sleep(0.05); b.start(); a.join(); b.join()
            self.assertEqual(order[:2], ["a-in", "a-out"])
            self.assertEqual(order[2:], ["b-in", "b-out"])
        finally:
            self._sleep.start()

    def test_lock_timeout_raises(self):
        with open(tm.LOCK_FILE, "w") as f:
            f.write("alive\n")
        with patch.object(tm.time, "time", side_effect=[1000.0, 1000.0, 1000.0, 1000.5, 1001.0, 1002.5, 1010.0, 1010.0]):
            with self.assertRaises(tm.TokenError):
                with tm._login_lock(wait=2):
                    pass


class ClientTests(Base):
    def test_get_client_is_cached_per_token_and_rebuilt_on_change(self):
        a, b = jwt(20, tag="a"), jwt(24, tag="b")
        with patch.object(tm, "get_valid_token_with_retry", side_effect=[("1", a), ("1", a), ("1", b)]):
            c1, c2, c3 = tm.get_client(), tm.get_client(), tm.get_client()
        self.assertIs(c1, c2)
        self.assertIsNot(c2, c3)
        self.assertEqual(c3.dhan_http.access_token, b)
        self.assertEqual(c3.dhan_http.header["client-id"], "1")

    def test_rest_headers(self):
        h = tm.rest_headers("1", "tok")
        self.assertEqual(h["access-token"], "tok")
        self.assertEqual(h["client-id"], "1")


class CapabilityTests(unittest.TestCase):
    def test_rest_classification(self):
        with patch.object(caps, "_request", return_value=Resp(401, {"806": "Data APIs not subscribed"})):
            ok, why, _ = caps._rest({}, "/x", {})
        self.assertIs(ok, False); self.assertIn("806", why)
        with patch.object(caps, "_request", return_value=Resp(429, {"805": "slow down"})):
            self.assertIsNone(caps._rest({}, "/x", {})[0])
        with patch.object(caps, "_request", return_value=Resp(400, {"errorCode": "DH-905", "errorMessage": "expiryCode is required"})):
            self.assertIsNone(caps._rest({}, "/x", {})[0])
        with patch.object(caps, "_request", return_value=Resp(200, {"status": "success", "data": {"data": {"oc": {}}}})):
            ok, _, body = caps._rest({}, "/x", {})
        self.assertTrue(ok); self.assertEqual(caps._data(body), {"oc": {}})

    def test_disconnect_packet(self):
        import struct
        self.assertEqual(caps._disconnect_reason(struct.pack("<BHBIH", 50, 10, 1, 1333, 806)), 806)
        self.assertIsNone(caps._disconnect_reason(struct.pack("<BHBIH", 2, 10, 1, 1333, 0)))
        self.assertIsNone(caps._disconnect_reason(b"\x32"))

    def test_market_hours(self):
        self.assertTrue(caps.market_open_now(datetime(2026, 10, 1, 10, 0, tzinfo=tm.IST)))    # Thu
        self.assertFalse(caps.market_open_now(datetime(2026, 10, 1, 2, 56, tzinfo=tm.IST)))
        self.assertFalse(caps.market_open_now(datetime(2026, 10, 4, 10, 0, tzinfo=tm.IST)))   # Sun


if __name__ == "__main__":
    unittest.main(verbosity=2)
