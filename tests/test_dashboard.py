#!/usr/bin/env python3
"""Tests for src/dashboard.py: blocklist from the event log, read-only access, HTTP rules.

Run:  python3 -m unittest discover -s tests -v
"""
import http.client
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import dashboard  # noqa: E402

SCHEMA = [
    # Same tables as responder.py, explainer.py and specialist.py create.
    """CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT,
        epoch REAL, ts TEXT, source_ip TEXT, attack_type TEXT, risk TEXT,
        action TEXT, duration_s INTEGER, mode TEXT, reason TEXT, evidence TEXT)""",
    "CREATE TABLE explanations (event_id INTEGER PRIMARY KEY, ts TEXT, model TEXT, text TEXT)",
    """CREATE TABLE analyses (event_id INTEGER PRIMARY KEY, ts TEXT, agent TEXT, model TEXT,
        verdict TEXT, confidence TEXT, risk_opinion TEXT, reasons TEXT)""",
]
XSS = '<img src=x onerror="alert(1)"><script>alert(2)</script>'


class Fixture:
    def __init__(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "oasis.db")
        db = sqlite3.connect(self.path)
        for s in SCHEMA:
            db.execute(s)
        db.commit()
        self.db = db

    def event(self, epoch, ip, action, dur=None, atype="port_scan", risk="medium",
              mode="enforce", evidence=None):
        cur = self.db.execute(
            "INSERT INTO events (epoch, ts, source_ip, attack_type, risk, action, duration_s, "
            "mode, reason, evidence) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (epoch, "t", ip, atype, risk, action, dur, mode, "rule",
             json.dumps(evidence) if evidence is not None else None))
        self.db.commit()
        return cur.lastrowid

    def close(self):
        self.db.close()
        self.dir.cleanup()


class BlockedFromLog(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.now = 1_000_000.0

    def tearDown(self):
        self.f.close()

    def blocked(self):
        db = dashboard.open_db_ro(self.f.path)
        try:
            return {b["ip"]: b for b in dashboard.active_blocks(db, self.now)}
        finally:
            db.close()

    def test_active_block_with_remaining_time(self):
        self.f.event(self.now - 60, "10.10.1.64", "block", 300)
        b = self.blocked()["10.10.1.64"]
        self.assertEqual(b["expires"] - self.now, 240)

    def test_expired_block_is_gone(self):
        self.f.event(self.now - 301, "10.10.1.65", "block", 300)
        self.assertNotIn("10.10.1.65", self.blocked())

    def test_unblock_removes_block(self):
        self.f.event(self.now - 60, "10.10.1.66", "block", 1800)
        self.f.event(self.now - 30, "10.10.1.66", "unblock", atype=None, risk=None)
        self.assertNotIn("10.10.1.66", self.blocked())

    def test_block_after_unblock_counts_again(self):
        self.f.event(self.now - 90, "10.10.1.66", "block", 300)
        self.f.event(self.now - 60, "10.10.1.66", "unblock", atype=None, risk=None)
        self.f.event(self.now - 10, "10.10.1.66", "block", 1800)
        self.assertEqual(self.blocked()["10.10.1.66"]["duration_s"], 1800)

    def test_manual_block_never_expires(self):
        self.f.event(self.now - 10 * 86400, "10.10.1.67", "block", None, "syn_flood", "high")
        b = self.blocked()["10.10.1.67"]
        self.assertIsNone(b["expires"])

    def test_failed_and_dry_run_rows_do_not_block(self):
        self.f.event(self.now - 10, "10.10.1.68", "block_failed")
        self.f.event(self.now - 10, "10.10.1.69", "block", 300, mode="dry-run")
        self.assertEqual(self.blocked(), {})

    def test_unblock_failed_keeps_block(self):
        self.f.event(self.now - 10, "10.10.1.70", "block", 300)
        self.f.event(self.now - 5, "10.10.1.70", "unblock_failed", atype=None, risk=None)
        self.assertIn("10.10.1.70", self.blocked())

    def test_host_status(self):
        self.f.event(self.now - 10, "10.10.1.71", "block", 300)                 # blocked
        self.f.event(self.now - 60, "10.10.1.72", "skip_already_blocked")        # alarm
        self.f.event(self.now - 1200, "10.10.1.73", "block", 300)                # normal again
        db = dashboard.open_db_ro(self.f.path)
        try:
            st = dashboard.compute_state(db, self.now)
        finally:
            db.close()
        status = {a["ip"]: a["status"] for a in st["hosts"]["attackers"]}
        self.assertEqual(status, {"10.10.1.71": "blocked", "10.10.1.72": "alarm",
                                  "10.10.1.73": "normal"})
        self.assertEqual(st["hosts"]["victim"], "alarm")


class ReadOnly(unittest.TestCase):
    def test_connection_refuses_writes(self):
        f = Fixture()
        try:
            db = dashboard.open_db_ro(f.path)
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("INSERT INTO explanations VALUES (1,'t','m','x')")
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("CREATE TABLE x (a)")
            db.close()
        finally:
            f.close()

    def test_missing_db_is_not_created(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "oasis.db")
            st = dashboard.read_state(path)
            self.assertFalse(st["ok"])
            self.assertFalse(os.path.exists(path))

    def test_db_without_tables(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "oasis.db")
            sqlite3.connect(path).close()
            st = dashboard.read_state(path)
            self.assertFalse(st["ok"])
            self.assertEqual(st["events"], [])


def live_doc(updated, seconds):
    return {"updated": updated, "interval": 1, "seconds": seconds}


class LiveFile(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "live.json")
        self.now = 2_000_000.0

    def tearDown(self):
        self.dir.cleanup()

    def put(self, doc):
        with open(self.path, "w") as f:
            f.write(doc if isinstance(doc, str) else json.dumps(doc))

    def test_valid_data_passes(self):
        good = {"pkts": 5, "syn": 1, "ports": 1, "fwd": 5}
        self.put(live_doc(self.now - 0.5, [{"t": 1999999, "sources": {"10.10.1.64": good}}]))
        r = dashboard.read_live(self.path, self.now)
        self.assertTrue(r["ok"])
        self.assertFalse(r["stale"])
        self.assertEqual(r["seconds"][0]["sources"]["10.10.1.64"], good)

    def test_bad_values_dropped(self):
        ok = {"pkts": 1, "syn": 0, "ports": 0, "fwd": 1}
        self.put(live_doc(self.now, [{"t": 1, "sources": {
            "10.10.1.64": ok,
            XSS: ok,                                                   # not an IP
            "10.10.1.65": {"pkts": -1, "syn": 0, "ports": 0, "fwd": 0},
            "10.10.1.66": {"pkts": 1.5, "syn": 0, "ports": 0, "fwd": 0},
            "10.10.1.67": {"pkts": True, "syn": 0, "ports": 0, "fwd": 0},
            "10.10.1.68": {"pkts": "9", "syn": 0, "ports": 0, "fwd": 0},
            "10.10.1.69": {"pkts": 1},                                 # missing counters
        }}, {"t": "x", "sources": {}}, "junk"]))
        r = dashboard.read_live(self.path, self.now)
        self.assertEqual(len(r["seconds"]), 1)
        self.assertEqual(list(r["seconds"][0]["sources"]), ["10.10.1.64"])

    def test_stale_missing_bad_and_large(self):
        self.put(live_doc(self.now - 10, []))
        self.assertTrue(dashboard.read_live(self.path, self.now)["stale"])
        self.put("not json")
        self.assertFalse(dashboard.read_live(self.path, self.now)["ok"])
        self.put("[1, 2]")
        self.assertFalse(dashboard.read_live(self.path, self.now)["ok"])
        self.put(" " * (dashboard.LIVE_MAX_BYTES + 1))
        self.assertFalse(dashboard.read_live(self.path, self.now)["ok"])
        os.remove(self.path)
        r = dashboard.read_live(self.path, self.now)
        self.assertFalse(r["ok"])
        self.assertTrue(r["stale"])

    def test_limits(self):
        many = {f"10.10.1.{i}": {"pkts": 1, "syn": 0, "ports": 0, "fwd": 0} for i in range(100)}
        self.put(live_doc(self.now, [{"t": t, "sources": many} for t in range(30)]))
        r = dashboard.read_live(self.path, self.now)
        self.assertEqual([s["t"] for s in r["seconds"]], list(range(20, 30)))
        self.assertEqual(len(r["seconds"][0]["sources"]), dashboard.LIVE_MAX_SOURCES)


def sse_open(port, host):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest("GET", "/api/live", skip_host=True)
    c.putheader("Host", host)
    c.endheaders()
    return c, c.getresponse()


def sse_next(r):
    while True:
        line = r.fp.readline().decode()
        if line.startswith("data: "):
            return json.loads(line[6:])


class LiveStream(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.live = os.path.join(self.f.dir.name, "live.json")
        with open(self.live, "w") as fh:
            json.dump(live_doc(time.time(), [{"t": int(time.time()), "sources": {
                "10.10.1.64": {"pkts": 3, "syn": 0, "ports": 0, "fwd": 0}}}]), fh)
        self.srv = dashboard.make_server("127.0.0.1", 0, self.f.path, {"good.test:1"}, self.live)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.f.close()

    def test_stream_sends_live_data(self):
        c, r = sse_open(self.port, "good.test:1")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("text/event-stream"))
        self.assertIn("default-src 'none'", r.getheader("Content-Security-Policy"))
        msg = sse_next(r)
        self.assertEqual(msg["seconds"][0]["sources"]["10.10.1.64"]["pkts"], 3)
        # sensor rewrites the file -> a new message arrives
        with open(self.live, "w") as fh:
            json.dump(live_doc(time.time(), [{"t": int(time.time()), "sources": {}}]), fh)
        deadline = time.time() + 3
        while time.time() < deadline:
            if sse_next(r)["seconds"][0]["sources"] == {}:
                break
        else:
            self.fail("no update after the file changed")
        c.close()

    def test_stream_wrong_host(self):
        c, r = sse_open(self.port, "evil.example:1")
        self.assertEqual(r.status, 403)
        c.close()

    def test_stream_limit(self):
        open_streams = []
        for _ in range(dashboard.SSE_MAX):
            c, r = sse_open(self.port, "good.test:1")
            self.assertEqual(r.status, 200)
            sse_next(r)
            open_streams.append(c)
        c, r = sse_open(self.port, "good.test:1")
        self.assertEqual(r.status, 503)
        c.close()
        for c in open_streams:
            c.close()


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = Fixture()
        now = time.time()
        eid = cls.f.event(now - 20, "10.10.1.64", "block", 300, evidence={"unique_ports": 30})
        cls.f.db.execute("INSERT INTO explanations VALUES (?,?,?,?)", (eid, "t", "mock", XSS))
        cls.f.db.execute("INSERT INTO analyses VALUES (?,?,?,?,?,?,?,?)",
                         (eid, "t", "PortScanAgent", "rules", "agree", "high", "keep",
                          json.dumps([XSS, "ok"])))
        cls.f.db.commit()
        cls.srv = dashboard.make_server("127.0.0.1", 0, cls.f.path, {"good.test:1"})
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.f.close()

    def req(self, method, path, host="good.test:1", body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.putrequest(method, path, skip_host=True)
        c.putheader("Host", host)
        if body is not None:
            c.putheader("Content-Length", str(len(body)))
        c.endheaders()
        if body is not None:
            c.send(body)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def test_index_has_csp_and_no_external_sources(self):
        r, body = self.req("GET", "/")
        self.assertEqual(r.status, 200)
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        for name in ("/", "/app.js", "/app.css"):
            _, b = self.req("GET", name)
            self.assertNotIn(b"http://", b.replace(b"http://www.w3.org/2000/svg", b""))
            self.assertNotIn(b"https://", b)

    def test_js_never_uses_html_sinks(self):
        _, js = self.req("GET", "/app.js")
        for sink in (b"innerHTML", b"outerHTML", b"insertAdjacentHTML", b"document.write", b"eval("):
            self.assertFalse(sink in js, f"{sink!r} found in app.js")

    def test_state_returns_raw_text(self):
        r, body = self.req("GET", "/api/state")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("application/json"))
        st = json.loads(body)
        ev = st["events"][0]
        self.assertEqual(ev["explanation"]["text"], XSS)
        self.assertEqual(ev["analysis"]["reasons"], [XSS, "ok"])
        self.assertEqual(st["blocked"][0]["ip"], "10.10.1.64")

    def test_wrong_host_is_refused(self):
        r, _ = self.req("GET", "/api/state", host="evil.example:1")
        self.assertEqual(r.status, 403)

    def test_only_get(self):
        for m in ("POST", "PUT", "DELETE", "PATCH"):
            r, _ = self.req(m, "/api/state", body=b"{}")
            self.assertEqual(r.status, 405, m)

    def test_no_file_access_from_path(self):
        for p in ("/../src/dashboard.py", "/dashboard.py", "/data/oasis.db", "/%2e%2e/etc/passwd"):
            r, _ = self.req("GET", p)
            self.assertEqual(r.status, 404, p)


if __name__ == "__main__":
    unittest.main()
