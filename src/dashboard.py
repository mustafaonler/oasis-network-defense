#!/usr/bin/env python3
"""OASIS dashboard: a read-only web view of the event database.

Never writes: the database is opened with mode=ro and query_only, and in Docker
the data volume is mounted read-only. Never touches the firewall: the blocklist
shown here is computed from the event log, not read from nftables.
Only GET is served; every database string is sent as JSON and shown as plain text.
"""
import ipaddress
import json
import os
import sqlite3
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_FILE = os.environ.get("OASIS_DB", "data/oasis.db")
BIND = os.environ.get("OASIS_DASH_BIND", "127.0.0.1")   # Docker sets 0.0.0.0
PORT = int(os.environ.get("OASIS_DASH_PORT", "8080"))
# Host header allowlist (blocks DNS rebinding). Must match the address in the browser.
ALLOWED_HOSTS = {h.strip() for h in os.environ.get(
    "OASIS_DASH_HOSTS", f"127.0.0.1:{PORT},localhost:{PORT}").split(",") if h.strip()}
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_static")

ALARM_WINDOW = 300     # seconds: a recent attack event marks a host as "alarm"
ACTIVE_WINDOW = 3600   # seconds: attackers with an event this recent appear in the diagram
EVENT_LIMIT = 200      # newest events in the list
ATTACK_ACTIONS = ("block", "skip_already_blocked", "skip_whitelist", "log_only", "block_failed")

# Live traffic: per-second summary written by the sensor (OASIS_LIVE_FILE there).
LIVE_FILE = os.environ.get("OASIS_LIVE_FILE", "data/live.json")
LIVE_STALE = 3           # seconds: older data means the sensor is not writing
LIVE_MAX_BYTES = 512 * 1024
LIVE_MAX_SECONDS = 10
LIVE_MAX_SOURCES = 64
LIVE_POLL = 0.25         # how often a stream checks the file
SSE_MAX = 4              # concurrent live streams (each holds one server thread)
LIVE_COUNTERS = ("pkts", "syn", "ports", "fwd")

STATIC = {             # exact paths only: no file system lookups from the URL
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def open_db_ro(path=DB_FILE):
    """Read-only connection. mode=ro never creates the file; query_only refuses writes."""
    uri = "file:" + urllib.parse.quote(path) + "?mode=ro"
    db = sqlite3.connect(uri, uri=True, timeout=5)
    db.execute("PRAGMA query_only=ON")
    return db


def table_exists(db, name):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                      (name,)).fetchone() is not None


def parse_json(text):
    if text is None:
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return {"raw": str(text)}


def active_blocks(db, now):
    """Blocks still in force, from the event log alone (no firewall access).

    Per IP, the newest enforce-mode 'block' counts unless a later 'unblock' exists
    or its duration has passed. duration_s NULL means until manual unblock.
    block_failed, unblock_failed and dry-run rows never change the state.
    """
    last = {}
    for _id, epoch, ip, action, dur, atype, risk in db.execute(
            "SELECT id, epoch, source_ip, action, duration_s, attack_type, risk FROM events "
            "WHERE mode='enforce' AND action IN ('block','unblock') ORDER BY id"):
        last[ip] = (_id, epoch, dur, atype, risk) if action == "block" else None
    out = []
    for ip, row in last.items():
        if row is None:
            continue
        _id, epoch, dur, atype, risk = row
        expires = None if dur is None else epoch + dur
        if expires is not None and expires <= now:
            continue
        out.append({"ip": ip, "event_id": _id, "since": epoch, "duration_s": dur,
                    "expires": expires, "attack_type": atype, "risk": risk})
    out.sort(key=lambda b: b["since"], reverse=True)
    return out


def host_status(db, now, blocked):
    """Diagram status per host: blocked > alarm (attack event in ALARM_WINDOW) > normal."""
    blocked_ips = {b["ip"] for b in blocked}
    marks = ",".join("?" * len(ATTACK_ACTIONS))
    rows = db.execute(
        f"SELECT source_ip, MAX(epoch), attack_type FROM events WHERE action IN ({marks}) "
        "AND epoch>? GROUP BY source_ip", (*ATTACK_ACTIONS, now - ACTIVE_WINDOW)).fetchall()
    seen = {ip: (epoch, atype) for ip, epoch, atype in rows}
    for ip in blocked_ips - seen.keys():          # e.g. a manual block older than an hour
        seen[ip] = (None, None)
    attackers = []
    for ip, (epoch, atype) in seen.items():
        if ip in blocked_ips:
            status = "blocked"
        elif epoch is not None and epoch > now - ALARM_WINDOW:
            status = "alarm"
        else:
            status = "normal"
        attackers.append({"ip": ip, "status": status, "last_epoch": epoch, "last_type": atype})
    order = {"blocked": 0, "alarm": 1, "normal": 2}
    attackers.sort(key=lambda a: (order[a["status"]], -(a["last_epoch"] or 0)))
    recent = any(a["last_epoch"] and a["last_epoch"] > now - ALARM_WINDOW for a in attackers)
    lab = "alarm" if recent else "normal"
    return {"attackers": attackers, "gateway": lab, "victim": lab}


def load_events(db):
    rows = db.execute(
        "SELECT id, epoch, ts, source_ip, attack_type, risk, action, duration_s, mode, "
        "reason, evidence FROM events ORDER BY id DESC LIMIT ?", (EVENT_LIMIT,)).fetchall()
    if not rows:
        return []
    low = rows[-1][0]
    expl, anal = {}, {}
    if table_exists(db, "explanations"):
        for eid, ts, model, text in db.execute(
                "SELECT event_id, ts, model, text FROM explanations WHERE event_id>=?", (low,)):
            expl[eid] = {"ts": ts, "model": model, "text": text}
    if table_exists(db, "analyses"):
        for eid, ts, agent, model, verdict, conf, risk_op, reasons in db.execute(
                "SELECT event_id, ts, agent, model, verdict, confidence, risk_opinion, reasons "
                "FROM analyses WHERE event_id>=?", (low,)):
            parsed = parse_json(reasons)
            items = parsed if isinstance(parsed, list) else ([] if reasons is None else [reasons])
            anal[eid] = {"ts": ts, "agent": agent, "model": model, "verdict": verdict,
                         "confidence": conf, "risk_opinion": risk_op,
                         "reasons": [str(x) for x in items]}
    events = []
    for _id, epoch, ts, ip, atype, risk, action, dur, mode, reason, ev in rows:
        events.append({"id": _id, "epoch": epoch, "ts": ts, "source_ip": ip,
                       "attack_type": atype, "risk": risk, "action": action,
                       "duration_s": dur, "mode": mode, "reason": reason,
                       "evidence": parse_json(ev),
                       "explanation": expl.get(_id), "analysis": anal.get(_id)})
    return events


def compute_state(db, now):
    if not table_exists(db, "events"):
        return empty_state(now, "Olay tablosu henüz yok (responder başlamadı).")
    blocked = active_blocks(db, now)
    events = load_events(db)
    blocks_hour = db.execute("SELECT COUNT(*) FROM events WHERE action='block' AND epoch>?",
                             (now - 3600,)).fetchone()[0]
    total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return {
        "ok": True, "error": None, "now": now,
        "summary": {"total_events": total, "blocks_last_hour": blocks_hour,
                    "active_blocks": len(blocked)},
        "hosts": host_status(db, now, blocked),
        "blocked": blocked,
        "events": events,
        "limits": {"alarm_window_s": ALARM_WINDOW, "active_window_s": ACTIVE_WINDOW,
                   "event_limit": EVENT_LIMIT},
    }


def empty_state(now, error):
    return {"ok": False, "error": error, "now": now,
            "summary": {"total_events": 0, "blocks_last_hour": 0, "active_blocks": 0},
            "hosts": {"attackers": [], "gateway": "normal", "victim": "normal"},
            "blocked": [], "events": [],
            "limits": {"alarm_window_s": ALARM_WINDOW, "active_window_s": ACTIVE_WINDOW,
                       "event_limit": EVENT_LIMIT}}


def read_state(path=DB_FILE):
    now = time.time()
    if not os.path.exists(path):
        return empty_state(now, "Veritabanı henüz yok (responder başlamadı).")
    try:
        db = open_db_ro(path)
        try:
            return compute_state(db, now)
        finally:
            db.close()
    except sqlite3.Error as e:
        return empty_state(now, f"Veritabanı okunamadı: {e}")


def count(v):
    """A non-negative integer from the live file, or None."""
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def read_live(path=LIVE_FILE, now=None):
    """Sanitized live summary: only valid IPs and non-negative integer counters pass."""
    now = time.time() if now is None else now
    try:
        if os.path.getsize(path) > LIVE_MAX_BYTES:
            return {"ok": False, "stale": True, "error": "live file too large", "seconds": []}
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return {"ok": False, "stale": True, "error": "no live data", "seconds": []}
    if not isinstance(raw, dict):
        return {"ok": False, "stale": True, "error": "bad live data", "seconds": []}
    updated = raw.get("updated")
    if not isinstance(updated, (int, float)) or isinstance(updated, bool):
        return {"ok": False, "stale": True, "error": "bad live data", "seconds": []}
    seconds = []
    for sec in (raw.get("seconds") or [])[-LIVE_MAX_SECONDS:]:
        if not isinstance(sec, dict) or not isinstance(sec.get("t"), int):
            continue
        sources = {}
        items = sec.get("sources") if isinstance(sec.get("sources"), dict) else {}
        for ip, c in list(items.items())[:LIVE_MAX_SOURCES]:
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                continue
            if not isinstance(c, dict):
                continue
            vals = {k: count(c.get(k)) for k in LIVE_COUNTERS}
            if None in vals.values():
                continue
            sources[ip] = vals
        seconds.append({"t": sec["t"], "sources": sources})
    return {"ok": True, "stale": now - updated > LIVE_STALE, "error": None,
            "now": now, "updated": updated, "seconds": seconds}


def load_static():
    files = {}
    for route, (name, ctype) in STATIC.items():
        with open(os.path.join(STATIC_DIR, name), "rb") as f:
            files[route] = (f.read(), ctype)
    return files


class Handler(BaseHTTPRequestHandler):
    server_version = "oasis-dashboard"
    sys_version = ""
    static = {}
    db_path = DB_FILE
    live_path = LIVE_FILE
    allowed_hosts = ALLOWED_HOSTS
    sse_slots = threading.BoundedSemaphore(SSE_MAX)

    def send(self, code, body=b"", ctype="text/plain; charset=utf-8", extra=None):
        self.send_response(code)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def stream_live(self):
        """Server-Sent Events: push the live summary when the sensor rewrites it.

        Also sends at least once a second, so the browser notices a stopped sensor.
        """
        self.close_connection = True
        self.send_response(200)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.end_headers()
        last_mtime, last_sent = None, 0.0
        try:
            self.wfile.write(b"retry: 2000\n\n")
            while True:
                try:
                    mtime = os.stat(self.live_path).st_mtime_ns
                except OSError:
                    mtime = None
                now = time.time()
                if mtime != last_mtime or now - last_sent >= 1:
                    data = json.dumps(read_live(self.live_path, now), ensure_ascii=False)
                    self.wfile.write(f"data: {data}\n\n".encode())
                    self.wfile.flush()
                    last_mtime, last_sent = mtime, now
                time.sleep(LIVE_POLL)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return   # browser closed the stream

    def do_GET(self):
        if self.headers.get("Host", "") not in self.allowed_hosts:
            return self.send(403, b"forbidden host\n")
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/live":
            if not self.sse_slots.acquire(blocking=False):
                return self.send(503, b"too many live streams\n", extra={"Retry-After": "5"})
            try:
                return self.stream_live()
            finally:
                self.sse_slots.release()
        if path == "/api/state":
            body = json.dumps(read_state(self.db_path), ensure_ascii=False).encode()
            return self.send(200, body, "application/json; charset=utf-8")
        if path == "/favicon.ico":
            return self.send(204)
        if path in self.static:
            body, ctype = self.static[path]
            return self.send(200, body, ctype)
        return self.send(404, b"not found\n")

    def refuse(self):
        self.send(405, b"method not allowed\n", extra={"Allow": "GET"})

    do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_TRACE = refuse

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")


def make_server(bind=BIND, port=PORT, db_path=DB_FILE, allowed_hosts=None, live_path=LIVE_FILE):
    handler = type("BoundHandler", (Handler,), {
        "static": load_static(), "db_path": db_path, "live_path": live_path,
        "sse_slots": threading.BoundedSemaphore(SSE_MAX),
        "allowed_hosts": set(allowed_hosts) if allowed_hosts else ALLOWED_HOSTS})
    srv = ThreadingHTTPServer((bind, port), handler)
    srv.daemon_threads = True   # open live streams never block shutdown
    return srv


def main():
    srv = make_server()
    print(f"Dashboard on {BIND}:{PORT} (read-only, db={DB_FILE}, live={LIVE_FILE}). "
          f"Allowed hosts: {', '.join(sorted(ALLOWED_HOSTS))}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped.")
