#!/usr/bin/env python3
"""OASIS responder v0: turns detector alerts into safe firewall actions.

Pipeline: alert -> whitelist -> risk level -> action ladder
          -> dry-run or nftables -> SQLite event log.
"""
import ipaddress
import json
import sqlite3
import subprocess
import sys
import time

ALERTS_FILE = "data/alerts.jsonl"
DB_FILE = "data/oasis.db"

# Never block these: gateway, victim, management network.
WHITELIST = [ipaddress.ip_network(n) for n in
             ("10.0.1.1/32", "10.0.2.1/32", "10.0.2.10/32", "192.168.56.0/24")]

RISK = {"port_scan": "medium", "syn_flood": "high"}
START_STEP = {"medium": 0, "high": 1}
LADDER = [300, 1800, None]   # seconds; None = until removed manually
REPEAT_WINDOW = 3600         # seconds: a repeat offender escalates

blocked_until = {}           # ip -> unix time (inf = manual)


def open_db():
    db = sqlite3.connect(DB_FILE)
    db.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        epoch REAL, ts TEXT, source_ip TEXT, attack_type TEXT, risk TEXT,
        action TEXT, duration_s INTEGER, mode TEXT, reason TEXT, evidence TEXT)""")
    db.commit()
    return db


def nft(*args):
    return subprocess.run(["nft", *args], capture_output=True, text=True)


def ensure_firewall():
    nft("add", "table", "inet", "oasis")
    nft("add", "set", "inet", "oasis", "blocklist",
        "{ type ipv4_addr; flags timeout; }")
    nft("add", "chain", "inet", "oasis", "forward",
        "{ type filter hook forward priority 0; policy accept; }")
    chain = nft("list", "chain", "inet", "oasis", "forward")
    if chain.returncode != 0:
        sys.exit("nftables setup failed: " + chain.stderr)
    if "@blocklist" not in chain.stdout:
        nft("add", "rule", "inet", "oasis", "forward",
            "ip", "saddr", "@blocklist", "drop")


def apply_block(ip, seconds):
    elem = f"{{ {ip} timeout {seconds}s }}" if seconds else f"{{ {ip} }}"
    r = nft("add", "element", "inet", "oasis", "blocklist", elem)
    return r.returncode == 0, r.stderr.strip()


def nft_blocked(ip):
    """True if the IP is really in the firewall blocklist (source of truth)."""
    return nft("get", "element", "inet", "oasis", "blocklist", f"{{ {ip} }}").returncode == 0


def whitelisted(ip):
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in WHITELIST)


def label(secs):
    if secs is None:
        return "manual"
    return f"{secs // 60}m"


def process(alert, db, enforce):
    now = time.time()
    try:
        # Validate: the IP must be a real address, never free text.
        ip = str(ipaddress.ip_address(alert["source_ip"]))
    except ValueError:
        print("SKIP: invalid source_ip in alert", flush=True)
        return
    atype = alert["attack_type"]
    risk = RISK.get(atype, "low")
    mode = "enforce" if enforce else "dry-run"
    secs = None

    if whitelisted(ip):
        action = "skip_whitelist"
    elif (nft_blocked(ip) if enforce else blocked_until.get(ip, 0) > now):
        action = "skip_already_blocked"
    elif risk == "low":
        action = "log_only"
    else:
        prior = db.execute(
            "SELECT COUNT(*) FROM events WHERE source_ip=? AND action='block' "
            "AND mode=? AND epoch>?", (ip, mode, now - REPEAT_WINDOW)).fetchone()[0]
        step = min(START_STEP[risk] + prior, len(LADDER) - 1)
        secs = LADDER[step]
        action = "block"
        if enforce:
            ok, err = apply_block(ip, secs)
            if not ok:
                action = "block_failed"
                print("nft error:", err, flush=True)
        if action == "block":
            blocked_until[ip] = now + secs if secs else float("inf")

    extra = f" {label(secs)}" if action == "block" else ""
    print(f"[{mode.upper()}] {ip} {atype} risk={risk} -> {action}{extra}", flush=True)
    db.execute(
        "INSERT INTO events (epoch, ts, source_ip, attack_type, risk, action, "
        "duration_s, mode, reason, evidence) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (now, alert.get("time"), ip, atype, risk, action, secs, mode,
         alert.get("reason"), json.dumps(alert.get("evidence"))))
    db.commit()


def main():
    replay = "--replay" in sys.argv
    enforce = "--enforce" in sys.argv and not replay   # replay is always dry-run
    db = open_db()
    if enforce:
        ensure_firewall()
    open(ALERTS_FILE, "a").close()
    with open(ALERTS_FILE) as f:
        if not replay:
            f.seek(0, 2)
        print(f"Responder started in {'ENFORCE' if enforce else 'DRY-RUN'} mode. "
              "Ctrl+C to stop.", flush=True)
        while True:
            line = f.readline()
            if not line:
                if replay:
                    break
                time.sleep(0.5)
                continue
            process(json.loads(line), db, enforce)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped.")
