#!/usr/bin/env python3
"""OASIS unblock: remove an IP from the firewall blocklist and log it."""
import ipaddress
import sqlite3
import subprocess
import sys
import time

DB_FILE = "data/oasis.db"


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: sudo .venv/bin/python src/unblock.py <ip>")
    ip = str(ipaddress.ip_address(sys.argv[1]))   # validates the input
    r = subprocess.run(
        ["nft", "delete", "element", "inet", "oasis", "blocklist", f"{{ {ip} }}"],
        capture_output=True, text=True)
    action = "unblock" if r.returncode == 0 else "unblock_failed"
    print(f"{action}: {ip}" + ("" if r.returncode == 0 else f" ({r.stderr.strip()})"))
    now = time.time()
    db = sqlite3.connect(DB_FILE)
    db.execute(
        "INSERT INTO events (epoch, ts, source_ip, attack_type, risk, action, "
        "duration_s, mode, reason, evidence) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (now, time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)), ip,
         None, None, action, None, "enforce", "manual unblock", None))
    db.commit()


if __name__ == "__main__":
    main()
