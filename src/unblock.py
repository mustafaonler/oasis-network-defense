#!/usr/bin/env python3
"""OASIS unblock: remove an IP from the firewall blocklist and log it.

If the IP was blocked for ARP spoofing, its MAC also leaves the ARP blocklist.
"""
import ipaddress
import json
import re
import sqlite3
import subprocess
import sys
import time

DB_FILE = "data/oasis.db"
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def unblock_mac(db, ip):
    """Drop the MAC of this IP's latest arp_spoof event from the ARP blocklist and the
    frame blocklist, if it is there."""
    row = db.execute("SELECT evidence FROM events WHERE source_ip=? AND attack_type='arp_spoof' "
                     "AND action='block' ORDER BY id DESC LIMIT 1", (ip,)).fetchone()
    mac = str(json.loads(row[0] or "{}").get("mac", "")).lower() if row else ""
    if MAC_RE.match(mac):
        for family, table in (("arp", "oasis_arp"), ("inet", "oasis")):
            r = subprocess.run(["nft", "delete", "element", family, table, "macblock",
                                f"{{ {mac} }}"], capture_output=True, text=True)
            if r.returncode == 0:
                print(f"{family} mac unblock: {mac}", flush=True)


def unblock(ip, db, reason="manual unblock"):
    """Remove a validated IP (and its ARP-spoofing MAC) from the blocklists; log it."""
    r = subprocess.run(
        ["nft", "delete", "element", "inet", "oasis", "blocklist", f"{{ {ip} }}"],
        capture_output=True, text=True)
    action = "unblock" if r.returncode == 0 else "unblock_failed"
    print(f"{action}: {ip}" + ("" if r.returncode == 0 else f" ({r.stderr.strip()})"), flush=True)
    now = time.time()
    unblock_mac(db, ip)
    db.execute(
        "INSERT INTO events (epoch, ts, source_ip, attack_type, risk, action, "
        "duration_s, mode, reason, evidence) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (now, time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)), ip,
         None, None, action, None, "enforce", reason, None))
    db.commit()
    return action


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: sudo .venv/bin/python src/unblock.py <ip>")
    ip = str(ipaddress.ip_address(sys.argv[1]))   # validates the input
    unblock(ip, sqlite3.connect(DB_FILE))


if __name__ == "__main__":
    main()
