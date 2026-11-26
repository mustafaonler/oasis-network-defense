#!/usr/bin/env python3
"""OASIS responder v0: turns detector alerts into safe firewall actions.

Pipeline: alert -> whitelist -> risk level -> action ladder
          -> dry-run or nftables -> SQLite event log.
"""
import ipaddress
import json
import os
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time

import unblock as unblocker
from policy import LADDER, REPEAT_WINDOW, RISK, START_STEP

ALERTS_FILE = "data/alerts.jsonl"
# Unblock requests written by the dashboard; unset (VM): no requests are read.
UNBLOCK_REQUESTS = os.environ.get("OASIS_UNBLOCK_REQUESTS") or None
DB_FILE = "data/oasis.db"
# Gateway address to defend after ARP spoofing: while a MAC is blocked for it, the
# gateway announces its real MAC (gratuitous ARP) so poisoned hosts are corrected.
# Unset (VM): no announcements (and no NET_RAW needed).
_defend = os.environ.get("OASIS_ARP_DEFEND_IP")
DEFEND_IP = str(ipaddress.ip_address(_defend)) if _defend else None
DEFEND_EVERY = 0.3      # s between announcements (forged replies come about every second)
DEFEND_CHECK = 5        # s between checks that a MAC is still blocked

# Never block these: gateway, victim, management network.
# OASIS_WHITELIST (comma-separated addresses or networks) overrides the VM list.
WHITELIST = [ipaddress.ip_network(n.strip()) for n in os.environ.get(
    "OASIS_WHITELIST", "10.0.1.1/32,10.0.2.1/32,10.0.2.10/32,192.168.56.0/24").split(",")
    if n.strip()]

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


MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def ensure_arp_guard():
    """ARP table on the gateway: drop ARP from blocked MACs (created on first use only)."""
    nft("add", "table", "arp", "oasis_arp")
    nft("add", "set", "arp", "oasis_arp", "macblock", "{ type ether_addr; flags timeout; }")
    nft("add", "chain", "arp", "oasis_arp", "input",
        "{ type filter hook input priority 0; policy accept; }")
    chain = nft("list", "chain", "arp", "oasis_arp", "input")
    if chain.returncode == 0 and "@macblock" not in chain.stdout:
        nft("add", "rule", "arp", "oasis_arp", "input", "arp", "saddr", "ether", "@macblock", "drop")
    return chain.returncode == 0


def ensure_mac_drop():
    """inet oasis: drop every frame from a blocked MAC, also packets it relays for others
    (they carry the victim's IP, so the IP blocklist alone lets them through)."""
    nft("add", "set", "inet", "oasis", "macblock", "{ type ether_addr; flags timeout; }")
    chain = nft("list", "chain", "inet", "oasis", "forward")
    if chain.returncode == 0 and "@macblock" not in chain.stdout:
        nft("add", "rule", "inet", "oasis", "forward", "ether", "saddr", "@macblock", "drop")
    return chain.returncode == 0


def arp_guard(evidence, seconds):
    """After an arp_spoof block: ignore that MAC's ARP, drop its frames, forget what it
    poisoned.

    Both values come from a file, so they are validated before they reach a command.
    """
    mac = str((evidence or {}).get("mac", "")).lower()
    if not MAC_RE.match(mac) or not ensure_arp_guard():
        return "arp guard skipped"
    elem = f"{{ {mac} timeout {seconds}s }}" if seconds else f"{{ {mac} }}"
    ok = nft("add", "element", "arp", "oasis_arp", "macblock", elem).returncode == 0
    frames = ensure_mac_drop() and nft("add", "element", "inet", "oasis", "macblock",
                                       elem).returncode == 0
    flushed = []
    for claimed in (evidence or {}).get("claimed_ip_list", []):
        try:
            addr = str(ipaddress.ip_address(claimed))
        except ValueError:
            continue
        subprocess.run(["ip", "neigh", "flush", "to", addr], capture_output=True)
        flushed.append(addr)
    return (f"arp guard: mac {'blocked' if ok else 'NOT blocked'}, frames "
            f"{'dropped' if frames else 'NOT dropped'}, neighbours flushed {flushed}")


def garp_frame(mac, ip):
    """Gratuitous ARP announcement (RFC 5227): 'ip is at mac', to everyone on the link."""
    m, a = bytes.fromhex(mac.replace(":", "")), socket.inet_aton(ip)
    return (b"\xff" * 6 + m + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
            + m + a + b"\x00" * 6 + a)


def iface_of(ip):
    """(interface, MAC) holding this address, from `ip -o -4 addr` (iproute2)."""
    out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) > 3 and parts[2] == "inet" and parts[3].split("/")[0] == ip:
            name = parts[1].split("@")[0]
            with open(f"/sys/class/net/{name}/address") as f:
                return name, f.read().strip().lower()
    return None, None


def mac_blocked():
    """True while the ARP blocklist holds at least one MAC (timeouts remove them)."""
    r = nft("list", "set", "arp", "oasis_arp", "macblock")
    return r.returncode == 0 and "elements" in r.stdout


class ArpDefender(threading.Thread):
    """While a MAC is blocked for ARP spoofing, announce the gateway's real MAC.

    A spoofer keeps telling hosts "the gateway is at my MAC"; the gateway cannot stop
    frames between two other hosts, but its announcements overwrite those entries
    (Linux always accepts a gratuitous ARP, and then ignores ordinary forged replies for
    about a second). Stops on its own when no MAC is blocked any more.
    """

    def __init__(self, ip):
        super().__init__(daemon=True)
        self.iface, self.mac = iface_of(ip)
        if not self.iface:
            raise OSError(f"no interface holds {ip}")
        self.frame = garp_frame(self.mac, ip)
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.sock.bind((self.iface, 0))
        self.active = mac_blocked()          # also after a responder restart
        self.sent = 0

    def activate(self):
        self.active = True

    def run(self):
        last_check = time.monotonic()
        while True:
            if self.active:
                try:
                    self.sock.send(self.frame)
                    self.sent += 1
                except OSError as e:
                    print("arp defender send error:", e, flush=True)
            if time.monotonic() - last_check >= DEFEND_CHECK:
                last_check = time.monotonic()
                was, self.active = self.active, mac_blocked()
                if was and not self.active:
                    print(f"arp defender: no blocked MAC, stopped ({self.sent} announcements)",
                          flush=True)
                    self.sent = 0
            time.sleep(DEFEND_EVERY)


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


defender = None              # ArpDefender in enforce mode with OASIS_ARP_DEFEND_IP


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
    if action == "block" and enforce and atype == "arp_spoof":
        print("   " + arp_guard(alert.get("evidence"), secs), flush=True)
        if defender:
            defender.activate()
            print(f"   arp defender: announcing {DEFEND_IP} at {defender.mac} "
                  f"every {DEFEND_EVERY}s on {defender.iface}", flush=True)
    db.execute(
        "INSERT INTO events (epoch, ts, source_ip, attack_type, risk, action, "
        "duration_s, mode, reason, evidence) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (now, alert.get("time"), ip, atype, risk, action, secs, mode,
         alert.get("reason"), json.dumps(alert.get("evidence"))))
    db.commit()


class UnblockRequests:
    """Unblock requests from the dashboard (OASIS_UNBLOCK_REQUESTS), read-only on this side.

    The dashboard (user nobody) creates and appends the file; we only make the directory
    writable for it (sticky, not listable) and read new lines. Requests that were waiting
    when the responder started are ignored. Every request is checked again here: a real
    IP that the firewall really blocks; anything else is only logged.
    """

    def __init__(self, path):
        self.path, self.f = path, None
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        os.chmod(os.path.dirname(path) or ".", 0o1733)
        if os.path.exists(path):
            self.f = open(path)
            self.f.seek(0, 2)

    def poll(self, db):
        if self.f is None:
            if not os.path.exists(self.path):
                return
            self.f = open(self.path)
        for _ in range(20):                      # a few per round; the rest wait, none are lost
            line = self.f.readline()
            if not line:
                break
            try:
                ip = str(ipaddress.ip_address(json.loads(line)["ip"]))
            except (ValueError, KeyError, TypeError):
                print("unblock request ignored: not a valid IP", flush=True)
                continue
            if not nft_blocked(ip):
                print(f"unblock request ignored: {ip} is not blocked", flush=True)
                continue
            print(f"unblock request from the dashboard: {ip}", flush=True)
            unblocker.unblock(ip, db, reason="unblock from dashboard")
            blocked_until.pop(ip, None)


def main():
    global defender
    replay = "--replay" in sys.argv
    enforce = "--enforce" in sys.argv and not replay   # replay is always dry-run
    db = open_db()
    if enforce:
        ensure_firewall()
        if DEFEND_IP:
            defender = ArpDefender(DEFEND_IP)
            defender.start()
            print(f"ARP defender ready for {DEFEND_IP} on {defender.iface}"
                  + (" (active: a MAC is blocked)" if defender.active else ""), flush=True)
    requests = UnblockRequests(UNBLOCK_REQUESTS) if enforce and UNBLOCK_REQUESTS else None
    open(ALERTS_FILE, "a").close()
    with open(ALERTS_FILE) as f:
        if not replay:
            f.seek(0, 2)
        print(f"Responder started in {'ENFORCE' if enforce else 'DRY-RUN'} mode. "
              "Ctrl+C to stop.", flush=True)
        if requests:
            print(f"Accepting unblock requests from {UNBLOCK_REQUESTS}", flush=True)
        while True:
            line = f.readline()
            if not line:
                if replay:
                    break
                if requests:
                    requests.poll(db)
                time.sleep(0.5)
                continue
            process(json.loads(line), db, enforce)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped.")
