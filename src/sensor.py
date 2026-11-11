#!/usr/bin/env python3
"""OASIS sensor: summarizes traffic in fixed time windows (JSON lines).

Defaults are the VM lab; the Docker lab overrides them with OASIS_* variables.
"""
import ipaddress
import json
import os
import socket
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, get_if_addr, get_if_list

WINDOW = 5  # seconds
# Validated with ipaddress so only real addresses reach the BPF filter.
SRC_NET = str(ipaddress.ip_network(os.environ.get("OASIS_SRC_NET", "10.0.1.0/24")))
IGNORE = [str(ipaddress.ip_address(h.strip())) for h in
          os.environ.get("OASIS_SENSOR_IGNORE", "10.0.1.1").split(",") if h.strip()]
BPF = f"ip and src net {SRC_NET}" + "".join(f" and not src host {h}" for h in IGNORE)
# Lab DNS server (Docker: the gateway). Lookups to it on port 53 are not counted as
# targets in unique_dst_ips; unset (VM) keeps the old behaviour.
_dns = os.environ.get("OASIS_SENSOR_DNS_SERVER")
DNS_SERVER = str(ipaddress.ip_address(_dns)) if _dns else None
OUTFILE = "data/windows.jsonl"

# Live view (dashboard only, never used for detection). Unset (VM): nothing changes.
# OASIS_LIVE_FILE: per-second, per-source counts of the last LIVE_KEEP seconds,
# rewritten atomically every second, so the file never grows.
# OASIS_LIVE_FWD_IP: address on the victim-side interface; packets from SRC_NET that
# leave through it were really forwarded by the gateway (blocked ones never are).
LIVE_FILE = os.environ.get("OASIS_LIVE_FILE") or None
_fwd = os.environ.get("OASIS_LIVE_FWD_IP")
LIVE_FWD_IP = str(ipaddress.ip_address(_fwd)) if _fwd else None
LIVE_KEEP = 10            # seconds kept in the live file
LIVE_MAX_SOURCES = 64     # busiest sources kept per second


def iface_for_ip(ip):
    for name in get_if_list():
        if get_if_addr(name) == ip:
            return name
    sys.exit(f"no interface holds {ip}")


def find_iface():
    """OASIS_IFACE, else the interface holding OASIS_GW_IP, else the VM NIC."""
    if os.environ.get("OASIS_IFACE"):
        return os.environ["OASIS_IFACE"]
    gw_ip = os.environ.get("OASIS_GW_IP")
    if gw_ip:
        return iface_for_ip(gw_ip)
    return "enp0s3"


def new_stats():
    return {"packet_count": 0, "syn_count": 0, "dst_ips": set(), "syn_ports": set()}


stats = defaultdict(new_stats)
lock = threading.Lock()


def is_dns_lookup(pkt):
    """True for a DNS query to the lab DNS server (port 53, UDP or TCP)."""
    if DNS_SERVER is None or pkt[IP].dst != DNS_SERVER:
        return False
    return any(L in pkt and pkt[L].dport == 53 for L in (UDP, TCP))


def new_live():
    return {"pkts": 0, "syn": 0, "ports": set(), "fwd": 0}


live = defaultdict(new_live)   # counts of the current second
live_lock = threading.Lock()


def handle(pkt):
    if IP not in pkt:
        return
    syn_port = None
    with lock:
        st = stats[pkt[IP].src]
        st["packet_count"] += 1
        if not is_dns_lookup(pkt):
            st["dst_ips"].add(pkt[IP].dst)
        if TCP in pkt:
            flags = int(pkt[TCP].flags)
            # SYN set, ACK not set = new connection attempt
            if flags & 0x02 and not flags & 0x10:
                st["syn_count"] += 1
                st["syn_ports"].add(pkt[TCP].dport)
                syn_port = pkt[TCP].dport
    if LIVE_FILE:
        with live_lock:
            lv = live[pkt[IP].src]
            lv["pkts"] += 1
            if syn_port is not None:
                lv["syn"] += 1
                lv["ports"].add(syn_port)


def live_bucket(t):
    """Close the current second: per-source counts, busiest sources first, capped."""
    with live_lock:
        snap = dict(live)
        live.clear()
    top = sorted(snap.items(), key=lambda kv: kv[1]["pkts"] + kv[1]["fwd"], reverse=True)
    return {"t": t,
            "sources": {ip: {"pkts": v["pkts"], "syn": v["syn"], "ports": len(v["ports"]),
                             "fwd": v["fwd"]} for ip, v in top[:LIVE_MAX_SOURCES]},
            "dropped_sources": max(0, len(top) - LIVE_MAX_SOURCES)}


def write_live(seconds, path):
    """Replace the live file in one step (readers never see half a file)."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"updated": time.time(), "interval": 1, "seconds": list(seconds)}, f)
    os.replace(tmp, path)


def live_writer(path):
    hist = deque(maxlen=LIVE_KEEP)
    nxt = int(time.time()) + 1
    while True:
        time.sleep(max(0.0, nxt - time.time()))
        hist.append(live_bucket(nxt))
        try:
            write_live(hist, path)
        except OSError as e:
            print("live file error:", e, flush=True)
        nxt += 1
        if time.time() > nxt + 1:          # fell behind (host paused): resync
            nxt = int(time.time()) + 1


def fwd_counter(iface, conn):
    """Child process: count forwarded packets per source on the victim-side interface.

    A separate process, so a flood here never competes with the scapy sniffer for the
    GIL. Raw socket with the sensor's BPF filter in the kernel, no scapy parsing: only
    the source address bytes are read. ETH_P_ALL is needed to see outgoing packets.
    Counts go to the parent ten times a second, not per packet.
    """
    from scapy.arch.linux import attach_filter
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    attach_filter(s, BPF, iface)
    s.bind((iface, 0))
    s.settimeout(0.1)
    counts = defaultdict(int)
    last = time.monotonic()
    outgoing = socket.PACKET_OUTGOING
    while True:
        try:
            frame, addr = s.recvfrom(64)
            if addr[2] == outgoing and len(frame) >= 34:
                counts[frame[26:30]] += 1      # Ethernet 14 + IPv4 source offset 12
        except socket.timeout:
            pass
        now = time.monotonic()
        if now - last >= 0.1:
            if counts:
                conn.send({socket.inet_ntoa(k): n for k, n in counts.items()})
                counts.clear()
            last = now


def fwd_merger(conn):
    """Parent thread: add the child's forwarded counts to the current second."""
    while True:
        try:
            batch = conn.recv()
        except EOFError:
            print("forwarded counter stopped", flush=True)
            return
        with live_lock:
            for ip, n in batch.items():
                live[ip]["fwd"] += n


def flusher(out):
    while True:
        start = time.time()
        time.sleep(WINDOW)
        end = time.time()
        with lock:
            snapshot = dict(stats)
            stats.clear()
        for ip, st in snapshot.items():
            rec = {
                "window_start": datetime.fromtimestamp(start).isoformat(timespec="seconds"),
                "window_end": datetime.fromtimestamp(end).isoformat(timespec="seconds"),
                "source_ip": ip,
                "packet_count": st["packet_count"],
                "syn_count": st["syn_count"],
                "unique_ports": len(st["syn_ports"]),
                "unique_dst_ips": len(st["dst_ips"]),
                "syn_per_second": round(st["syn_count"] / WINDOW, 1),
            }
            line = json.dumps(rec)
            print(line, flush=True)
            out.write(line + "\n")
            out.flush()


def main():
    iface = find_iface()
    print(f"Sensor started on {iface}, window={WINDOW}s. Ctrl+C to stop.", flush=True)
    print(f"BPF: {BPF}", flush=True)
    if LIVE_FILE:
        if LIVE_FWD_IP:
            # fork before any thread starts
            import multiprocessing
            fwd_iface = iface_for_ip(LIVE_FWD_IP)
            ctx = multiprocessing.get_context("fork")
            parent_end, child_end = ctx.Pipe(duplex=False)
            ctx.Process(target=fwd_counter, args=(fwd_iface, child_end), daemon=True).start()
            child_end.close()
            threading.Thread(target=fwd_merger, args=(parent_end,), daemon=True).start()
            print(f"Forwarded count on {fwd_iface} (child process)", flush=True)
        threading.Thread(target=live_writer, args=(LIVE_FILE,), daemon=True).start()
        print(f"Live summary: {LIVE_FILE} (last {LIVE_KEEP}s, every 1s)", flush=True)
    with open(OUTFILE, "a") as out:
        threading.Thread(target=flusher, args=(out,), daemon=True).start()
        try:
            sniff(iface=iface, filter=BPF, prn=handle, store=False)
        except KeyboardInterrupt:
            print("Stopped.")


if __name__ == "__main__":
    main()
