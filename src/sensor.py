#!/usr/bin/env python3
"""OASIS sensor: summarizes traffic in fixed time windows (JSON lines).

Defaults are the VM lab; the Docker lab overrides them with OASIS_* variables.
"""
import ipaddress
import json
import os
import sys
import threading
import time
from collections import defaultdict
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


def find_iface():
    """OASIS_IFACE, else the interface holding OASIS_GW_IP, else the VM NIC."""
    if os.environ.get("OASIS_IFACE"):
        return os.environ["OASIS_IFACE"]
    gw_ip = os.environ.get("OASIS_GW_IP")
    if gw_ip:
        for name in get_if_list():
            if get_if_addr(name) == gw_ip:
                return name
        sys.exit(f"no interface holds {gw_ip}")
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


def handle(pkt):
    if IP not in pkt:
        return
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
    with open(OUTFILE, "a") as out:
        threading.Thread(target=flusher, args=(out,), daemon=True).start()
        try:
            sniff(iface=iface, filter=BPF, prn=handle, store=False)
        except KeyboardInterrupt:
            print("Stopped.")


if __name__ == "__main__":
    main()
