#!/usr/bin/env python3
"""OASIS sensor: summarizes traffic in fixed time windows (JSON lines)."""
import json
import threading
import time
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP

IFACE = "enp0s3"
WINDOW = 5  # seconds
BPF = "ip and src net 10.0.1.0/24 and not src host 10.0.1.1"
OUTFILE = "data/windows.jsonl"


def new_stats():
    return {"packet_count": 0, "syn_count": 0, "dst_ips": set(), "syn_ports": set()}


stats = defaultdict(new_stats)
lock = threading.Lock()


def handle(pkt):
    if IP not in pkt:
        return
    with lock:
        st = stats[pkt[IP].src]
        st["packet_count"] += 1
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
    print(f"Sensor started on {IFACE}, window={WINDOW}s. Ctrl+C to stop.", flush=True)
    with open(OUTFILE, "a") as out:
        threading.Thread(target=flusher, args=(out,), daemon=True).start()
        try:
            sniff(iface=IFACE, filter=BPF, prn=handle, store=False)
        except KeyboardInterrupt:
            print("Stopped.")


if __name__ == "__main__":
    main()
