#!/usr/bin/env python3
"""OASIS detector v1: rule-based Port Scan and SYN Flood detection."""
import json
import sys
import time

WINDOWS_FILE = "data/windows.jsonl"
ALERTS_FILE = "data/alerts.jsonl"
PORT_SCAN_MIN_PORTS = 20      # distinct SYN ports in one window
SYN_FLOOD_MIN_RATE = 50       # SYN per second from one source
WHITELIST = {"10.0.1.1"}      # sources that never raise alerts


def check(rec):
    """Return an alert dict or None."""
    if rec["source_ip"] in WHITELIST:
        return None
    if rec["unique_ports"] >= PORT_SCAN_MIN_PORTS:
        return {
            "time": rec["window_end"],
            "source_ip": rec["source_ip"],
            "attack_type": "port_scan",
            "reason": f"{rec['unique_ports']} distinct ports probed in one window "
                      f"(threshold {PORT_SCAN_MIN_PORTS})",
            "evidence": rec,
        }
    if rec["syn_per_second"] >= SYN_FLOOD_MIN_RATE:
        return {
            "time": rec["window_end"],
            "source_ip": rec["source_ip"],
            "attack_type": "syn_flood",
            "reason": f"{rec['syn_per_second']} SYN/s toward {rec['unique_ports']} port(s) "
                      f"(threshold {SYN_FLOOD_MIN_RATE} SYN/s)",
            "evidence": rec,
        }
    return None


def emit(alert, out):
    line = json.dumps(alert)
    print("ALERT", line, flush=True)
    out.write(line + "\n")
    out.flush()


def main():
    replay = "--replay" in sys.argv
    with open(WINDOWS_FILE) as f, open(ALERTS_FILE, "a") as out:
        if not replay:
            f.seek(0, 2)  # start from the end: only new windows
            print("Detector watching for new windows. Ctrl+C to stop.", flush=True)
        while True:
            line = f.readline()
            if not line:
                if replay:
                    break
                time.sleep(0.5)
                continue
            alert = check(json.loads(line))
            if alert:
                emit(alert, out)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped.")
