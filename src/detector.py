#!/usr/bin/env python3
"""OASIS detector v1: rule-based Port Scan, SYN Flood and tripwire detection.

Rules are checked in order and the first match wins: a big scan that also touches a
tripwire port is reported as the more telling port_scan.
"""
import json
import os
import sys
import time

WINDOWS_FILE = "data/windows.jsonl"
ALERTS_FILE = "data/alerts.jsonl"
PORT_SCAN_MIN_PORTS = 20      # distinct SYN ports in one window
SYN_FLOOD_MIN_RATE = 50       # SYN per second from one source
TRIPWIRE_MIN_HITS = 1         # one probe of a port with no service is enough
# Sources that never raise alerts; OASIS_WHITELIST (comma-separated) overrides.
WHITELIST = {h.strip() for h in os.environ.get("OASIS_WHITELIST", "10.0.1.1").split(",")
             if h.strip()}


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
    # Only in windows from a sensor with tripwire ports (absent in the VM: no alert).
    if rec.get("tripwire_hits", 0) >= TRIPWIRE_MIN_HITS:
        return {
            "time": rec["window_end"],
            "source_ip": rec["source_ip"],
            "attack_type": "tripwire",
            "reason": f"{rec['tripwire_hits']} connection attempt(s) to tripwire ports "
                      f"(threshold {TRIPWIRE_MIN_HITS})",
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
