#!/usr/bin/env python3
"""OASIS detector v1: rule-based Port Scan, SYN Flood, tripwire and distributed scan detection.

Per-source rules are checked in order and the first match wins: a big scan that also
touches a tripwire port is reported as the more telling port_scan. The distributed rule
reads per-target windows (OASIS_TARGET_FILE) and only fires when no single source
already reached the port-scan threshold.
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
# Distributed scan: the same 20 ports of one target, split over several sources.
DIST_MIN_PORTS = PORT_SCAN_MIN_PORTS
DIST_MIN_SOURCE_PORTS = 3     # a source counts as a contributor from 3 ports (a user hits 1)
DIST_MIN_CONTRIBUTORS = 2
TARGETS_FILE = os.environ.get("OASIS_TARGET_FILE") or None   # unset (VM): rule off
SENSOR_WINDOW = 5             # seconds per window (sensor.WINDOW)
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


def check_target(rec):
    """Return one distributed_scan alert per contributing source (or an empty list)."""
    per = rec["per_source"]
    if rec["target_unique_ports"] < DIST_MIN_PORTS:
        return []
    if any(s["ports"] >= PORT_SCAN_MIN_PORTS for s in per.values()):
        return []                 # that source is already a port_scan on its own
    contrib = {ip: s for ip, s in per.items()
               if s["ports"] >= DIST_MIN_SOURCE_PORTS and ip not in WHITELIST}
    if len(contrib) < DIST_MIN_CONTRIBUTORS:
        return []
    alerts = []
    for ip, s in sorted(contrib.items()):
        alerts.append({
            "time": rec["window_end"],
            "source_ip": ip,
            "attack_type": "distributed_scan",
            "reason": f"{len(contrib)} sources probed {rec['target_unique_ports']} distinct ports "
                      f"of one target in one window (threshold {DIST_MIN_PORTS}); "
                      f"this source {s['ports']}",
            "evidence": {
                "window_start": rec["window_start"], "window_end": rec["window_end"],
                "dst_ip": rec["dst_ip"],                 # kept for the analyst, never sent to the LLM
                "syn_count": s["syn"], "unique_ports": s["ports"], "unique_dst_ips": 1,
                "syn_per_second": round(s["syn"] / SENSOR_WINDOW, 1),
                "target_unique_ports": rec["target_unique_ports"],
                "distributed_sources": len(contrib),
            },
        })
    return alerts


def emit(alert, out):
    line = json.dumps(alert)
    print("ALERT", line, flush=True)
    out.write(line + "\n")
    out.flush()


def check_window(rec):
    alert = check(rec)
    return [alert] if alert else []


def main():
    replay = "--replay" in sys.argv
    inputs = [(WINDOWS_FILE, check_window)]
    if TARGETS_FILE:
        inputs.append((TARGETS_FILE, check_target))
    with open(ALERTS_FILE, "a") as out:
        files = []
        for path, rule in inputs:
            f = open(path)
            if not replay:
                f.seek(0, 2)  # start from the end: only new windows
            files.append((f, rule))
        if not replay:
            print("Detector watching for new windows. Ctrl+C to stop.", flush=True)
            if TARGETS_FILE:
                print(f"Also watching per-target windows: {TARGETS_FILE}", flush=True)
        while True:
            idle = True
            for f, rule in files:
                line = f.readline()
                if line:
                    idle = False
                    for alert in rule(json.loads(line)):
                        emit(alert, out)
            if idle:
                if replay:
                    break
                time.sleep(0.5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped.")
