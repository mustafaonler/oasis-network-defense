#!/usr/bin/env python3
"""Tests for the sensor's live summary (needs scapy: run in the core image).

Run:  python3 -m unittest discover -s tests -p test_sensor.py -v
The OASIS_* variables must be unset, so the VM defaults are checked.
"""
import json
import os
import sys
import tempfile
import unittest
from collections import deque

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
for k in [k for k in os.environ if k.startswith("OASIS_")]:
    del os.environ[k]
import sensor  # noqa: E402
from scapy.all import IP, TCP, UDP, ICMP  # noqa: E402


def packets():
    src = "10.0.1.5"
    out = [IP(src=src, dst="10.0.2.10") / TCP(dport=p, flags="S") for p in range(1, 31)]
    out += [IP(src=src, dst="10.0.2.10") / TCP(dport=80, flags="SA")] * 3     # not a SYN
    out += [IP(src=src, dst="10.0.2.10") / TCP(dport=80, flags="A")] * 4
    out += [IP(src=src, dst="10.0.2.10") / ICMP()] * 2
    out += [IP(src=src, dst="10.0.1.1") / UDP(dport=53)]
    out += [IP(src="10.0.1.6", dst="10.0.2.10") / TCP(dport=22, flags="S")] * 5
    return out


def window_stats():
    with sensor.lock:
        return {ip: {"packet_count": s["packet_count"], "syn_count": s["syn_count"],
                     "dst_ips": sorted(s["dst_ips"]), "syn_ports": sorted(s["syn_ports"])}
                for ip, s in sensor.stats.items()}


class VmUnchanged(unittest.TestCase):
    def setUp(self):
        sensor.stats.clear()
        sensor.live.clear()
        self.saved = sensor.LIVE_FILE

    def tearDown(self):
        sensor.LIVE_FILE = self.saved
        sensor.stats.clear()
        sensor.live.clear()

    def test_vm_defaults(self):
        self.assertIsNone(sensor.LIVE_FILE)
        self.assertIsNone(sensor.LIVE_FWD_IP)
        self.assertEqual(sensor.BPF, "ip and src net 10.0.1.0/24 and not src host 10.0.1.1")
        self.assertEqual(sensor.find_iface(), "enp0s3")

    def test_windows_identical_with_and_without_live(self):
        sensor.LIVE_FILE = None
        for p in packets():
            sensor.handle(p)
        off = window_stats()
        self.assertEqual(len(sensor.live), 0)       # VM: no live counting at all
        sensor.stats.clear()
        sensor.LIVE_FILE = "unused.json"
        for p in packets():
            sensor.handle(p)
        self.assertEqual(window_stats(), off)
        self.assertEqual(off["10.0.1.5"]["packet_count"], 40)
        self.assertEqual(off["10.0.1.5"]["syn_count"], 30)


class LiveCounts(unittest.TestCase):
    def setUp(self):
        sensor.live.clear()
        self.saved = sensor.LIVE_FILE
        sensor.LIVE_FILE = "unused.json"

    def tearDown(self):
        sensor.LIVE_FILE = self.saved
        sensor.live.clear()
        sensor.stats.clear()

    def test_per_second_counts(self):
        for p in packets():
            sensor.handle(p)
        b = sensor.live_bucket(1000)
        self.assertEqual(b["t"], 1000)
        self.assertEqual(b["sources"]["10.0.1.5"], {"pkts": 40, "syn": 30, "ports": 30, "fwd": 0})
        self.assertEqual(b["sources"]["10.0.1.6"], {"pkts": 5, "syn": 5, "ports": 1, "fwd": 0})
        self.assertEqual(list(b["sources"])[0], "10.0.1.5")     # busiest first
        self.assertEqual(sensor.live_bucket(1001)["sources"], {})  # counters were reset

    def test_sources_capped(self):
        for i in range(100):
            sensor.live[f"10.0.1.{i}"]["pkts"] = i + 1
        b = sensor.live_bucket(1)
        self.assertEqual(len(b["sources"]), sensor.LIVE_MAX_SOURCES)
        self.assertEqual(b["dropped_sources"], 100 - sensor.LIVE_MAX_SOURCES)
        self.assertIn("10.0.1.99", b["sources"])
        self.assertNotIn("10.0.1.0", b["sources"])

    def test_file_keeps_last_seconds_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "live.json")
            hist = deque(maxlen=sensor.LIVE_KEEP)
            sizes = []
            for t in range(50):
                for i in range(sensor.LIVE_MAX_SOURCES):
                    sensor.live[f"10.10.1.{i}"]["pkts"] = 60000
                    sensor.live[f"10.10.1.{i}"]["ports"].update(range(100))
                hist.append(sensor.live_bucket(t))
                sensor.write_live(hist, path)
                sizes.append(os.path.getsize(path))
            with open(path) as f:
                data = json.load(f)
            self.assertEqual([s["t"] for s in data["seconds"]], list(range(40, 50)))
            self.assertEqual(os.listdir(d), ["live.json"])          # no temp file left
            self.assertLess(max(sizes), 100 * 1024)                  # bounded, worst case
            self.assertLess(abs(sizes[-1] - sizes[20]), 16)          # stops growing


if __name__ == "__main__":
    unittest.main()
