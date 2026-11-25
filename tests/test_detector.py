#!/usr/bin/env python3
"""Tests for the detector rules (no scapy needed: runs in the core image).

Run:  python3 -m unittest discover -s tests -p test_detector.py -v
The OASIS_* variables must be unset, so the VM whitelist is used.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
for k in [k for k in os.environ if k.startswith("OASIS_")]:
    del os.environ[k]
import detector  # noqa: E402


def window(**kw):
    rec = {"window_start": "t0", "window_end": "t1", "source_ip": "10.0.1.50",
           "packet_count": 3, "syn_count": 1, "unique_ports": 1, "unique_dst_ips": 1,
           "syn_per_second": 0.2}
    rec.update(kw)
    return rec


def kind(rec):
    alert = detector.check(rec)
    return alert["attack_type"] if alert else None


class Rules(unittest.TestCase):
    def test_normal_window_no_alert(self):
        self.assertIsNone(kind(window()))

    def test_vm_window_without_tripwire_field(self):
        self.assertIsNone(kind(window(unique_ports=15)))         # small scan, no field

    def test_tripwire_one_hit(self):
        self.assertEqual(kind(window(tripwire_hits=1)), "tripwire")

    def test_tripwire_zero_hits(self):
        self.assertIsNone(kind(window(tripwire_hits=0)))

    def test_port_scan_wins_over_tripwire(self):
        self.assertEqual(kind(window(unique_ports=30, tripwire_hits=2)), "port_scan")

    def test_syn_flood_wins_over_tripwire(self):
        self.assertEqual(kind(window(syn_per_second=900.0, tripwire_hits=1)), "syn_flood")

    def test_whitelisted_source_never_alerts(self):
        self.assertIsNone(kind(window(source_ip="10.0.1.1", tripwire_hits=5)))

    def test_alert_keeps_evidence_and_reason(self):
        alert = detector.check(window(tripwire_hits=1))
        self.assertEqual(alert["evidence"]["tripwire_hits"], 1)
        self.assertIn("tripwire", alert["reason"])


if __name__ == "__main__":
    unittest.main()
