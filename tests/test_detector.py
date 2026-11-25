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


def target(per_source):
    ports = sum(n for n in per_source.values())          # disjoint port ranges in these tests
    return {"window_start": "t0", "window_end": "t1", "dst_ip": "10.0.2.10",
            "sources": len(per_source), "target_unique_ports": ports,
            "target_syn_count": ports,
            "per_source": {ip: {"ports": n, "syn": n} for ip, n in per_source.items()}}


def blamed(rec):
    return sorted(a["source_ip"] for a in detector.check_target(rec))


class Distributed(unittest.TestCase):
    def test_vm_rule_off(self):
        self.assertIsNone(detector.TARGETS_FILE)

    def test_three_sources_ten_ports_each(self):                         # D1
        rec = target({"10.0.1.65": 10, "10.0.1.66": 10, "10.0.1.67": 10})
        self.assertEqual(blamed(rec), ["10.0.1.65", "10.0.1.66", "10.0.1.67"])
        a = detector.check_target(rec)[0]
        self.assertEqual(a["attack_type"], "distributed_scan")
        self.assertEqual(a["evidence"]["target_unique_ports"], 30)
        self.assertEqual(a["evidence"]["distributed_sources"], 3)
        self.assertEqual(a["evidence"]["unique_ports"], 10)

    def test_normal_user_not_blamed(self):                               # D2
        rec = target({"10.0.1.65": 10, "10.0.1.66": 10, "10.0.1.70": 1})
        self.assertEqual(blamed(rec), ["10.0.1.65", "10.0.1.66"])

    def test_below_threshold(self):                                      # D3
        self.assertEqual(blamed(target({"10.0.1.65": 5, "10.0.1.66": 5})), [])

    def test_single_big_scanner_left_to_port_scan(self):                 # D4
        self.assertEqual(blamed(target({"10.0.1.65": 30, "10.0.1.66": 5})), [])

    def test_one_contributor_is_not_distributed(self):
        self.assertEqual(blamed(target({"10.0.1.65": 19, "10.0.1.70": 1})), [])

    def test_whitelisted_source_not_blamed(self):
        rec = target({"10.0.1.65": 10, "10.0.1.66": 10, "10.0.1.1": 10})
        self.assertEqual(blamed(rec), ["10.0.1.65", "10.0.1.66"])


if __name__ == "__main__":
    unittest.main()
