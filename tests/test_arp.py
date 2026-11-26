#!/usr/bin/env python3
"""Tests for the ARP guard (MITM): sensor checks, detector rule, responder action.

No network and no real nft/ip commands: in-memory scapy packets and fake command calls.
Run in the core image:  python3 -m unittest discover -s tests -p test_arp.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
for k in [k for k in os.environ if k.startswith("OASIS_")]:
    del os.environ[k]
import detector    # noqa: E402
import responder   # noqa: E402
import sensor      # noqa: E402
from scapy.all import ARP, Ether, IP, TCP  # noqa: E402

GW_IP, GW_MAC = "10.0.1.1", "02:00:00:00:00:01"
USER_IP, USER_MAC = "10.0.1.20", "02:00:00:00:00:20"
ATT_IP, ATT_MAC = "10.0.1.66", "02:00:00:00:00:66"


def arp(mac, claim, op=2, pdst=GW_IP):
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=op, hwsrc=mac, psrc=claim, pdst=pdst)


def ip_pkt(mac, src):
    return Ether(src=mac) / IP(src=src, dst="10.0.2.10") / TCP(dport=80, flags="S")


def reset():
    for d in (sensor.ip_owner, sensor.mac_first_ip, sensor.arp_stats, sensor.stats):
        d.clear()


class SensorGuard(unittest.TestCase):
    def setUp(self):
        reset()
        self.saved = (sensor.ARP_FILE, dict(sensor.GUARD))
        sensor.ARP_FILE = "unused-in-this-test"
        sensor.GUARD.update(own_mac=GW_MAC, protected={GW_IP})

    def tearDown(self):
        sensor.ARP_FILE, guard = self.saved
        sensor.GUARD.clear()
        sensor.GUARD.update(guard)
        reset()

    def findings(self, mac):
        st = sensor.arp_stats.get(mac)
        return (st["gw_impersonation"], st["binding_conflicts"]) if st else (0, 0)

    def test_vm_learns_nothing(self):
        sensor.ARP_FILE = None
        sensor.handle(ip_pkt(USER_MAC, USER_IP))
        self.assertEqual(sensor.ip_owner, {})

    def test_gateway_impersonation(self):
        sensor.handle_arp(arp(ATT_MAC, GW_IP), now=100)
        self.assertEqual(self.findings(ATT_MAC), (1, 0))

    def test_own_arp_and_probes_ignored(self):
        sensor.handle_arp(arp(GW_MAC, GW_IP), now=100)            # the gateway itself
        sensor.handle_arp(arp(ATT_MAC, "0.0.0.0", op=1), now=100)  # ARP probe
        self.assertEqual(len(sensor.arp_stats), 0)

    def test_normal_reply_is_learned_not_flagged(self):
        sensor.handle_arp(arp(USER_MAC, USER_IP), now=100)
        self.assertEqual(len(sensor.arp_stats), 0)
        self.assertEqual(sensor.ip_owner[USER_IP][0], USER_MAC)

    def test_conflict_only_while_owner_is_recent(self):
        sensor.learn(USER_MAC, USER_IP, 100)
        sensor.handle_arp(arp(ATT_MAC, USER_IP), now=110)          # 10 s later: conflict
        self.assertEqual(self.findings(ATT_MAC), (0, 1))
        sensor.arp_stats.clear()
        sensor.handle_arp(arp(ATT_MAC, USER_IP), now=100 + sensor.ARP_CONFLICT_AGE + 5)
        self.assertEqual(self.findings(ATT_MAC), (0, 0))         # owner long gone: accepted

    def test_relayed_packets_do_not_reassign_attacker_ip(self):
        sensor.handle(ip_pkt(USER_MAC, USER_IP))
        sensor.handle(ip_pkt(ATT_MAC, ATT_IP))                     # attacker's own traffic
        sensor.handle(ip_pkt(ATT_MAC, USER_IP))                    # user's packet relayed by it
        sensor.handle_arp(arp(ATT_MAC, USER_IP))
        rec = sensor.arp_record(ATT_MAC, sensor.arp_stats[ATT_MAC], 0, 5)
        self.assertEqual(rec["source_ip"], ATT_IP)
        self.assertEqual(rec["binding_conflicts"], 1)
        self.assertEqual(rec["claimed_ip_list"], [USER_IP])
        self.assertEqual(sensor.ip_owner[USER_IP][0], USER_MAC)   # owner unchanged


def rec(**kw):
    r = {"window_start": "t0", "window_end": "t1", "mac": ATT_MAC, "source_ip": ATT_IP,
         "gw_impersonation": 0, "binding_conflicts": 0, "arp_claimed_ips": 0,
         "claimed_ip_list": []}
    r.update(kw)
    return r


class DetectorRule(unittest.TestCase):
    def test_vm_rule_off(self):
        self.assertIsNone(detector.ARP_FILE)

    def test_no_forged_claim_no_alert(self):
        self.assertEqual(detector.check_arp(rec()), [])

    def test_unknown_ip_cannot_be_blocked(self):
        self.assertEqual(detector.check_arp(rec(source_ip=None, gw_impersonation=2)), [])

    def test_whitelisted_ip_not_blamed(self):
        self.assertEqual(detector.check_arp(rec(source_ip="10.0.1.1", gw_impersonation=1)), [])

    def test_alert(self):
        [a] = detector.check_arp(rec(gw_impersonation=2, binding_conflicts=1,
                                     arp_claimed_ips=2, claimed_ip_list=[GW_IP, USER_IP]))
        self.assertEqual((a["attack_type"], a["source_ip"]), ("arp_spoof", ATT_IP))
        self.assertEqual(a["evidence"]["mac"], ATT_MAC)
        self.assertEqual(a["evidence"]["claimed_ip_list"], [GW_IP, USER_IP])


class ResponderGuard(unittest.TestCase):
    def setUp(self):
        self.nft_calls, self.cmd_calls = [], []
        self.saved = (responder.nft, responder.subprocess.run)

        class Done:
            returncode, stdout, stderr = 0, "", ""

        def fake_nft(*args):
            self.nft_calls.append(args)
            return Done()

        responder.nft = fake_nft
        responder.subprocess.run = lambda cmd, **kw: self.cmd_calls.append(cmd)

    def tearDown(self):
        responder.nft, responder.subprocess.run = self.saved

    def test_bad_mac_never_reaches_a_command(self):
        for bad in ("", "x; rm -rf /", "02:00:00:00:00", "02:00:00:00:00:zz"):
            self.assertIn("skipped", responder.arp_guard({"mac": bad}, 1800))
        self.assertEqual((self.nft_calls, self.cmd_calls), ([], []))

    def test_mac_blocked_and_valid_neighbours_flushed(self):
        out = responder.arp_guard({"mac": ATT_MAC.upper(),
                                   "claimed_ip_list": [USER_IP, "not-an-ip", GW_IP]}, 1800)
        self.assertIn(("add", "element", "arp", "oasis_arp", "macblock",
                       f"{{ {ATT_MAC} timeout 1800s }}"), self.nft_calls)
        self.assertEqual(self.cmd_calls, [["ip", "neigh", "flush", "to", USER_IP],
                                          ["ip", "neigh", "flush", "to", GW_IP]])
        self.assertIn("mac blocked", out)

    def test_manual_step_has_no_timeout(self):
        responder.arp_guard({"mac": ATT_MAC}, None)
        self.assertIn(("add", "element", "arp", "oasis_arp", "macblock", f"{{ {ATT_MAC} }}"),
                      self.nft_calls)


if __name__ == "__main__":
    unittest.main()
