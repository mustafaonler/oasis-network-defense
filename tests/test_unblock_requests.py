#!/usr/bin/env python3
"""Tests for the responder side of dashboard unblock requests (no nft: fake calls).

Run in the core image:  python3 -m unittest discover -s tests -p test_unblock_requests.py -v
"""
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
for k in [k for k in os.environ if k.startswith("OASIS_")]:
    del os.environ[k]
import responder   # noqa: E402

BLOCKED = {"10.10.1.64", "10.10.1.70"}


class Requests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "req", "unblock.jsonl")
        self.done = []
        self.saved = (responder.nft_blocked, responder.unblocker.unblock)
        responder.nft_blocked = lambda ip: ip in BLOCKED
        responder.unblocker.unblock = lambda ip, db, reason: self.done.append((ip, reason))

    def tearDown(self):
        responder.nft_blocked, responder.unblocker.unblock = self.saved
        self.tmp.cleanup()

    def write(self, *ips):
        with open(self.path, "a") as f:
            for ip in ips:
                f.write(json.dumps({"ip": ip}) + "\n")

    def test_vm_reads_no_requests(self):
        self.assertIsNone(responder.UNBLOCK_REQUESTS)

    def test_directory_open_for_the_dashboard(self):
        responder.UnblockRequests(self.path)
        mode = stat.S_IMODE(os.stat(os.path.dirname(self.path)).st_mode)
        self.assertEqual(mode, 0o1733)
        self.assertFalse(os.path.exists(self.path))     # the dashboard creates the file

    def test_waiting_requests_are_not_replayed(self):
        os.makedirs(os.path.dirname(self.path))
        self.write("10.10.1.64")                         # before the responder started
        q = responder.UnblockRequests(self.path)
        q.poll(None)
        self.assertEqual(self.done, [])
        self.write("10.10.1.70")
        q.poll(None)
        self.assertEqual(self.done, [("10.10.1.70", "unblock from dashboard")])

    def test_only_blocked_valid_ips(self):
        q = responder.UnblockRequests(self.path)
        self.write("10.10.1.64", "10.10.1.99", "not-an-ip")
        with open(self.path, "a") as f:
            f.write("{broken json\n")
        q.poll(None)
        self.assertEqual([ip for ip, _ in self.done], ["10.10.1.64"])

    def test_nothing_lost_above_the_per_round_limit(self):
        q = responder.UnblockRequests(self.path)
        self.write(*(["10.10.1.64"] * 25))
        q.poll(None)
        self.assertEqual(len(self.done), 20)
        q.poll(None)
        self.assertEqual(len(self.done), 25)


if __name__ == "__main__":
    unittest.main()
