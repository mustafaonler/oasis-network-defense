#!/bin/sh
# OASIS gateway: check forwarding, load the firewall, report interfaces.
set -e
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 1 ]; then
    echo "ip_forward is off" >&2
    exit 1
fi
nft list table inet lab_isolation >/dev/null 2>&1 || nft -f /etc/oasis/lab_isolation.nft
nft list table inet oasis >/dev/null 2>&1 || nft -f /etc/oasis/oasis.nft
# No way out of the lab: drop the Docker-provided default route.
ip route del default 2>/dev/null && echo "default route removed" || true
# Interface names depend on network attach order, so look them up by IP.
for ip in $OASIS_GW_IPS; do
    ifc=$(ip -o -4 addr show | awk -v ip="$ip" 'index($4, ip "/") == 1 {print $2}')
    if [ -z "$ifc" ]; then
        echo "no interface holds $ip" >&2
        exit 1
    fi
    echo "$ip -> $ifc"
done
exec "$@"
