#!/bin/sh
# Lab hosts: send all traffic through the OASIS gateway, then run the command.
set -e
if [ -n "$OASIS_GW" ]; then
    ip route replace default via "$OASIS_GW"
    echo "default route -> $OASIS_GW"
fi
exec "$@"
