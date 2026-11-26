# OASIS attacker: lab traffic generator (nmap, hping3, scapy for forged ARP tests,
# mitm.py for the ARP-poisoning demo).
FROM debian:trixie-slim
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
       nmap hping3 iproute2 iputils-ping curl ca-certificates python3-scapy \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0755 common/set-route.sh /usr/local/bin/set-route.sh
COPY --chmod=0755 attacker/mitm.py /usr/local/bin/mitm.py
ENTRYPOINT ["/usr/local/bin/set-route.sh"]
CMD ["sleep", "infinity"]
