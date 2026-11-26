# OASIS attacker: lab traffic generator (nmap, hping3, scapy for forged ARP tests).
FROM debian:trixie-slim
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
       nmap hping3 iproute2 iputils-ping curl ca-certificates python3-scapy \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0755 common/set-route.sh /usr/local/bin/set-route.sh
ENTRYPOINT ["/usr/local/bin/set-route.sh"]
CMD ["sleep", "infinity"]
