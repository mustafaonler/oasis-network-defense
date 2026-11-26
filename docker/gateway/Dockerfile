# OASIS gateway: routes attacker-net <-> victim-net and enforces nftables.
FROM debian:trixie-slim
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
       nftables iproute2 iputils-ping tcpdump procps \
    && rm -rf /var/lib/apt/lists/*
COPY gateway/oasis.nft gateway/lab_isolation.nft /etc/oasis/
COPY --chmod=0755 gateway/entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]
