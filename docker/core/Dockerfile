# OASIS core: sensor, detector, responder (one image, one service each).
FROM debian:trixie-slim
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
       python3 python3-scapy tcpdump nftables \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY src/ src/
ENV PYTHONUNBUFFERED=1
CMD ["python3", "src/sensor.py"]
