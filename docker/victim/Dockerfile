# OASIS victim: simple web server behind the gateway.
FROM debian:trixie-slim
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
       python3 iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0755 common/set-route.sh /usr/local/bin/set-route.sh
WORKDIR /srv
RUN echo "OASIS victim" > index.html
ENTRYPOINT ["/usr/local/bin/set-route.sh"]
CMD ["python3", "-m", "http.server", "80"]
