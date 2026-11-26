# OASIS dashboard: read-only web view of oasis.db (Python standard library only).
FROM debian:trixie-slim
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY src/dashboard.py src/
COPY src/dashboard_static/ src/dashboard_static/
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
EXPOSE 8080
CMD ["python3", "src/dashboard.py"]
