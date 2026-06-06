# PurpleRecon — reproducible backend + CLI image, with nmap baked in.
#
# Build:  docker build -t purplerecon .
# Run the API (LAN scanning needs the host network — see docker-compose.yml):
#         docker run --rm --network host -e PURPLERECON_API_TOKEN=changeme purplerecon
# Run the CLI:
#         docker run --rm --network host purplerecon \
#             python /app/purple_recon.py 192.168.0.0/24 --discover --no-ui -y
#
# ⚠️ Authorized use only. With --network host the API listens on the host's
#    interfaces; set PURPLERECON_API_TOKEN so it isn't open on your LAN.

FROM python:3.12-slim

# Runtime tools the scanner shells out to: nmap (service/version), ping + arp/ndp
# (discovery). Pinned base + cleaned apt lists for a small, reproducible image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap iproute2 iputils-ping net-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first for layer caching.
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Application: the shared CLI engine + the FastAPI backend + packaging metadata.
COPY purple_recon.py pyproject.toml README.md ./
COPY backend/ ./backend/
RUN pip install --no-cache-dir -e .

# Persisted scan history lives here (mount a volume to keep it across runs).
ENV PURPLERECON_DB=/data/purplerecon_history.db
RUN mkdir -p /data

EXPOSE 8011
WORKDIR /app/backend

# Inside the container we must bind 0.0.0.0; isolate it with --network host +
# a token (or a bridge network + reverse proxy) when deploying. Localhost-only
# is the default for the bare `make dev` workflow.
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8011"]
