# Build locally, review/scan it, then configure its immutable sha256 image ID.
FROM python:3.11-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl nmap nftables util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/aria
COPY worker/__init__.py worker/policy.py worker/container_entry.py ./worker/
COPY orchestrator/__init__.py orchestrator/execution_policy.py ./orchestrator/
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["/usr/local/bin/python", "-m", "worker.container_entry"]
