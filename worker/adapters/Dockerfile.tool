# A per-tool context contains only the reviewed source and selected tool bytes.
ARG RUNTIME_BASE
FROM ${RUNTIME_BASE}
ARG TOOL
COPY overlay/ /
COPY source/ /opt/aria/
ENTRYPOINT ["/usr/local/bin/python3.11", "-m", "worker.container_entry"]
