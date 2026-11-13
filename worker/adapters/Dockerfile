# Build from repo root with a reviewed vendor/ overlay and vendor.lock.json.
# ARIA_BASE_IMAGE must include @sha256:<64 hex>; this recipe performs no downloads.
ARG ARIA_BASE_IMAGE
FROM ${ARIA_BASE_IMAGE}
ARG ARIA_BASE_IMAGE
COPY worker/adapters/verify_bundle.py /opt/verify_bundle.py
COPY vendor/ /opt/vendor/
COPY vendor.lock.json /opt/vendor.lock.json
RUN python -c "import os,re; assert re.fullmatch(r'[^ ]+@sha256:[0-9a-f]{64}', os.environ['ARIA_BASE_IMAGE'])" \
    && python /opt/verify_bundle.py /opt/vendor /opt/vendor.lock.json \
    && cp -a /opt/vendor/. / \
    && rm -rf /opt/vendor
WORKDIR /opt/aria
COPY security_tools/ ./security_tools/
COPY config/__init__.py config/security_tool_registry.py ./config/
COPY worker/__init__.py worker/policy.py worker/container_entry.py worker/http_profile.py worker/http_runner.py ./worker/
COPY orchestrator/__init__.py orchestrator/execution_policy.py ./orchestrator/
COPY worker/assets/ ./assets/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/opt/aria
ENTRYPOINT ["/usr/local/bin/python3.11", "-m", "worker.container_entry"]
