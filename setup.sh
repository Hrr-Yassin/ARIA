#!/usr/bin/env bash
# Unprivileged checkout-local setup. Provision PostgreSQL/Redis separately.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ "$(id -u)" == 0 ]]; then
    echo 'Run setup as an unprivileged user, without sudo.' >&2
    exit 1
fi
PYTHON_BIN="${PYTHON_BIN:-python3.11}"
"$PYTHON_BIN" -c 'import sys; assert sys.version_info[:2] == (3, 11), "ARIA supports Python 3.11 only"'
"$PYTHON_BIN" -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python -m pip check
printf '%s\n' 'Environment ready. Configure .env, apply migrations, bootstrap an administrator, then start the API (see README.md).'
