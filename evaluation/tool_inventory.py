"""Read-only host tool inventory; never probes targets or changes worker profiles."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shutil
import subprocess

from config.tool_knowledge import catalog


def inventory(worker_metadata: Path | None = None) -> dict:
    snapshot = json.loads(worker_metadata.read_text()) if worker_metadata else {}
    advertised = set(snapshot.get('tools', []))
    rows = []
    for item in catalog():
        row = dict(item)
        executable = shutil.which(row.get('host_executable', row['tool']))
        package = row.get('fedora_package') or row['tool']
        rpm = subprocess.run(['rpm', '-q', '--qf', '%{NAME}|%{VERSION}-%{RELEASE}|%{LICENSE}\n', package],
                             capture_output=True, text=True, timeout=5)
        package_data = rpm.stdout.strip() if rpm.returncode == 0 else None
        distribution = row.get('python_distribution')
        try:
            python_version = importlib.metadata.version(distribution) if distribution else None
        except importlib.metadata.PackageNotFoundError:
            python_version = None
        row.update({'host_on_path': executable is not None, 'host_executable_path': executable,
                    'host_package_metadata': package_data, 'host_python_distribution_version': python_version,
                    'installed_on_host': bool(executable or package_data or python_version),
                    'advertised_by_saved_worker_metadata': row['tool'] in advertised,
                    'worker_live_rechecked': False,
                    'measured_runtime_rss_bytes': None})
        rows.append(row)
    return {'schema': 'aria.tool-inventory.v1', 'observed_at': datetime.now(timezone.utc).isoformat(),
            'host': 'Fedora read-only PATH/RPM/Python distribution inspection',
            'worker_metadata': str(worker_metadata) if worker_metadata else None,
            'worker_metadata_sha256': hashlib.sha256(worker_metadata.read_bytes()).hexdigest() if worker_metadata else None,
            'tools': rows, 'installations': 0, 'worker_changes': 0, 'target_actions': 0,
            'limitations': ['Installed does not mean integrated, tested, enabled or operationally verified.',
                           'Worker advertisements and lab receipts are retained historical evidence; no new worker job was run.',
                           'Null versions and license metadata remain unknown; no current upstream-release claim.']}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker-metadata', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inventory(args.worker_metadata)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as handle:
        handle.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'tools': len(result['tools']), 'installed_on_host': sum(r['installed_on_host'] for r in result['tools']),
                      'new_worker_jobs': 0, 'output': str(args.output)}))


if __name__ == '__main__':
    main()
