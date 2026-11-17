"""Local preparation/transaction mechanics for the reviewed telemetry patch.

No guest connection or CLI apply path exists here. A future authorized operator
must stop/drain the existing worker, serialize maintenance with its process lock,
and provide live quiescence/restart/configuration checks. This module itself
neither establishes owner approval nor grants execution authority.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Callable
import uuid

BASE_SERVICE_SHA = 'be276da5a9eb6aea69fd94e681f333e09f680abbaa579c3772b0f83342ba030a'
REVIEWED_SHA = {
    'observability.py': 'abc14e2dbca1dff49e81628d5a11bae3035ef94a5ca261a14b4b92ae13fc0913',
    'service.py': '5c380f07266d94605e415f34989650ba9757d25bd59ad29013921d2dbbc66824',
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prepare_bundle(source_root: Path, output: Path) -> dict:
    """Copy exactly two reviewed files into a new local private directory."""
    sources = {}
    for name, expected in REVIEWED_SHA.items():
        path = source_root/'worker'/name
        if path.is_symlink() or digest(path.read_bytes()) != expected:
            raise ValueError('Source differs from reviewed telemetry patch')
        sources[name] = path.read_bytes()
        compile(sources[name], name, 'exec')
    output.mkdir(mode=0o700)  # Never reuse or overwrite an earlier review bundle.
    for name, data in sources.items():
        (output/name).write_bytes(data)
        (output/name).chmod(0o600)
    result = {'schema': 'aria.worker.telemetry.bundle.v1', 'approval': 'NOT_GRANTED',
        'expected_old_service_sha256': BASE_SERVICE_SHA, 'sha256': REVIEWED_SHA,
        'scope': ['worker/observability.py', 'worker/service.py'], 'worker_operations': 0}
    (output/'manifest.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


@dataclass
class DeploymentResult:
    status: str
    files_restored: bool = False
    service_restored: bool = False
    error_type: str | None = None
    backup: str | None = None


def install_reviewed_files(worker_directory: Path, bundle: Path, *, owner_authorized: bool,
                           quiescent: Callable[[], bool], restart: Callable[[], None],
                           verify_running: Callable[[], bool]) -> DeploymentResult:
    """Two-file transaction; caller must already own the maintenance window.

    quiescent must prove an inactive/drained worker, no active/uncertain jobs and
    serialized maintenance. Returning True is not an API/model approval. Actual
    Kali invocation remains prohibited until explicit owner authorization.
    """
    if owner_authorized is not True:
        raise PermissionError('Explicit owner authorization required')
    root = worker_directory.absolute()
    if root.resolve() != root or not root.is_dir():
        raise ValueError('Worker directory must be existing and have no symlink components')
    old = root/'service.py'
    observer = root/'observability.py'
    if old.is_symlink() or not old.is_file() or digest(old.read_bytes()) != BASE_SERVICE_SHA:
        raise ValueError('Worker service baseline mismatch')
    if observer.exists() or observer.is_symlink():
        raise ValueError('Unexpected existing telemetry module')
    payload = {}
    for name, expected in REVIEWED_SHA.items():
        path = bundle/name
        if path.is_symlink() or digest(path.read_bytes()) != expected:
            raise ValueError('Bundle differs from reviewed patch')
        payload[name] = path.read_bytes()
        compile(payload[name], name, 'exec')
    if quiescent() is not True:
        raise RuntimeError('Worker quiescence is not verified')
    info = old.stat()
    original = old.read_bytes()
    backup = root/('.telemetry-backup-'+uuid.uuid4().hex)
    backup.mkdir(mode=0o700)
    (backup/'service.py').write_bytes(original)
    (backup/'service.py').chmod(0o600)
    (backup/'metadata.json').write_text(json.dumps({'uid': info.st_uid, 'gid': info.st_gid,
        'mode': stat.S_IMODE(info.st_mode), 'observer_existed': False,
        'service_sha256': digest(original)}, indent=2)+'\n')
    installed = []
    temporary = []
    restart_attempted = False

    def replace(name: str, data: bytes) -> None:
        staged = root/('.telemetry-stage-'+uuid.uuid4().hex)
        temporary.append(staged)
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
        os.replace(staged, root/name)

    try:
        # Install the dependency before the service importing it.
        for name, data in payload.items():
            if name == 'service.py' and (old.is_symlink() or digest(old.read_bytes()) != BASE_SERVICE_SHA):
                raise RuntimeError('Service baseline changed during maintenance')
            if name == 'observability.py' and (observer.exists() or observer.is_symlink()):
                raise RuntimeError('Telemetry module appeared during maintenance')
            replace(name, data)
            installed.append(name)
        if quiescent() is not True:
            raise RuntimeError('Worker quiescence changed')
        restart_attempted = True
        restart()
        if verify_running() is not True:
            raise RuntimeError('Worker post-start identity/configuration check failed')
        return DeploymentResult('APPLIED', backup=str(backup))
    except Exception as error:
        result = DeploymentResult('FAILED', error_type=type(error).__name__, backup=str(backup))
        try:
            # Refuse to overwrite an external change even during rollback.
            for name in installed:
                path = root/name
                if path.is_symlink() or digest(path.read_bytes()) != REVIEWED_SHA[name]:
                    raise RuntimeError('Manual reconciliation required: installed source changed')
            if 'service.py' in installed:
                replace('service.py', original)
            if 'observability.py' in installed:
                observer.unlink()
            result.files_restored = True
            if restart_attempted:
                restart()
                result.service_restored = verify_running() is True
        except Exception:
            # Never guess that the old service is running after a rollback fault.
            pass
        return result
    finally:
        for staged in temporary:
            staged.unlink(missing_ok=True)
