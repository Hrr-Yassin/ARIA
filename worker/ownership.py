"""Local process lock prevents a stale controller surviving DB lease loss."""
import fcntl
import os
import stat
from pathlib import Path


class ControllerLock:
    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.fd = None

    def open(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError('Worker state directory must be private and owned by this user')
        fd = os.open(self.directory / 'controller.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(fd)
            raise RuntimeError('Another local worker controller is running') from None
        self.fd = fd

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
