"""Verify a fully vendored image overlay without downloading or executing tools.

The lock contains every path, including symlink targets, so an approved bundle can
be rebuilt without mutable tags, package indexes, update checks or network access.
Generate it once during dependency review; retain it beside the immutable bundle.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat


def inventory(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            import os
            target = os.readlink(path)
            # Overlay symlinks must resolve within its root, not to build-host files.
            if target.startswith('/') or not path.resolve().is_relative_to(root.resolve()):
                raise ValueError('Bundle symlink escapes root')
            result[name] = {'symlink': target}
        elif stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                while chunk := stream.read(1048576):digest.update(chunk)
            result[name] = {'sha256':digest.hexdigest(),'mode':stat.S_IMODE(info.st_mode)}
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError('Bundle contains special files')
    if not result:raise ValueError('Empty dependency bundle')
    return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('root',type=Path)
    parser.add_argument('lock',type=Path)
    parser.add_argument('--write-lock',action='store_true')
    args=parser.parse_args()
    current=inventory(args.root)
    if args.write_lock:
        # Explicit operator action for newly reviewed dependency bytes.
        with args.lock.open('x') as stream:json.dump(current,stream,sort_keys=True,indent=2);stream.write('\n')
    elif json.loads(args.lock.read_text())!=current:
        raise ValueError('Dependency bundle differs from its lock')


if __name__=='__main__':main()
