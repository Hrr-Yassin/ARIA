#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ $# -ne 1 ]]; then echo 'Usage: bash burp-community/build.sh /path/to/montoya-api.jar' >&2; exit 2; fi
mkdir -p build
task_build_dir=$(mktemp -d build/classes.XXXXXX)
javac --release 17 -cp "$1" -d "$task_build_dir" src/aria/*.java
jar --create --file build/aria-community.jar -C "$task_build_dir" .
