#!/bin/sh
set -eu
python=''
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys;sys.exit(not (sys.implementation.name=="cpython" and (3,12,14)<=sys.version_info[:3]<(3,15,0)))'; then
        python="$candidate"; break
    fi
done
[ -n "$python" ] || { echo 'Install CPython 3.12.14 or newer (through 3.14), then run this command again.' >&2; exit 1; }
directory=$(mktemp -d "${TMPDIR:-/tmp}/ssh-snakehole.XXXXXX")
curl -fsSL https://github.com/heetbeet/ssh-snakehole/releases/latest/download/ssh-snakehole.pyz -o "$directory/app.pyz"
[ "$#" -gt 0 ] || set -- open
exec "$python" "$directory/app.pyz" "$@"
