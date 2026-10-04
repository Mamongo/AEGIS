#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ -n "${PYTHON:-}" ]; then
  "$PYTHON" run.py test
elif command -v python3 >/dev/null 2>&1; then
  python3 run.py test
else
  python run.py test
fi
