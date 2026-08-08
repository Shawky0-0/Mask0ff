#!/usr/bin/env sh
set -eu

if [ -n "${MASK0FF_PYTHON:-}" ]; then
  python_executable="$MASK0FF_PYTHON"
elif command -v python3 >/dev/null 2>&1; then
  python_executable="python3"
elif command -v python >/dev/null 2>&1; then
  python_executable="python"
else
  echo "ERROR: mask0ff requires Python 3.10 or newer. Set MASK0FF_PYTHON to a usable interpreter." >&2
  exit 2
fi

if ! "$python_executable" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
  echo "ERROR: mask0ff requires Python 3.10 or newer." >&2
  exit 2
fi

export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8
export PYTHONDONTWRITEBYTECODE=1
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$python_executable" "$script_dir/mask0ff.py" "$@"
