#!/usr/bin/env sh
# cchooks installer for macOS, Linux, WSL and Git Bash.
# Finds a Python 3.9+ interpreter and hands off to installer/install.py,
# which records that interpreter's absolute path in the hook entries.
# All arguments are passed through (see: sh install.sh --help).
set -eu

here=$(cd "$(dirname "$0")" && pwd)

try_python() {
  # $@ = interpreter command; prints its absolute path if it is 3.9+
  "$@" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1 || return 1
  "$@" -c 'import sys; print(sys.executable)' 2>/dev/null
}

py=""
for cand in "${CCHOOKS_PYTHON:-}" python3 python "py -3"; do
  [ -n "$cand" ] || continue
  # shellcheck disable=SC2086  # "py -3" must split
  if out=$(try_python $cand); then
    py="$out"
    break
  fi
done

if [ -z "$py" ]; then
  echo "cchooks: no Python 3.9+ found (tried \$CCHOOKS_PYTHON, python3, python, py -3)." >&2
  echo "Install Python from https://www.python.org/downloads/ and re-run." >&2
  echo "Without it the hooks would fail to start, and Claude Code treats that as 'allow'." >&2
  exit 1
fi

echo "Using Python: $py"
exec "$py" "$here/installer/install.py" "$@"
