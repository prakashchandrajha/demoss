#!/usr/bin/env bash
# Compatibility adapter: history is opt-in and never authorizes an edit.
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <target-file>" >&2
  exit 2
fi
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo 'context: not inside a Git worktree' >&2; exit 2;
}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$SCRIPT_DIR/context.py" --cwd "$PWD" \
  --history --limit 8 "$1"
