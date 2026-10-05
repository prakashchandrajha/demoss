#!/usr/bin/env bash
# Compatibility runner for the repository's protected invariant suite.
# It does not create branches, alter files, or claim broader correctness.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT=$(cd -- "$SCRIPT_DIR/.." && pwd)
git -C "$PROJECT" rev-parse --show-toplevel >/dev/null 2>&1 || {
  echo 'check_vault: not inside a Git worktree' >&2; exit 2;
}
cd "$PROJECT"
if [[ ! -d tests/invariants ]]; then
  echo 'check_vault: tests/invariants is absent (not passed)' >&2
  exit 2
fi
exec env PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/invariants/ -q -p no:cacheprovider
