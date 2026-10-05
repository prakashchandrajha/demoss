#!/usr/bin/env bash
# Compatibility adapter for older agents. It reserves the real worktree;
# unlike the old script it never switches branches or uses checkout -B.
set -euo pipefail
if [[ ${1:-} == --force ]]; then
  echo 'enforce_workflow: --force was removed; unknowns must be resolved, not bypassed' >&2
  exit 2
fi
if [[ $# -lt 2 ]]; then
  echo 'Usage: enforce_workflow.sh <task> <target> [--check JSON_ARGV ...]' >&2
  exit 2
fi
TASK=$1
TARGET=$2
shift 2
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ARGS=(begin --task "$TASK" --project "$PWD")
while [[ $# -gt 0 ]]; do
  case $1 in
    --check|--protect|--unknown|--timeout)
      [[ $# -ge 2 ]] || { echo "$1 needs a value" >&2; exit 2; }
      ARGS+=("$1" "$2"); shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
exec python3 "$SCRIPT_DIR/agent.py" "${ARGS[@]}" "$TARGET"
