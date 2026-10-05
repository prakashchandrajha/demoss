#!/usr/bin/env bash
# Small compatibility adapter. History and probes are optional observations;
# this command never creates a branch and never grants edit permission.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SYMBOL=
PROBE_SCRIPT=
PROBE_BASELINE=
PROBE_VERIFY=
PROBE_PYTHON=
MACHINE_OUT=
TARGET=
while [[ $# -gt 0 ]]; do
  case $1 in
    -s|--symbol) [[ $# -ge 2 ]] || { echo "$1 needs a value" >&2; exit 2; }; SYMBOL=$2; shift 2 ;;
    --no-symbols) shift ;;
    --probe-script) [[ $# -ge 2 ]] || { echo "$1 needs a value" >&2; exit 2; }; PROBE_SCRIPT=$2; shift 2 ;;
    --probe-baseline) [[ $# -ge 2 ]] || { echo "$1 needs a value" >&2; exit 2; }; PROBE_BASELINE=$2; shift 2 ;;
    --probe-verify) [[ $# -ge 2 ]] || { echo "$1 needs a value" >&2; exit 2; }; PROBE_VERIFY=$2; shift 2 ;;
    --python) [[ $# -ge 2 ]] || { echo "$1 needs a value" >&2; exit 2; }; PROBE_PYTHON=$2; shift 2 ;;
    --machine-out) [[ $# -ge 2 ]] || { echo "$1 needs a value" >&2; exit 2; }; MACHINE_OUT=$2; shift 2 ;;
    --) shift; [[ $# -eq 1 ]] || { echo 'one target is required' >&2; exit 2; }; TARGET=$1; shift ;;
    -*) echo "unsupported legacy option: $1" >&2; exit 2 ;;
    *) [[ -z $TARGET ]] || { echo 'only one target is supported' >&2; exit 2; }; TARGET=$1; shift ;;
  esac
done
[[ -n $TARGET ]] || { echo 'Usage: radar.sh [options] <target>' >&2; exit 2; }
if [[ -n $PROBE_BASELINE || -n $PROBE_VERIFY ]]; then
  [[ -n $PROBE_SCRIPT ]] || { echo '--probe-script is required' >&2; exit 2; }
  [[ -z $PROBE_BASELINE || -z $PROBE_VERIFY ]] || { echo 'choose baseline or verify' >&2; exit 2; }
  ARGS=(probe --project "$PWD" --script "$PROBE_SCRIPT")
  [[ -n $PROBE_BASELINE ]] && ARGS+=(--baseline "$PROBE_BASELINE")
  [[ -n $PROBE_VERIFY ]] && ARGS+=(--verify "$PROBE_VERIFY")
  [[ -n $PROBE_PYTHON ]] && ARGS+=(--python "$PROBE_PYTHON")
  exec python3 "$SCRIPT_DIR/agent.py" "${ARGS[@]}"
fi
if [[ -n $MACHINE_OUT ]]; then
  printf 'RISK\tUNKNOWN\t0\n' > "$MACHINE_OUT"
  echo 'machine output reports UNKNOWN; it is not an authorization signal' >&2
fi
if [[ -n $SYMBOL ]]; then
  exec python3 "$SCRIPT_DIR/context.py" --cwd "$PWD" --history --symbol "$SYMBOL" "$TARGET"
fi
exec python3 "$SCRIPT_DIR/context.py" --cwd "$PWD" --history "$TARGET"
