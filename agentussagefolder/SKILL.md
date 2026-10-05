---
name: agentussagefolder
description: Fast, in-place, evidence-driven workflow for AI coding agents.
---

# Agent toolkit — read this, not a manual

The toolkit is an **in-place** engineering aid. Do not create a clone,
worktree, branch, merge, or duplicate implementation. Work in the user's
current repository and preserve unrelated dirty changes.

## One compact loop

Run from the project directory. Replace the JSON command with the project's real
check; it is an argv array, never a shell string.

```sh
python3 agentussagefolder/agent.py inspect path/to/target.py
python3 agentussagefolder/agent.py begin --task fix-name \
  --check '["python3","-m","pytest","tests/test_target.py","-q"]' \
  path/to/target.py
# make the smallest change directly here
python3 agentussagefolder/agent.py verify --task fix-name
python3 agentussagefolder/agent.py status --task fix-name
# after review/integration of the direct worktree result
python3 agentussagefolder/agent.py close --task fix-name
```

`inspect` is lazy and bounded: it reads only named targets and returns pointers
to nearby rules/manifests. Add `--history` or `--symbol NAME` only when that
decision needs it. `begin` records a baseline; it does not run checks. `verify`
always executes the declared commands again—never trusts a pasted PASS, cached
result, or self-written evidence file. Keep the same interpreter/environment for
`verify`, `status`, and `close`; a changed test environment makes the receipt
stale instead of silently reusing it.

## Safety contract

- No toolkit command switches Git state or writes project files. The only
  automatic writes are private receipts under `agentussagefolder/.state/`.
- Exact file/directory scopes are reserved. A concurrent overlapping task is
  rejected. HEAD, index, protected `tests/invariants/`, private/runtime files,
  ignored executable source, symlinks, and out-of-scope deltas fail closed.
- Dirty files that existed before `begin` are preserved and included in the
  baseline; unrelated edits made afterward block verification.
- Clean files are protected by Git HEAD/index. Dirty files are freshly hashed;
  no recursive repository walk or stat-only content cache is used.
- Known ephemeral trees (`.venv`, caches, build output, `.agents`, `scratch`,
  `research`, and `.kilo`) are deliberately opaque and excluded from evidence;
  never place production source there. Other ignored executable source or
  ignored directories block the task.
- Output is compact JSON with bounded tails and content hashes. `CHECKS_PASSED`
  proves only that the explicit commands passed without changing watched state;
  it is not correctness, review approval, or a process sandbox. Commands may
  still access networks, credentials, or external files, so authorize them
  deliberately and use temporary fixtures.
- Unresolved `--unknown` claims block verification. The command receipt is
  integrity-protected against accidental edits, not an independent human
  attestation.

## Retrieval map

| Need | Command | Cost |
|---|---|---|
| What matters now | `agent.py inspect TARGET...` | bounded target facts |
| History coupling | add `--history` | opt-in, latest 100 commits |
| Lexical callers | add `--symbol NAME` | opt-in, named targets only |
| Reserve + verify | `agent.py begin/verify/status` | exact task scope |
| Release reservation | `agent.py close --task NAME` | keeps an audit receipt |
| Existing invariant check | `check_vault.sh` | project-defined invariant suite |

`radar.sh`, `git_logical_coupling.sh`, and `enforce_workflow.sh` are compatibility
adapters. They do not grant permission, calculate a magic risk score, or create
branches. `semantic_airlock.py` is a legacy structural-capsule API; its `ok`
field is not independent approval. Use `agent.py` for new work.

For a deterministic stdout regression probe, use `agent.py probe` with an
explicit script and baseline; it is supplementary evidence, not a replacement
for the real test command. Before changing dependencies, detect the repository's
existing manager/lockfile and use it; never run global `pip install`, silently
replace the manager, or rewrite lockfiles outside the requested task.

Do not read the other toolkit files unless the retrieval map or a compatibility
failure points there. If a command cannot prove a fact, it reports unknown; do
not convert unknown into confidence.
