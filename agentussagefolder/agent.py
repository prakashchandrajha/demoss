#!/usr/bin/env python3
"""Fast, in-place task receipts for AI coding agents.

This tool never creates a branch, worktree, clone, commit, reset, restore, or
project file.  It reserves exact paths in the current worktree, runs only the
JSON argv checks the agent explicitly declares, and re-snapshots watched source
paths before and after each check.  ``CHECKS_PASSED`` means only that those
commands passed without changing the watched state; it is not code correctness,
review approval, or a sandbox guarantee.

Only the toolkit's private ``.state`` directory is written automatically.
Credentials, databases, logs, runtime data, symlinks and unsupported special
files are never read.  An authorized check is still allowed to access the
network or external files; use a disposable command/environment when that
matters.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

TOOLKIT = Path(__file__).resolve().parent
STATE = TOOLKIT / ".state"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
PRUNE = {".venv", ".venv_test", "venv", "env", "node_modules", "build", "dist",
         "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
         ".tox", ".nox", "coverage", ".cache", "htmlcov"}
PRIVATE_DIRS = {"logs", "runtime", "data", "database", ".ssh", ".aws",
               ".gnupg", ".kube"}
# These are explicitly ephemeral/tooling trees in this repository. Their
# contents are not evidence and are never read; production source belongs in a
# tracked project directory, not in one of these paths.
GENERATED_DIRS = PRUNE | {".agents", ".omnirush", ".kilo", "scratch", "research"}
PRIVATE_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".log", ".pid", ".lock", ".pem",
                    ".key", ".p12", ".pfx", ".csv", ".parquet", ".pkl", ".pickle",
                    ".zip", ".gz", ".so", ".pyc", ".pyo", ".shm"}
MAX_FILE, MAX_TOTAL, MAX_ENTRIES = 16 << 20, 256 << 20, 50000
MAX_STATUS_BYTES, TAIL = 16 << 20, 8192
SOURCE_SUFFIXES = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".c", ".h", ".cc",
                   ".cpp", ".hpp", ".rs", ".go", ".java", ".rb", ".sh", ".sql"}


class Blocked(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_hash(path, maximum=MAX_FILE):
    """Never use a stat-based content cache; reject races and symlink reads."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise Blocked(f"unsupported file size/type: {path}")
        hasher, count = hashlib.sha256(), 0
        for chunk in iter(lambda: stream.read(65536), b""):
            count += len(chunk)
            if count > maximum:
                raise Blocked(f"file grew past snapshot limit: {path}")
            hasher.update(chunk)
        after = os.fstat(stream.fileno())
    if guard(before) != guard(after):
        raise Blocked(f"file changed while hashing: {path}")
    return hasher.hexdigest()


def guard(info):
    return [info.st_mode, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def environment():
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GIT_"):
            del env[key]
    env.update(GIT_OPTIONAL_LOCKS="0", PYTHONDONTWRITEBYTECODE="1")
    env["PYTEST_ADDOPTS"] = env.get("PYTEST_ADDOPTS", "") + " -p no:cacheprovider"
    return env


def git(root, *args, data=None, allowed=(0,)):
    result = subprocess.run(["git", "--no-pager", "-c",
                             "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
                            cwd=root, input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=environment(), timeout=30, check=False)
    if len(result.stdout) > MAX_STATUS_BYTES:
        raise Blocked("Git result exceeds the bounded output limit")
    if result.returncode not in allowed:
        raise Blocked("git " + args[0] + " failed: " +
                      result.stderr.decode(errors="replace").strip()[:300])
    return result.stdout


def ignored(root, names):
    if not names:
        return set()
    output = git(root, "check-ignore", "--no-index", "-z", "--stdin",
                 data=b"\0".join(os.fsencode(x) for x in names) + b"\0", allowed=(0, 1))
    return {os.fsdecode(x) for x in output.split(b"\0") if x}


def private(path):
    parts, name = Path(path).parts, Path(path).name.lower()
    # src/database is source, whereas top-level/project database trees are data.
    data_dir = any(p.lower() in PRIVATE_DIRS and
                   not (p.lower() == "database" and i and parts[i - 1].lower() == "src")
                   for i, p in enumerate(parts[:-1]))
    return (data_dir or name in {".kite_session", ".netrc", ".npmrc", ".pypirc",
                                "credentials", "credentials.json",
                                "secrets.json", "secrets.yml", "secrets.yaml"}
            or name.startswith(("id_rsa", "id_ed25519", "id_ecdsa"))
            or (name.startswith(".env") and name not in
                {".env.example", ".env.sample", ".env.template"})
            or Path(name).suffix in PRIVATE_SUFFIXES
            or any(name.endswith(x) for x in (".db-wal", ".db-shm", ".sqlite-wal")))


def git_state(root):
    entries = git(root, "ls-files", "--stage", "-v", "-z")
    if any(record[:1].islower() for record in entries.split(b"\0") if record):
        raise Blocked("assume-unchanged tracked files are unsupported; clear the flag first")
    if any(record[2:].startswith(b"160000 ") for record in entries.split(b"\0")):
        raise Blocked("submodules require their own verified boundary; unsupported here")
    if git(root, "ls-files", "--unmerged", "-z"):
        raise Blocked("unmerged index entries must be resolved first")
    return {"head": git(root, "rev-parse", "--verify", "HEAD").decode().strip(),
            "ref": git(root, "symbolic-ref", "-q", "HEAD", allowed=(0, 1)).decode().strip(),
            "index": hashlib.sha256(entries).hexdigest()}


def _status_paths(root, boundary=None):
    """Return Git's changed paths without walking clean or ignored trees."""
    raw = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all",
              "--ignored=matching", "--ignore-submodules=none")
    if len(raw) > MAX_STATUS_BYTES:
        raise Blocked("too many changed paths for a bounded receipt")
    boundary_rel = None
    if boundary is not None:
        boundary_rel = Path(boundary).relative_to(root).as_posix().rstrip("/")
        if boundary_rel == ".":
            boundary_rel = ""
    records, index = [], 0
    parts = raw.split(b"\0")
    while index < len(parts):
        item = parts[index]
        index += 1
        if not item:
            continue
        if len(item) < 4 or item[2:3] != b" ":
            raise Blocked("Git returned an unsupported porcelain status record")
        code, encoded = os.fsdecode(item[:2]), os.fsdecode(item[3:])
        records.append((code, encoded))
        if code[0] in "RC" or code[1] in "RC":
            if index >= len(parts) or not parts[index]:
                raise Blocked("Git returned an incomplete rename record")
            records.append((code, os.fsdecode(parts[index])))
            index += 1
    if boundary_rel:
        records = [(code, rel) for code, rel in records
                   if rel == boundary_rel or rel.startswith(boundary_rel + "/")]
    if len(records) > MAX_ENTRIES:
        raise Blocked("changed-path limit exceeded")
    return records


def _opaque(path):
    info = path.lstat()
    return {"kind": "opaque", "guard": guard(info), "mode": stat.S_IMODE(info.st_mode)}


def _state_relative(root):
    try:
        return STATE.relative_to(root).as_posix()
    except ValueError:
        return None


def _path_record(root, code, rel):
    """Hash one changed path; never read private, generated, symlink or special data."""
    if not rel or rel == "." or rel == ".git" or rel.startswith(".git/"):
        raise Blocked("Git returned an unsafe changed path")
    state_rel = _state_relative(root)
    if state_rel and (rel == state_rel or rel.startswith(state_rel + "/")):
        return None
    path = root / rel
    try:
        info = path.lstat()
    except FileNotFoundError:
        if private(rel):
            return {"code": code, "kind": "opaque", "reason": "private/runtime deletion"}
        return {"code": code, "kind": "deleted"}
    parts = set(Path(rel).parts)
    if code == "!!" and parts & GENERATED_DIRS:
        return None
    if stat.S_ISDIR(info.st_mode):
        if code == "!!" and (private(rel) or Path(rel).name in PRIVATE_DIRS):
            result = _opaque(path)
            result["reason"] = "private/runtime tree"
            return {"code": code, **result}
        if code == "!!":
            raise Blocked("ignored directory is not an approved generated/private tree: " + rel)
        return {"code": code, "kind": "directory", "guard": guard(info)}
    if code == "!!" and path.suffix.lower() in SOURCE_SUFFIXES:
        raise Blocked("ignored executable source is outside the evidence boundary: " + rel)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return {"code": code, "kind": "opaque", "guard": guard(info), "reason": "symlink/special"}
    if private(rel):
        result = _opaque(path)
        result["reason"] = "private/runtime file"
        return {"code": code, **result}
    if info.st_size > MAX_FILE:
        raise Blocked("changed file exceeds snapshot limit: " + rel)
    return {"code": code, "kind": "file", "mode": stat.S_IMODE(info.st_mode),
            "sha256": file_hash(path)}


def snapshot(root, boundary=None):
    """Snapshot Git state and only paths Git says are changed.

    This is the main latency change: the old toolkit recursively read every
    file in the repository.  Git already exposes the complete changed set, so
    clean source files are protected by HEAD/index and dirty files alone are
    freshly hashed.
    """
    before = git_state(root)
    files = {}
    for code, rel in _status_paths(root, boundary):
        record = _path_record(root, code, rel)
        if record is not None:
            files[rel] = record
    after = git_state(root)
    if before != after:
        raise Blocked("HEAD/index changed during snapshot")
    return {"git": after, "files": files}


def contains(spec, rel):
    return (rel == spec["path"] or spec["directory"] and
            (not spec["path"] or rel.startswith(spec["path"] + "/")))


def validate_path(project, root, text):
    raw = Path(text)
    if (not text or raw.is_absolute() or ".." in raw.parts or
            any(c in text for c in "*?[]{}\0") or ".git" in raw.parts):
        raise Blocked(f"invalid relative literal path: {text!r}")
    path = project / raw
    try:
        path.relative_to(root)
    except ValueError:
        raise Blocked(f"target is outside the Git root: {text}") from None
    for ancestor in [path, *path.parents]:
        if ancestor == root:
            break
        if ancestor.is_symlink():
            raise Blocked(f"symlink target: {text}")
    rel = path.relative_to(root).as_posix().rstrip("/")
    if rel == ".":
        rel = ""
    state_rel = STATE.relative_to(root).as_posix() if STATE.is_relative_to(root) else None
    if ((state_rel and (rel == state_rel or rel.startswith(state_rel + "/"))) or
            STATE in path.parents or private(rel) or path.name in PRIVATE_DIRS):
        raise Blocked(f"private/runtime target: {text}")
    if rel in ignored(root, [rel] if rel else []):
        raise Blocked(f"ignored target: {text}")
    if path.exists() and not (path.is_file() or path.is_dir()):
        raise Blocked(f"unsupported target: {text}")
    return {"path": rel, "directory": path.is_dir() or text.endswith("/") or text == "."}


def protections(project, root, extra):
    specs = [validate_path(project, root, item) for item in extra]
    # Protect this path even when it has not yet been created.
    specs.append({"path": (project / "tests/invariants").relative_to(root).as_posix(),
                  "directory": True})
    return sorted({canonical(x): x for x in specs}.values(), key=lambda x: x["path"])


def problems(plan, current):
    reasons, baseline = [], plan["baseline"]
    if current["git"] != baseline["git"]:
        reasons.append("initial HEAD/ref/index changed")
    for rel in sorted(baseline["files"].keys() | current["files"].keys()):
        old, new = baseline["files"].get(rel), current["files"].get(rel)
        if old == new:
            continue
        if any(contains(p, rel) for p in plan["protect"]) or "/tests/invariants/" in "/" + rel + "/":
            reasons.append("protected path changed: " + rel)
        elif any(x and x["kind"] in {"opaque", "unsupported"} for x in (old, new)):
            reasons.append("unsupported/private/runtime delta: " + rel)
        elif not any(contains(s, rel) for s in plan["scope"]):
            reasons.append("outside-scope delta (baseline dirty files included): " + rel)
    if plan["unknown"]:
        reasons.append("unresolved unknown claims: " + "; ".join(plan["unknown"]))
    return reasons


def load(path, key):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 << 20:
        raise Blocked(f"invalid task receipt: {path.name}")
    try:
        record = json.loads(path.read_bytes())
        payload = record["payload"]
        signature = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, record["mac"]) or payload["version"] != 1:
            raise ValueError("receipt integrity/version mismatch")
        return payload
    except (ValueError, KeyError, TypeError) as exc:
        raise Blocked(f"invalid task receipt: {path.name}") from exc


def save(path, payload, key):
    record = {"payload": payload, "mac": hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()}
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=STATE)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(record) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def state_guard(key, lock_fd):
    if STATE.is_symlink() or (STATE / ".lock").lstat().st_ino != os.fstat(lock_fd).st_ino:
        raise Blocked("state directory/lock changed")
    for path in STATE.iterdir():
        if path.is_symlink() or not path.is_file():
            raise Blocked(f"unsupported runtime state entry: {path.name}")
        if path.name in {".key", ".lock"}:
            continue
        if not re.fullmatch(r"task\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.json", path.name):
            raise Blocked(f"unexpected runtime state entry: {path.name}")
        load(path, key)  # No source/evidence file can acquire an exclusion by its name.
    if (STATE / ".key").read_bytes() != key:
        raise Blocked("receipt key changed")


@contextlib.contextmanager
def locked():
    if STATE.is_symlink():
        raise Blocked("state directory must not be a symlink")
    STATE.mkdir(mode=0o700, exist_ok=True)
    state_info = STATE.lstat()
    if not stat.S_ISDIR(state_info.st_mode) or stat.S_IMODE(state_info.st_mode) & 0o077:
        raise Blocked("toolkit state directory must be a private 0700 directory")
    fd = os.open(STATE / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        lock_info = os.fstat(fd)
        if not stat.S_ISREG(lock_info.st_mode) or stat.S_IMODE(lock_info.st_mode) & 0o077:
            raise Blocked("invalid state lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Blocked("another task operation holds the toolkit lock") from exc
        key_path = STATE / ".key"
        if not key_path.exists() and not key_path.is_symlink():
            key_fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(key_fd, "wb") as stream:
                stream.write(os.urandom(32))
                stream.flush()
                os.fsync(stream.fileno())
        key_info = key_path.lstat()
        if (key_path.is_symlink() or not stat.S_ISREG(key_info.st_mode) or
                stat.S_IMODE(key_info.st_mode) & 0o077 or key_info.st_size != 32):
            raise Blocked("invalid receipt key")
        key = key_path.read_bytes()
        state_guard(key, fd)
        yield key, fd
    finally:
        os.close(fd)


def check_argv(raw):
    try:
        argv = json.loads(raw)
    except ValueError as exc:
        raise Blocked("--check must be a JSON argv array") from exc
    if (not isinstance(argv, list) or not argv or len(argv) > 128 or
            not all(isinstance(s, str) and "\0" not in s and len(s) <= 8000 for s in argv)
            or not argv[0].strip()):
        raise Blocked("--check requires a nonempty JSON array of string arguments")
    if re.fullmatch(r"python(?:3(?:\.\d+)?)?", argv[0]):
        argv[0] = sys.executable
    executable = Path(argv[0]).name.lower()
    shell_flags = {"-c", "-command", "/c", "/command"}
    if executable in {"sh", "bash", "dash", "zsh", "fish", "ksh", "cmd", "powershell", "pwsh"} and any(
            item.lower() in shell_flags for item in argv[1:]):
        raise Blocked("shell-string checks are not supported; pass an executable argv directly")
    return argv


def identity(project, checks, env):
    executables = []
    for argv in checks:
        command = argv[0]
        found = str(project / command) if "/" in command else shutil.which(command, path=env.get("PATH"))
        if not found or not Path(found).is_file() or not os.access(found, os.X_OK):
            raise Blocked(f"check executable missing/not executable: {command}")
        path = Path(found).resolve(strict=True)
        executables.append({"requested": command, "path": str(path), "sha256": file_hash(path, 128 << 20)})
    python = Path(sys.executable).resolve()
    selected = {name: env.get(name, "") for name in (
        "PATH", "PYTHONPATH", "VIRTUAL_ENV", "CONDA_PREFIX", "PYTEST_ADDOPTS",
        "TRADING_MODE", "NODE_PATH", "JAVA_HOME", "RUSTUP_TOOLCHAIN", "GOPATH",
        "LANG", "LC_ALL")}
    return {"python": {"executable": sys.executable, "resolved": str(python),
                        "sha256": file_hash(python, 128 << 20), "version": sys.version,
                        "prefix": sys.prefix, "base_prefix": sys.base_prefix},
            "platform": platform.platform(), "executables": executables,
            "environment_sha256": digest(selected)}


def command_env(project):
    env = environment()
    env["PWD"] = str(project)
    return env


def run_check(argv, project, env, timeout, capture_limit=TAIL):
    """Drain both streams with bounded tails; kill the process group on timeout."""
    output = {name: {"bytes": 0, "tail": b"", "hash": hashlib.sha256()}
              for name in ("stdout", "stderr")}
    record = {"argv": argv, "cwd": str(project), "timeout_seconds": timeout,
              "exit_code": None, "timed_out": False}

    def drain(stream, target):
        try:
            for chunk in iter(lambda: stream.read(65536), b""):
                target["hash"].update(chunk)
                target["bytes"] += len(chunk)
                target["tail"] = (target["tail"] + chunk)[-capture_limit:]
        finally:
            stream.close()

    try:
        process = subprocess.Popen(argv, cwd=project, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   shell=False, start_new_session=True)
        threads = [threading.Thread(target=drain, args=(getattr(process, name), output[name]), daemon=True)
                   for name in output]
        for thread in threads:
            thread.start()
        try:
            record["exit_code"] = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
        if record["timed_out"]:
            # Only kill a group after a timeout; never signal a recycled group
            # after a normally completed check.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                record["exit_code"] = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                record["error"] = "process group did not exit after timeout"
        for thread in threads:
            thread.join(timeout=2)
        if any(thread.is_alive() for thread in threads):
            record["error"] = "output pipes still open; check descendants may have escaped the process group"
    except OSError as exc:
        record["error"] = str(exc)[:300]
    for name, result in output.items():
        record[name] = {"bytes": result["bytes"], "sha256": result["hash"].hexdigest(),
                        "tail": result["tail"].decode("utf-8", errors="replace")}
    if capture_limit > TAIL:
        record["_stdout_raw"] = output["stdout"]["tail"]
    return record


def report(task, state, reasons=(), **extra):
    return {"task": task, "state": state, "reasons": list(reasons), **extra}


def begin(args, project, root, key):
    scope = sorted({canonical(x): x for x in
                    (validate_path(project, root, p) for p in args.paths)}.values(), key=lambda x: x["path"])
    protect = protections(project, root, args.protect)
    for s in scope:
        if any(contains(p, s["path"]) or contains(s, p["path"]) for p in protect):
            raise Blocked("scope overlaps a protected path: " + s["path"])
    checks = [check_argv(raw) for raw in args.check]
    invariants = project / "tests/invariants"
    if invariants.exists():
        validate_path(project, root, "tests/invariants")
        required = [sys.executable, "-m", "pytest", "tests/invariants", "-q", "-p", "no:cacheprovider"]
        if required not in checks:
            checks.append(required)
    if not checks:
        raise Blocked("declare at least one --check (JSON argv); no implicit verification exists")
    if args.timeout < 1 or args.timeout > 3600:
        raise Blocked("timeout must be between 1 and 3600 seconds")
    configuration = {"version": 1, "project": str(project), "root": str(root), "scope": scope,
                     "protect": protect, "checks": checks, "timeout": args.timeout,
                     "unknown": sorted(set(args.unknown))}
    path = STATE / f"task.{args.task}.json"
    env_id = identity(project, checks, command_env(project))
    baseline = snapshot(root)
    if path.exists():
        previous = load(path, key)
        if (all(previous.get(k) == v for k, v in configuration.items()) and
                previous["baseline"] == baseline and previous["environment"] == env_id):
            return status(args.task, previous, baseline, env_id)
        raise Blocked("task already exists; begin only accepts unchanged identical input")
    for other_path in sorted(STATE.glob("task.*.json")):
        other = load(other_path, key)
        if other.get("closed") is True:
            continue  # closed receipts remain audit records, not reservations
        if other["root"] != str(root) or other["baseline"]["git"]["head"] != baseline["git"]["head"]:
            continue
        if any(contains(s, o["path"]) or contains(o, s["path"])
               for s in scope for o in other["scope"]):
            raise Blocked("overlapping task reservation: " + other_path.name[5:-5])
    plan = {**configuration, "baseline": baseline, "environment": env_id,
            "last": None, "closed": False}
    save(path, plan, key)
    return status(args.task, plan, baseline, env_id)


def status(task, plan, current, env_id):
    if plan.get("closed") is True:
        last = plan.get("last") or {}
        if last.get("post") == current and last.get("environment") == env_id:
            return report(task, "CLOSED", checks=len(last.get("runs", [])),
                          meaning="Archived receipt; checks passed, not correctness or review approval.")
        return report(task, "CLOSED_STALE", ["receipt was closed before the current worktree changed"])
    failures = problems(plan, current)
    last = plan["last"]
    if failures:
        return report(task, "BLOCKED", failures)
    if last is None:
        return report(task, "READY" if current == plan["baseline"] else "UNVERIFIED",
                      checks=len(plan["checks"]))
    if last.get("post") != current or last.get("environment") != env_id:
        return report(task, "STALE", ["snapshot or check environment differs from the latest attempt"])
    if last["state"] != "CHECKS_PASSED":
        return report(task, "BLOCKED", last.get("reasons") or ["verification incomplete/interrupted"])
    return report(task, "CHECKS_PASSED", checks=len(last["runs"]),
                  meaning="Recorded commands passed; not correctness or review approval.")


def close_task(args, plan, project, root, key):
    current = snapshot(root)
    env_id = identity(project, plan["checks"], command_env(project))
    if plan.get("closed") is True:
        return status(args.task, plan, current, env_id)
    if not plan.get("last") or plan["last"].get("state") != "CHECKS_PASSED":
        raise Blocked("only a fresh CHECKS_PASSED receipt can be closed")
    if plan["last"].get("post") != current or plan["last"].get("environment") != env_id:
        raise Blocked("receipt is stale; run verify again before closing")
    if problems(plan, current):
        raise Blocked("current worktree no longer matches the verified receipt")
    plan["closed"] = True
    save(STATE / f"task.{args.task}.json", plan, key)
    return status(args.task, plan, current, env_id)


def verify(args, plan, project, root, key, lock_fd):
    path, env = STATE / f"task.{args.task}.json", command_env(project)
    before, env_id = snapshot(root), identity(project, plan["checks"], env)
    failures = problems(plan, before)
    if failures:
        return report(args.task, "BLOCKED", failures)
    # Always replace a cached pass with a running receipt before executing.
    last = {"state": "RUNNING", "pre": before, "post": before,
            "environment": env_id, "runs": [], "reasons": []}
    plan["last"] = last
    save(path, plan, key)
    for argv in plan["checks"]:
        pre = snapshot(root)
        if pre != before or identity(project, plan["checks"], env) != env_id:
            last["reasons"].append("snapshot/environment changed before a check")
            break
        result = run_check(argv, project, env, plan["timeout"])
        try:
            post = snapshot(root)
        except Blocked as exc:
            post = pre
            result["snapshot_error"] = str(exc)
        result.update(environment=env_id, snapshot_pre=digest(pre), snapshot_post=digest(post))
        last["runs"].append(result)
        last["post"] = post
        if (result["exit_code"] != 0 or result["timed_out"] or result.get("error") or
                result.get("snapshot_error")):
            last["reasons"].append("check failed/timed out: " + json.dumps(argv))
        if pre != post or identity(project, plan["checks"], env) != env_id:
            last["reasons"].append("check changed watched files, HEAD/index, or executable identity")
        last["reasons"].extend(problems(plan, post))
        state_guard(key, lock_fd)
        save(path, plan, key)
        if last["reasons"]:
            break
    if len(last["runs"]) != len(plan["checks"]):
        last["reasons"].append("not all planned checks completed")
    last["state"] = "BLOCKED" if last["reasons"] else "CHECKS_PASSED"
    state_guard(key, lock_fd)
    save(path, plan, key)
    return status(args.task, plan, snapshot(root), identity(project, plan["checks"], env))


def project_and_root(value):
    project = Path(value or Path.cwd()).absolute()
    if not project.exists() or not project.is_dir():
        raise Blocked("project directory does not exist: " + str(project))
    if any(path.is_symlink() for path in (project, *project.parents)):
        raise Blocked("project path may not contain symlinks")
    raw = git(project, "rev-parse", "--show-toplevel")
    root = Path(raw.decode().strip()).absolute()
    try:
        project.relative_to(root)
    except ValueError:
        raise Blocked("project is not inside its Git root") from None
    return project, root


def load_plan(task, key):
    if not NAME.fullmatch(task):
        raise Blocked("invalid task name")
    path = STATE / f"task.{task}.json"
    if not path.exists():
        raise Blocked("task does not exist: " + task)
    return path, load(path, key)


def plan_project(plan, requested):
    stored = Path(plan["project"])
    if requested is not None and Path(requested).absolute() != stored:
        raise Blocked("requested project differs from the task receipt")
    project, root = project_and_root(stored)
    if str(project) != plan["project"] or str(root) != plan["root"]:
        raise Blocked("repository/project identity changed")
    return project, root


def output(value, pretty=False):
    print(json.dumps(value, sort_keys=True, indent=2 if pretty else None,
                     separators=None if pretty else (",", ":")))


def command_probe(args, project):
    """Compatibility probe: exact stdout, bounded, no shell."""
    script = Path(args.script)
    if not script.is_absolute():
        script = project / script
    if not script.is_file() or script.is_symlink():
        raise Blocked("probe script must be a regular local file")
    try:
        script.relative_to(project)
    except ValueError:
        raise Blocked("probe script must be inside the project") from None
    if any(parent.is_symlink() for parent in (script, *script.parents) if parent != project):
        raise Blocked("probe script may not traverse a symlink")
    script_rel = script.relative_to(project).as_posix()
    if private(script_rel) or script_rel.startswith(".git/"):
        raise Blocked("probe script is private/runtime data")
    result = run_check([args.python or sys.executable, str(script)], project,
                       command_env(project), args.timeout, capture_limit=MAX_FILE)
    if result["timed_out"] or result.get("error") or result["exit_code"] != 0:
        raise Blocked("probe failed: " + json.dumps(result, sort_keys=True))
    output_bytes = result.pop("_stdout_raw").replace(b"\r", b"")
    if result["stdout"]["bytes"] > MAX_FILE:
        raise Blocked("probe stdout exceeds the bounded artifact limit")
    destination = args.baseline or args.verify_path
    if not destination:
        return report("probe", "CHECKS_PASSED", stdout_sha256=result["stdout"]["sha256"])
    target = Path(destination)
    if not target.is_absolute():
        target = project / target
    try:
        target.relative_to(project)
    except ValueError:
        raise Blocked("probe artifact must remain inside the project") from None
    if any(parent.is_symlink() for parent in (target, *target.parents) if parent != project):
        raise Blocked("probe artifact may not traverse a symlink")
    if args.baseline:
        if target.exists() and target.is_symlink():
            raise Blocked("probe baseline may not be a symlink")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(output_bytes)
        return report("probe", "BASELINE_SAVED", path=str(target.relative_to(project)))
    if not target.is_file() or target.read_bytes() != output_bytes:
        return report("probe", "BLOCKED", ["probe output changed"], path=str(target))
    return report("probe", "CHECKS_PASSED", path=str(target),
                  stdout_sha256=result["stdout"]["sha256"])


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pretty", action="store_true", help="format JSON for a human")
    subs = parser.add_subparsers(dest="command", required=True)

    begin_parser = subs.add_parser("begin", help="reserve paths and record a baseline")
    begin_parser.add_argument("--task", required=True)
    begin_parser.add_argument("--project", type=Path)
    begin_parser.add_argument("--check", action="append", default=[],
                              help="JSON argv array; repeat for independent checks")
    begin_parser.add_argument("--protect", action="append", default=[])
    begin_parser.add_argument("--unknown", action="append", default=[])
    begin_parser.add_argument("--timeout", type=int, default=300)
    begin_parser.add_argument("paths", nargs="+")

    for name in ("verify", "status", "close"):
        sub = subs.add_parser(name, help=f"{name} a task receipt")
        sub.add_argument("--task", required=True)
        sub.add_argument("--project", type=Path)

    listing = subs.add_parser("list", help="list local task receipts")
    listing.add_argument("--project", type=Path)

    inspect = subs.add_parser("inspect", help="bounded lazy repository context")
    inspect.add_argument("--project", type=Path)
    inspect.add_argument("--history", action="store_true")
    inspect.add_argument("--symbol")
    inspect.add_argument("--limit", type=int, default=8)
    inspect.add_argument("paths", nargs="*")

    probe = subs.add_parser("probe", help="run a legacy deterministic stdout probe")
    probe.add_argument("--project", type=Path)
    probe.add_argument("--script", required=True)
    probe.add_argument("--baseline")
    probe.add_argument("--verify", dest="verify_path")
    probe.add_argument("--python")
    probe.add_argument("--timeout", type=int, default=300)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "timeout", 300) < 1 or getattr(args, "timeout", 300) > 3600:
        output(report("tool", "BLOCKED", ["timeout must be between 1 and 3600 seconds"]), args.pretty)
        return 2
    try:
        if args.command == "inspect":
            project, _ = project_and_root(args.project)
            spec = importlib.util.spec_from_file_location("agentussage_context", TOOLKIT / "context.py")
            module = importlib.util.module_from_spec(spec)
            assert spec and spec.loader
            spec.loader.exec_module(module)
            result = module.inspect_context(project, args.paths, history=args.history,
                                            symbol=args.symbol, limit=args.limit)
            output(result, args.pretty)
            return 2 if result["errors"] else 0

        if args.command == "probe":
            project, _ = project_and_root(args.project)
            if args.baseline and args.verify_path:
                raise Blocked("probe accepts only --baseline or --verify")
            result = command_probe(args, project)
            output(result, args.pretty)
            return 0 if result["state"] != "BLOCKED" else 1

        with locked() as (key, lock_fd):
            if args.command == "begin":
                if not NAME.fullmatch(args.task):
                    raise Blocked("invalid task name")
                project, root = project_and_root(args.project)
                result = begin(args, project, root, key)
            elif args.command in {"verify", "status", "close"}:
                _, plan = load_plan(args.task, key)
                project, root = plan_project(plan, args.project)
                if args.command == "verify":
                    result = verify(args, plan, project, root, key, lock_fd)
                elif args.command == "close":
                    result = close_task(args, plan, project, root, key)
                else:
                    current = snapshot(root)
                    env_id = identity(project, plan["checks"], command_env(project))
                    result = status(args.task, plan, current, env_id)
            else:  # list
                project, root = project_and_root(args.project)
                rows = []
                for path in sorted(STATE.glob("task.*.json")):
                    task = path.name[5:-5]
                    plan = load(path, key)
                    if (plan.get("root") == str(root) and
                            (args.project is None or plan.get("project") == str(project))):
                        rows.append({"task": task,
                                     "state": (plan.get("last") or {}).get("state", "READY"),
                                     "scope": plan.get("scope", [])})
                result = {"state": "READY", "tasks": rows}
        output(result, args.pretty)
        return 0 if result.get("state") not in {"BLOCKED", "STALE", "CLOSED_STALE"} else 1
    except (Blocked, OSError, ValueError, RuntimeError, KeyError) as exc:
        output(report(getattr(args, "task", "tool"), "BLOCKED", [str(exc)]), args.pretty)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
