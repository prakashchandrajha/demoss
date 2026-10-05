#!/usr/bin/env python3
"""Legacy structural change-capsule API.

This module is retained for callers and older capsule fixtures. It checks
capsule structure, paths, hashes and declared fields, but it cannot establish
that a named verifier actually ran a command or that a text artifact is
independent. Its historical ``ok`` result is therefore a *structural pass*,
never approval to merge and never a substitute for ``agent.py verify``.

The generated capsule has this shape (all paths are repository-relative when
possible)::

    {
      "schema_version": "1.0",
      "change_id": "...", "author": "...", "risk": "low",
      "base": {"ref": "HEAD", "commit": "...", "tree": "..."},
      "scope": ["src/**"],
      "metadata": {
        "capsule_path": "capsules/change.json",
        "evidence_path": null,
        "paths": ["capsules/change.json"]
      },
      "candidate": {"digest_algorithm": "sha256-v1",
                    "worktree_digest": "..."},
      "contract": {"preserve": [], "allowed_changes": [],
                   "unknowns": ["UNRESOLVED: ..."]},
      "evidence": {"status": "PENDING", "independent": false,
                   "verifier": "", "domain": "", "command": "",
                   "artifact": {"path": null, "sha256": ""}},
      "effects": {"read_only": true, "sandboxed": true,
                   "transactional": true, "external_writes": false},
      "rollback": {"strategy": "", "verified": false}
    }

Only the standard library is used. Git is invoked with argument lists and
never through a shell. ``verify`` only reads the worktree and the declared
evidence artifact; it never executes the evidence command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence


SCHEMA_VERSION = "1.0"
DIGEST_ALGORITHM = "sha256-v1"
RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})
HASH_RE = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
UNRESOLVED_RE = re.compile(
    r"(?:unresolved|unknown|tbd|todo|not\s+reviewed|pending)", re.IGNORECASE
)
SOURCE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".go",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".py",
        ".pyi",
        ".rs",
        ".sql",
        ".ts",
        ".tsx",
    }
)
IGNORED_GENERATED_PARTS = frozenset(
    {"__pycache__", ".venv", ".venv_test", "build", "dist", "node_modules"}
)


class AirlockError(Exception):
    """An expected, reportable airlock failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _error_report(code: str, message: str, capsule: Optional[str] = None) -> dict[str, Any]:
    """Build a structured report for errors occurring before verification."""

    failure = {"code": code, "message": message}
    result: dict[str, Any] = {
        "ok": False,
        "approval": False,
        "trust": "structural-only",
        "failure_codes": [code],
        "failures": [failure],
        "checks": {},
    }
    if capsule is not None:
        result["capsule"] = capsule
    return result


class _Report:
    """Accumulate checks without allowing one malformed field to abort verify."""

    def __init__(self, capsule: str):
        self.capsule = capsule
        self.checks: dict[str, dict[str, Any]] = {}
        self.failures: list[dict[str, str]] = []

    def check(self, name: str, passed: bool, detail: str = "") -> None:
        entry = self.checks.setdefault(name, {"passed": True})
        if not passed:
            entry["passed"] = False
            if detail:
                entry["message"] = detail
        elif detail and "message" not in entry:
            entry["message"] = detail

    def fail(self, code: str, message: str, check: str) -> None:
        self.check(check, False, message)
        self.failures.append({"code": code, "message": message})

    def finish(self) -> dict[str, Any]:
        codes: list[str] = []
        for failure in self.failures:
            if failure["code"] not in codes:
                codes.append(failure["code"])
        return {
            "ok": not self.failures,
            "approval": False,
            "trust": "structural-only",
            "decision": "STRUCTURAL_PASS_NOT_APPROVAL" if not self.failures else "BLOCKED",
            "capsule": self.capsule,
            "failure_codes": codes,
            "failures": self.failures,
            "checks": self.checks,
        }


def _decode_git(data: bytes) -> str:
    return data.decode("utf-8", "surrogateescape")


def _git_error(stderr: bytes, fallback: str) -> str:
    text = _decode_git(stderr).strip().replace("\x00", " ")
    if not text:
        return fallback
    return text.splitlines()[0][:400]


def _run_git(repo_root: str, args: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    """Run Git without a shell and return the raw result."""

    try:
        return subprocess.run(
            ["git", *[str(arg) for arg in args]],
            cwd=repo_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except (OSError, ValueError) as exc:
        raise AirlockError("GIT_UNAVAILABLE", f"could not run git: {exc}") from exc


def _git_output(repo_root: str, args: Sequence[str]) -> bytes:
    result = _run_git(repo_root, args)
    if result.returncode != 0:
        raise AirlockError(
            "GIT_COMMAND_FAILED",
            _git_error(result.stderr, f"git {' '.join(args)} failed"),
        )
    return result.stdout


def find_repo_root(cwd: Optional[os.PathLike[str] | str] = None) -> str:
    """Return the top-level directory of the Git worktree containing *cwd*."""

    start = os.path.abspath(os.fspath(cwd or os.getcwd()))
    output = _git_output(start, ["rev-parse", "--show-toplevel"])
    root = _decode_git(output).strip()
    if not root:
        raise AirlockError("REPOSITORY_NOT_FOUND", "git returned an empty worktree root")
    return os.path.abspath(root)


def _validate_string(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise AirlockError("TYPE_INVALID", f"{field} must be a string")
    if "\x00" in value:
        raise AirlockError("NUL_BYTE", f"{field} contains a NUL byte")
    if not allow_empty and not value.strip():
        raise AirlockError("VALUE_EMPTY", f"{field} must not be empty")
    return value


def _inside_root(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:
        return False


def _relative_path(path: str, root: str) -> Optional[str]:
    """Convert an absolute path to a normalized repository-relative path."""

    absolute = os.path.abspath(path)
    root_abs = os.path.abspath(root)
    if not _inside_root(absolute, root_abs):
        return None
    relative = os.path.relpath(absolute, root_abs)
    if relative == ".":
        return None
    return relative.replace(os.sep, "/")


def _reject_git_path(relative: str, field: str) -> None:
    if relative == ".git" or relative.startswith(".git/"):
        raise AirlockError("GIT_PATH_FORBIDDEN", f"{field} may not refer to .git")


def _normalize_relative_path(value: str, root: str, field: str) -> str:
    """Normalize a repository-relative path and reject lexical escapes."""

    _validate_string(value, field)
    if value.startswith("/") or os.path.isabs(value):
        raise AirlockError("PATH_ABSOLUTE", f"{field} must be repository-relative")
    raw = value.replace("\\", "/")
    normalized = posixpath.normpath(raw)
    if normalized in {"", "."} or normalized == ".." or normalized.startswith("../"):
        raise AirlockError("PATH_ESCAPE", f"{field} escapes the repository: {value!r}")
    _reject_git_path(normalized, field)
    absolute = os.path.abspath(os.path.join(root, *normalized.split("/")))
    if not _inside_root(absolute, root):
        raise AirlockError("PATH_ESCAPE", f"{field} escapes the repository: {value!r}")
    return normalized


def _normalize_metadata_path(value: Any, root: str, field: str = "metadata path") -> str:
    """Normalize a metadata path.

    Relative paths are repository-relative and may not escape.  Absolute
    metadata paths are retained when outside the repository because an output
    capsule may intentionally live elsewhere; they never contribute to the
    worktree digest.
    """

    text = _validate_string(value, field)
    if os.path.isabs(text):
        absolute = os.path.abspath(text)
        relative = _relative_path(absolute, root)
        if relative is not None:
            _reject_git_path(relative, field)
            return relative
        return absolute
    return _normalize_relative_path(text, root, field)


def _metadata_record_path(absolute_path: str, root: str) -> str:
    relative = _relative_path(absolute_path, root)
    if relative is not None:
        _reject_git_path(relative, "capsule metadata path")
        return relative
    return os.path.abspath(absolute_path)


def _path_bytes(relative: str) -> bytes:
    return os.fsencode(relative)


def _git_path_list(repo_root: str, args: Sequence[str]) -> list[str]:
    data = _git_output(repo_root, args)
    result: list[str] = []
    seen: set[str] = set()
    for raw in data.split(b"\0"):
        if not raw:
            continue
        value = _decode_git(raw).replace("\\", "/")
        normalized = posixpath.normpath(value)
        if normalized in {"", "."} or normalized == ".." or normalized.startswith("../"):
            raise AirlockError("GIT_PATH_INVALID", f"git returned an unsafe path: {value!r}")
        if normalized.startswith("/"):
            raise AirlockError("GIT_PATH_INVALID", f"git returned an absolute path: {value!r}")
        if normalized == ".git" or normalized.startswith(".git/"):
            continue
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    return result


def _tracked_and_unignored_files(repo_root: str) -> list[str]:
    tracked = _git_path_list(repo_root, ["ls-files", "--cached", "-z", "--"])
    untracked = _git_path_list(
        repo_root,
        ["ls-files", "--others", "--exclude-standard", "-z", "--"],
    )
    result: list[str] = []
    seen: set[str] = set()
    for path in [*tracked, *untracked]:
        if path not in seen:
            result.append(path)
            seen.add(path)
    return result


def _ignored_source_files(repo_root: str) -> list[str]:
    """Find ignored source-like files that Git would otherwise hide.

    Ignored logs, credentials, caches and databases are intentionally not read.
    An ignored Python/JS/etc. source file is different: excluding it from the
    evidence surface would let a refactor change executable logic without any
    Git or digest witness.  The airlock therefore fails closed on these paths.
    """

    ignored = _git_path_list(
        repo_root,
        ["ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--"],
    )
    source_files: list[str] = []
    for path in ignored:
        parts = set(path.split("/"))
        if parts & IGNORED_GENERATED_PARTS:
            continue
        if Path(path).suffix.lower() in SOURCE_SUFFIXES:
            source_files.append(path)
    return sorted(source_files, key=_path_bytes)


def _digest_one_file(hasher: Any, absolute: str, relative: str) -> None:
    """Add one file's path, mode and bytes to a digest stream."""

    path_bytes = _path_bytes(relative)
    try:
        file_stat = os.lstat(absolute)
    except FileNotFoundError:
        # A tracked deletion is represented explicitly, so deleting a file
        # cannot accidentally collide with a worktree that never listed it.
        file_stat = None

    mode = 0 if file_stat is None else file_stat.st_mode
    hasher.update(struct.pack(">Q", len(path_bytes)))
    hasher.update(path_bytes)
    hasher.update(struct.pack(">Q", mode))

    if file_stat is None:
        hasher.update(struct.pack(">Q", 0))
        return

    if stat.S_ISLNK(file_stat.st_mode):
        data = os.fsencode(os.readlink(absolute))
        hasher.update(struct.pack(">Q", len(data)))
        hasher.update(data)
        return

    if stat.S_ISREG(file_stat.st_mode):
        expected_size = file_stat.st_size
        hasher.update(struct.pack(">Q", expected_size))
        read_size = 0
        try:
            with open(absolute, "rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    read_size += len(chunk)
        except OSError as exc:
            raise AirlockError("DIGEST_READ_FAILED", f"could not read {relative}: {exc}") from exc
        if read_size != expected_size:
            raise AirlockError("DIGEST_RACE", f"file changed while hashing: {relative}")
        try:
            after = os.lstat(absolute)
        except FileNotFoundError as exc:
            raise AirlockError("DIGEST_RACE", f"file disappeared while hashing: {relative}") from exc
        if after.st_mode != file_stat.st_mode or after.st_size != expected_size:
            raise AirlockError("DIGEST_RACE", f"file changed while hashing: {relative}")
        return

    if stat.S_ISDIR(file_stat.st_mode):
        # Git submodules can be represented by a directory in the worktree.
        hasher.update(struct.pack(">Q", 0))
        return

    raise AirlockError("DIGEST_UNSAFE_FILE", f"cannot hash special file: {relative}")


def _exclusion_rel_paths(repo_root: str, exclude_paths: Iterable[Any]) -> set[str]:
    exclusions: set[str] = set()
    for value in exclude_paths:
        text = _validate_string(value, "digest exclusion path")
        if os.path.isabs(text):
            relative = _relative_path(os.path.abspath(text), repo_root)
            if relative is None:
                continue
            _reject_git_path(relative, "digest exclusion path")
            exclusions.add(relative)
        else:
            exclusions.add(_normalize_relative_path(text, repo_root, "digest exclusion path"))
    return exclusions


def compute_worktree_digest(
    repo_root: os.PathLike[str] | str,
    exclude_paths: Iterable[Any] = (),
) -> str:
    """Return the deterministic digest of tracked/unignored worktree files.

    Each record contains a normalized path, the complete ``st_mode`` value,
    and the file bytes (or symlink target bytes).  Records are sorted by raw
    path bytes and framed with lengths before being fed to SHA-256.  Only the
    supplied metadata paths are excluded; ``.git`` is always excluded.
    """

    root = os.path.abspath(os.fspath(repo_root))
    exclusions = _exclusion_rel_paths(root, exclude_paths)
    files = _tracked_and_unignored_files(root)
    hasher = hashlib.sha256()
    hasher.update(DIGEST_ALGORITHM.encode("ascii"))
    hasher.update(b"\0")
    for relative in sorted(files, key=_path_bytes):
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if relative in exclusions:
            continue
        absolute = os.path.join(root, *relative.split("/"))
        _digest_one_file(hasher, absolute, relative)
    return hasher.hexdigest()


# A short alias is convenient for callers that use the term from the capsule.
worktree_digest = compute_worktree_digest


def _changed_paths(repo_root: str, base_commit: str) -> list[str]:
    tracked = _git_path_list(
        repo_root,
        ["diff", "--name-only", "--no-renames", "-z", base_commit, "--"],
    )
    untracked = _git_path_list(
        repo_root,
        ["ls-files", "--others", "--exclude-standard", "-z", "--"],
    )
    result: list[str] = []
    seen: set[str] = set()
    for path in [*tracked, *untracked]:
        if path not in seen:
            result.append(path)
            seen.add(path)
    return result


def _resolve_commit(repo_root: str, ref: str) -> str:
    ref = _validate_string(ref, "base ref")
    if ref.startswith("-"):
        raise AirlockError("REF_INVALID", "base ref may not start with '-'")
    output = _git_output(repo_root, ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"])
    commit = _decode_git(output).strip()
    if not HASH_RE.fullmatch(commit):
        raise AirlockError("BASE_COMMIT_INVALID", "git did not return a full commit hash")
    return commit.lower()


def _resolve_tree(repo_root: str, commit: str) -> str:
    output = _git_output(repo_root, ["rev-parse", "--verify", "--quiet", f"{commit}^{{tree}}"])
    tree = _decode_git(output).strip()
    if not HASH_RE.fullmatch(tree):
        raise AirlockError("BASE_TREE_INVALID", "git did not return a full tree hash")
    return tree.lower()


def _atomic_write_json(path: str, value: Mapping[str, Any]) -> None:
    parent = os.path.dirname(path) or os.curdir
    try:
        os.makedirs(parent, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".semantic-airlock-", suffix=".tmp", dir=parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(value, handle, ensure_ascii=True, indent=2, sort_keys=True)
                handle.write("\n")
            os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    except (OSError, TypeError, ValueError) as exc:
        raise AirlockError("CAPSULE_WRITE_FAILED", f"could not write capsule {path}: {exc}") from exc


def init_capsule(
    *,
    base: str,
    output: os.PathLike[str] | str,
    scope: Sequence[str],
    risk: str,
    author: str,
    change_id: str,
    cwd: Optional[os.PathLike[str] | str] = None,
) -> dict[str, Any]:
    """Create and write a deliberately non-passing change capsule."""

    working_dir = os.path.abspath(os.fspath(cwd or os.getcwd()))
    root = find_repo_root(working_dir)
    base_ref = _validate_string(base, "base ref")
    if base_ref.startswith("-"):
        raise AirlockError("REF_INVALID", "base ref may not start with '-'")
    if not isinstance(scope, Sequence) or isinstance(scope, (str, bytes)) or not scope:
        raise AirlockError("SCOPE_INVALID", "scope must contain at least one pattern")
    normalized_scope: list[str] = []
    for index, pattern in enumerate(scope):
        pattern_text = _validate_string(pattern, f"scope[{index}]")
        normalized_scope.append(_normalize_scope_pattern(pattern_text, root, f"scope[{index}]"))
    risk = _validate_string(risk, "risk")
    if risk not in RISK_LEVELS:
        raise AirlockError("RISK_INVALID", f"risk must be one of: {', '.join(sorted(RISK_LEVELS))}")
    author = _validate_string(author, "author")
    change_id = _validate_string(change_id, "change_id")

    commit = _resolve_commit(root, base_ref)
    tree = _resolve_tree(root, commit)

    output_text = _validate_string(os.fspath(output), "output")
    output_absolute = (
        os.path.abspath(output_text)
        if os.path.isabs(output_text)
        else os.path.abspath(os.path.join(working_dir, output_text))
    )
    capsule_path = _metadata_record_path(output_absolute, root)
    digest = compute_worktree_digest(root, [capsule_path])

    capsule: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "semantic-airlock.change-capsule",
        "change_id": change_id,
        "author": author,
        "risk": risk,
        "base": {"ref": base_ref, "commit": commit, "tree": tree},
        "scope": normalized_scope,
        "metadata": {
            "capsule_path": capsule_path,
            "evidence_path": None,
            "paths": [capsule_path],
        },
        "candidate": {
            "digest_algorithm": DIGEST_ALGORITHM,
            "worktree_digest": digest,
        },
        "contract": {
            "preserve": [],
            "allowed_changes": [],
            "unknowns": ["UNRESOLVED: contract has not been reviewed"],
        },
        "evidence": {
            "status": "PENDING",
            "independent": False,
            "verifier": "",
            "domain": "",
            "command": "",
            "artifact": {"path": None, "sha256": ""},
        },
        "effects": {
            "read_only": True,
            "sandboxed": True,
            "transactional": True,
            "external_writes": False,
        },
        "rollback": {"strategy": "", "verified": False},
    }
    _atomic_write_json(output_absolute, capsule)
    return capsule


def _load_json_object(path: str) -> dict[str, Any]:
    def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle, object_pairs_hook=no_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise AirlockError("CAPSULE_JSON_INVALID", f"could not read JSON capsule {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AirlockError("CAPSULE_NOT_OBJECT", "capsule JSON root must be an object")
    return value


def _normalize_scope_pattern(value: str, root: str, field: str) -> str:
    _validate_string(value, field)
    if value == "GLOBAL":
        return value
    if os.path.isabs(value) or value.startswith("/"):
        raise AirlockError("SCOPE_PATTERN_INVALID", f"{field} must be relative or GLOBAL")
    pattern = value.replace("\\", "/")
    # A glob may contain '..', but it must not be able to name a path outside
    # the repository.  Reject the segment rather than trying to interpret it.
    segments = pattern.split("/")
    if any(segment == ".." for segment in segments):
        raise AirlockError("SCOPE_PATTERN_ESCAPE", f"{field} escapes the repository")
    normalized = posixpath.normpath(pattern)
    if normalized in {"", "."}:
        raise AirlockError("SCOPE_PATTERN_INVALID", f"{field} is empty")
    _reject_git_path(normalized, field)
    # Keep root in the signature so callers cannot accidentally pass a path
    # from another worktree while changing this helper's contract.
    del root
    return normalized


def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile a small slash-aware glob supporting ``**``."""

    pieces: list[str] = ["^"]
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    pieces.append("(?:.*/)?")
                    index += 1
                else:
                    pieces.append(".*")
                continue
            pieces.append("[^/]*")
        elif character == "?":
            pieces.append("[^/]")
        elif character == "[":
            end = pattern.find("]", index + 1)
            if end != -1:
                content = pattern[index + 1 : end]
                if content.startswith("!"):
                    content = "^" + content[1:]
                pieces.append("[" + content + "]")
                index = end
            else:
                pieces.append(r"\[")
        else:
            pieces.append(re.escape(character))
        index += 1
    pieces.append("$")
    return re.compile("".join(pieces))


def _scope_matches(path: str, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        if pattern == "GLOBAL" or pattern == path:
            return True
        if any(character in pattern for character in "*?[") and _glob_regex(pattern).fullmatch(path):
            return True
    return False


def _alias_value(
    primary: Any,
    alias: Any,
    *,
    primary_name: str,
    alias_name: str,
    report: _Report,
    check: str,
) -> Any:
    if primary is not None and alias is not None and primary != alias:
        report.fail(
            "FIELD_CONFLICT",
            f"{primary_name} conflicts with {alias_name}",
            check,
        )
    return primary if primary is not None else alias


def _hash_string(value: Any, field: str, report: _Report, check: str) -> Optional[str]:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        report.fail("HASH_INVALID", f"{field} must be a full hexadecimal Git hash", check)
        return None
    return value.lower()


def _read_artifact_fields(evidence: Mapping[str, Any]) -> tuple[Any, Any]:
    artifact = evidence.get("artifact")
    if isinstance(artifact, Mapping):
        path = artifact.get("path")
        digest = artifact.get("sha256")
    elif artifact is not None:
        path = artifact
        digest = evidence.get("artifact_sha256")
    else:
        path = evidence.get("artifact_path")
        digest = evidence.get("artifact_sha256")
    if path is None and "artifact_path" in evidence:
        path = evidence.get("artifact_path")
    if digest is None and "artifact_sha256" in evidence:
        digest = evidence.get("artifact_sha256")
    return path, digest


def _normalize_artifact_path(value: Any, root: str) -> tuple[str, str]:
    text = _validate_string(value, "evidence artifact path")
    if os.path.isabs(text):
        absolute = os.path.abspath(text)
        relative = _relative_path(absolute, root)
        if relative is None:
            raise AirlockError(
                "ARTIFACT_PATH_ESCAPE",
                "evidence artifact must be inside the current repository",
            )
    else:
        relative = _normalize_relative_path(text, root, "evidence artifact path")
        absolute = os.path.abspath(os.path.join(root, *relative.split("/")))
    # Do not follow a repository symlink out of the repository while reading.
    real = os.path.realpath(absolute)
    if not _inside_root(real, os.path.realpath(root)):
        raise AirlockError("ARTIFACT_PATH_ESCAPE", "evidence artifact resolves outside the repository")
    return relative, absolute


def _sha256_file(path: str) -> str:
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
    except OSError as exc:
        raise AirlockError("ARTIFACT_READ_FAILED", f"could not read evidence artifact: {exc}") from exc
    return hasher.hexdigest()


def verify_capsule(
    capsule_path: os.PathLike[str] | str,
    *,
    cwd: Optional[os.PathLike[str] | str] = None,
) -> dict[str, Any]:
    """Verify a capsule and return a JSON-serializable report.

    This function is intentionally total for ordinary input: malformed JSON,
    unsafe paths, Git failures and filesystem races become structured failure
    codes instead of tracebacks.
    """

    try:
        capsule_text = _validate_string(os.fspath(capsule_path), "capsule path")
        base_cwd = os.path.abspath(os.fspath(cwd or os.getcwd()))
        capsule_absolute = os.path.abspath(os.path.join(base_cwd, capsule_text))
    except (AirlockError, TypeError, ValueError) as exc:
        code = exc.code if isinstance(exc, AirlockError) else "CAPSULE_PATH_INVALID"
        message = exc.message if isinstance(exc, AirlockError) else str(exc)
        return _error_report(code, message, str(capsule_path))

    report = _Report(capsule_absolute)
    try:
        root = find_repo_root(base_cwd)
    except AirlockError as exc:
        report.fail(exc.code, exc.message, "repository")
        return report.finish()

    ignored_source_ok = True
    try:
        ignored_source_files = _ignored_source_files(root)
        if ignored_source_files:
            report.fail(
                "IGNORED_SOURCE_FILE",
                "Git ignores executable source files; make them tracked before merging: "
                + ", ".join(ignored_source_files[:50]),
                "ignored_source",
            )
            ignored_source_ok = False
    except AirlockError as exc:
        report.fail(exc.code, exc.message, "ignored_source")
        ignored_source_ok = False
    report.check("ignored_source", ignored_source_ok)

    try:
        capsule = _load_json_object(capsule_absolute)
    except AirlockError as exc:
        report.fail(exc.code, exc.message, "capsule")
        return report.finish()

    # Schema and top-level type checks.
    schema_ok = True
    schema_version = capsule.get("schema_version")
    valid_schema_versions = {SCHEMA_VERSION, "1", 1}
    if isinstance(schema_version, bool) or schema_version not in valid_schema_versions:
        report.fail("SCHEMA_VERSION_INVALID", "unsupported or missing schema_version", "schema")
        schema_ok = False
    for field in (
        "kind",
        "change_id",
        "author",
        "risk",
        "base",
        "scope",
        "metadata",
        "candidate",
        "contract",
        "evidence",
        "effects",
        "rollback",
    ):
        if field not in capsule:
            report.fail("FIELD_MISSING", f"capsule is missing required field: {field}", "schema")
            schema_ok = False
    if "kind" in capsule and capsule.get("kind") != "semantic-airlock.change-capsule":
        report.fail(
            "KIND_INVALID",
            "kind must be semantic-airlock.change-capsule",
            "schema",
        )
        schema_ok = False
    for field in ("change_id", "author", "risk"):
        if field in capsule and (not isinstance(capsule[field], str) or not capsule[field].strip()):
            report.fail("FIELD_TYPE_INVALID", f"{field} must be a non-empty string", "schema")
            schema_ok = False
    if isinstance(capsule.get("risk"), str) and capsule["risk"] not in RISK_LEVELS:
        report.fail("RISK_INVALID", f"risk must be one of: {', '.join(sorted(RISK_LEVELS))}", "schema")
        schema_ok = False
    report.check("schema", schema_ok)

    # Resolve the canonical base fields, while accepting the simple aliases
    # used by older callers.
    base_obj = capsule.get("base")
    if not isinstance(base_obj, Mapping):
        report.fail("BASE_INVALID", "base must be an object", "base")
        base_obj = {}
    base_commit_raw = _alias_value(
        base_obj.get("commit"),
        capsule.get("base_commit"),
        primary_name="base.commit",
        alias_name="base_commit",
        report=report,
        check="base",
    )
    base_tree_raw = _alias_value(
        base_obj.get("tree"),
        capsule.get("base_tree"),
        primary_name="base.tree",
        alias_name="base_tree",
        report=report,
        check="base",
    )
    base_commit = _hash_string(base_commit_raw, "base.commit", report, "base")
    base_tree = _hash_string(base_tree_raw, "base.tree", report, "base")
    if "ref" in base_obj and (not isinstance(base_obj.get("ref"), str) or not base_obj["ref"].strip()):
        report.fail("BASE_REF_INVALID", "base.ref must be a non-empty string", "base")

    base_gate_ok = base_commit is not None and base_tree is not None
    if base_gate_ok:
        try:
            resolved_commit = _resolve_commit(root, base_commit)
            if resolved_commit != base_commit:
                report.fail("BASE_COMMIT_MISMATCH", "recorded base commit does not resolve to itself", "base")
                base_gate_ok = False
        except AirlockError as exc:
            report.fail("BASE_COMMIT_MISSING", f"base commit is unavailable: {exc.message}", "base")
            base_gate_ok = False
        if base_gate_ok:
            try:
                resolved_tree = _resolve_tree(root, base_commit)
                if resolved_tree != base_tree:
                    report.fail("BASE_TREE_MISMATCH", "recorded base tree hash does not match Git", "base")
                    base_gate_ok = False
            except AirlockError as exc:
                report.fail("BASE_TREE_MISSING", f"base tree is unavailable: {exc.message}", "base")
                base_gate_ok = False
        if base_gate_ok:
            try:
                head = _resolve_commit(root, "HEAD")
                ancestor_result = _run_git(root, ["merge-base", "--is-ancestor", base_commit, head])
                if ancestor_result.returncode != 0:
                    if ancestor_result.returncode == 1:
                        report.fail(
                            "BASE_NOT_ANCESTOR",
                            "base commit is not an ancestor of the current worktree HEAD",
                            "base",
                        )
                    else:
                        report.fail(
                            "BASE_ANCESTOR_CHECK_FAILED",
                            _git_error(ancestor_result.stderr, "could not check base ancestry"),
                            "base",
                        )
                    base_gate_ok = False
            except AirlockError as exc:
                report.fail("HEAD_UNAVAILABLE", f"could not resolve current HEAD: {exc.message}", "base")
                base_gate_ok = False
    report.check("base", base_gate_ok)

    # Read candidate digest fields before digest verification.
    candidate_obj = capsule.get("candidate")
    if not isinstance(candidate_obj, Mapping):
        report.fail("CANDIDATE_INVALID", "candidate must be an object", "digest")
        candidate_obj = {}
    candidate_digest_raw = _alias_value(
        candidate_obj.get("worktree_digest"),
        capsule.get("candidate_worktree_digest"),
        primary_name="candidate.worktree_digest",
        alias_name="candidate_worktree_digest",
        report=report,
        check="digest",
    )
    candidate_digest: Optional[str]
    if not isinstance(candidate_digest_raw, str) or not SHA256_RE.fullmatch(candidate_digest_raw):
        report.fail("CANDIDATE_DIGEST_INVALID", "candidate worktree digest must be a SHA-256 hex string", "digest")
        candidate_digest = None
    else:
        candidate_digest = candidate_digest_raw.lower()
    if candidate_obj.get("digest_algorithm") != DIGEST_ALGORITHM:
        report.fail("DIGEST_ALGORITHM_INVALID", "candidate.digest_algorithm must be sha256-v1", "digest")

    # Extract evidence fields now so its artifact can be authorized as a
    # declared metadata path below.
    evidence_obj = capsule.get("evidence")
    if not isinstance(evidence_obj, Mapping):
        report.fail("EVIDENCE_INVALID", "evidence must be an object", "evidence")
        evidence_obj = {}
    artifact_path_raw, artifact_sha_raw = _read_artifact_fields(evidence_obj)
    normalized_artifact_path: Optional[str] = None
    artifact_absolute: Optional[str] = None
    try:
        if artifact_path_raw is not None:
            normalized_artifact_path, artifact_absolute = _normalize_artifact_path(artifact_path_raw, root)
    except AirlockError as exc:
        report.fail(exc.code, exc.message, "evidence")

    # Metadata paths are the only paths excluded from the candidate digest.
    metadata_obj = capsule.get("metadata")
    if not isinstance(metadata_obj, Mapping):
        report.fail("METADATA_INVALID", "metadata must be an object", "metadata")
        metadata_obj = {}
    metadata_paths_raw = metadata_obj.get("paths")
    if metadata_paths_raw is None and "metadata_paths" in capsule:
        metadata_paths_raw = capsule.get("metadata_paths")
    actual_capsule_path = _metadata_record_path(capsule_absolute, root)
    normalized_metadata_paths: list[str] = []
    metadata_ok = True
    if not isinstance(metadata_paths_raw, list):
        report.fail("METADATA_PATHS_INVALID", "metadata.paths must be a list", "metadata")
        metadata_ok = False
    else:
        for index, raw_path in enumerate(metadata_paths_raw):
            try:
                normalized_metadata_paths.append(
                    _normalize_metadata_path(raw_path, root, f"metadata.paths[{index}]")
                )
            except AirlockError as exc:
                report.fail(exc.code, exc.message, "metadata")
                metadata_ok = False
    declared_capsule_path = metadata_obj.get("capsule_path")
    if declared_capsule_path is None:
        report.fail("CAPSULE_METADATA_MISSING", "metadata.capsule_path must identify this capsule", "metadata")
        metadata_ok = False
    else:
        try:
            normalized_declared = _normalize_metadata_path(
                declared_capsule_path, root, "metadata.capsule_path"
            )
            if normalized_declared != actual_capsule_path:
                report.fail(
                    "CAPSULE_PATH_MISMATCH",
                    "metadata.capsule_path does not match --capsule",
                    "metadata",
                )
                metadata_ok = False
        except AirlockError as exc:
            report.fail(exc.code, exc.message, "metadata")
            metadata_ok = False
    declared_evidence_path = metadata_obj.get("evidence_path")
    normalized_evidence_path: Optional[str] = None
    if declared_evidence_path is not None:
        try:
            normalized_evidence_path = _normalize_metadata_path(
                declared_evidence_path, root, "metadata.evidence_path"
            )
        except AirlockError as exc:
            report.fail(exc.code, exc.message, "metadata")
            metadata_ok = False

    if actual_capsule_path not in normalized_metadata_paths:
        report.fail(
            "CAPSULE_PATH_NOT_RECORDED",
            "metadata.paths must include the capsule path",
            "metadata",
        )
        metadata_ok = False
    allowed_metadata_paths = {actual_capsule_path}
    if normalized_evidence_path is not None:
        if normalized_artifact_path is None:
            report.fail(
                "EVIDENCE_PATH_WITHOUT_ARTIFACT",
                "metadata.evidence_path requires evidence.artifact.path",
                "metadata",
            )
            metadata_ok = False
        elif normalized_evidence_path != normalized_artifact_path:
            report.fail(
                "EVIDENCE_PATH_MISMATCH",
                "metadata.evidence_path must match evidence.artifact.path",
                "metadata",
            )
            metadata_ok = False
        if normalized_artifact_path == normalized_evidence_path:
            allowed_metadata_paths.add(normalized_evidence_path)
    if normalized_artifact_path is not None:
        allowed_metadata_paths.add(normalized_artifact_path)
    unauthorized_metadata = sorted(set(normalized_metadata_paths) - allowed_metadata_paths)
    if unauthorized_metadata:
        report.fail(
            "METADATA_PATH_UNAUTHORIZED",
            "metadata.paths contains paths other than the capsule/evidence metadata: "
            + ", ".join(unauthorized_metadata[:20]),
            "metadata",
        )
        metadata_ok = False
    if normalized_evidence_path is not None and normalized_evidence_path not in normalized_metadata_paths:
        report.fail(
            "EVIDENCE_PATH_NOT_RECORDED",
            "metadata.paths must include metadata.evidence_path",
            "metadata",
        )
        metadata_ok = False
    if normalized_artifact_path is not None and normalized_artifact_path not in normalized_metadata_paths:
        report.fail(
            "ARTIFACT_PATH_NOT_RECORDED",
            "metadata.paths must include the evidence artifact path",
            "metadata",
        )
        metadata_ok = False
    report.check("metadata", metadata_ok)

    # Only authorized paths are used as digest exclusions.  A malformed or
    # over-broad metadata list therefore cannot hide a source file.
    digest_exclusions = [
        path for path in normalized_metadata_paths if path in allowed_metadata_paths and _inside_root(os.path.join(root, *path.split("/")), root)
    ]
    digest_ok = candidate_digest is not None
    if candidate_digest is not None:
        try:
            actual_digest = compute_worktree_digest(root, digest_exclusions)
            if actual_digest != candidate_digest:
                report.fail(
                    "CANDIDATE_DIGEST_MISMATCH",
                    "current tracked/unignored worktree does not match candidate.worktree_digest",
                    "digest",
                )
                digest_ok = False
        except AirlockError as exc:
            report.fail(exc.code, exc.message, "digest")
            digest_ok = False
    report.check("digest", digest_ok)

    # Scope and changed-file gate.
    scope_raw = capsule.get("scope")
    normalized_scope: list[str] = []
    scope_ok = True
    if not isinstance(scope_raw, list) or not scope_raw:
        report.fail("SCOPE_INVALID", "scope must be a non-empty list", "scope")
        scope_ok = False
    else:
        for index, raw_pattern in enumerate(scope_raw):
            try:
                normalized_scope.append(
                    _normalize_scope_pattern(raw_pattern, root, f"scope[{index}]")
                )
            except AirlockError as exc:
                report.fail(exc.code, exc.message, "scope")
                scope_ok = False
    if base_commit is not None:
        try:
            changed = _changed_paths(root, base_commit)
            changed_outside_scope = [
                path
                for path in changed
                if path not in digest_exclusions and not _scope_matches(path, normalized_scope)
            ]
            if changed_outside_scope:
                report.fail(
                    "SCOPE_VIOLATION",
                    "changed files outside declared scope: " + ", ".join(changed_outside_scope[:50]),
                    "scope",
                )
                scope_ok = False
        except AirlockError as exc:
            report.fail("CHANGED_PATHS_UNAVAILABLE", exc.message, "scope")
            scope_ok = False
    else:
        report.fail("CHANGED_PATHS_UNAVAILABLE", "cannot determine changed files without a valid base commit", "scope")
        scope_ok = False
    report.check("scope", scope_ok)

    # Contract gate.
    contract_obj = capsule.get("contract")
    contract_ok = True
    if not isinstance(contract_obj, Mapping):
        report.fail("CONTRACT_INVALID", "contract must be an object", "contract")
        contract_obj = {}
        contract_ok = False
    for field in ("preserve", "allowed_changes", "unknowns"):
        value = contract_obj.get(field)
        if not isinstance(value, list):
            report.fail("CONTRACT_LIST_INVALID", f"contract.{field} must be a list", "contract")
            contract_ok = False
        elif field != "unknowns":
            if not value:
                report.fail("CONTRACT_EMPTY", f"contract.{field} must contain an explicit claim", "contract")
                contract_ok = False
            if any(not isinstance(item, str) or not item.strip() for item in value):
                report.fail("CONTRACT_ENTRY_INVALID", f"contract.{field} entries must be non-empty strings", "contract")
                contract_ok = False
    unknowns = contract_obj.get("unknowns")
    if isinstance(unknowns, list):
        unresolved: list[str] = []
        for item in unknowns:
            if not isinstance(item, str) or not item.strip():
                unresolved.append(repr(item))
            elif not re.match(r"^\s*(?:resolved|closed)\s*:", item, re.IGNORECASE):
                unresolved.append(item)
            elif UNRESOLVED_RE.search(item):
                unresolved.append(item)
        if unresolved:
            report.fail(
                "CONTRACT_UNRESOLVED",
                "contract.unknowns contains unresolved entries: " + ", ".join(unresolved[:20]),
                "contract",
            )
            contract_ok = False
    report.check("contract", contract_ok)

    # Evidence gate.  The command is recorded for auditability only and is
    # deliberately never sent to a shell.
    evidence_ok = True
    status = evidence_obj.get("status")
    if status != "PASS":
        report.fail("EVIDENCE_STATUS_INVALID", "evidence.status must be PASS", "evidence")
        evidence_ok = False
    if type(evidence_obj.get("independent")) is not bool or evidence_obj.get("independent") is not True:
        report.fail("EVIDENCE_NOT_INDEPENDENT", "evidence.independent must be true", "evidence")
        evidence_ok = False
    verifier = evidence_obj.get("verifier")
    if verifier is None:
        verifier = evidence_obj.get("verifier_id")
    author_value = capsule.get("author")
    if not isinstance(verifier, str) or not verifier.strip():
        report.fail("EVIDENCE_VERIFIER_INVALID", "evidence.verifier must be non-empty", "evidence")
        evidence_ok = False
    elif not isinstance(author_value, str) or verifier == author_value:
        report.fail("EVIDENCE_VERIFIER_NOT_INDEPENDENT", "evidence.verifier must differ from author", "evidence")
        evidence_ok = False
    for field in ("domain", "command"):
        if not isinstance(evidence_obj.get(field), str) or not evidence_obj[field].strip():
            report.fail("EVIDENCE_FIELD_INVALID", f"evidence.{field} must be non-empty", "evidence")
            evidence_ok = False
    if not isinstance(artifact_sha_raw, str) or not SHA256_RE.fullmatch(artifact_sha_raw):
        report.fail("ARTIFACT_HASH_INVALID", "evidence artifact sha256 must be a 64-character hex string", "evidence")
        evidence_ok = False
    elif artifact_absolute is None:
        report.fail("ARTIFACT_PATH_MISSING", "evidence artifact path is required", "evidence")
        evidence_ok = False
    else:
        try:
            artifact_stat = os.stat(artifact_absolute)
            if not stat.S_ISREG(artifact_stat.st_mode):
                report.fail("ARTIFACT_NOT_REGULAR", "evidence artifact must be a regular file", "evidence")
                evidence_ok = False
            else:
                actual_artifact_hash = _sha256_file(artifact_absolute)
                if actual_artifact_hash != artifact_sha_raw.lower():
                    report.fail("ARTIFACT_HASH_MISMATCH", "evidence artifact SHA-256 does not match", "evidence")
                    evidence_ok = False
        except FileNotFoundError:
            report.fail("ARTIFACT_MISSING", "evidence artifact does not exist", "evidence")
            evidence_ok = False
        except OSError as exc:
            report.fail("ARTIFACT_STAT_FAILED", f"could not inspect evidence artifact: {exc}", "evidence")
            evidence_ok = False
    report.check("evidence", evidence_ok)

    # Effects gate.
    effects_obj = capsule.get("effects")
    effects_ok = True
    if not isinstance(effects_obj, Mapping):
        report.fail("EFFECTS_INVALID", "effects must be an object", "effects")
        effects_obj = {}
        effects_ok = False
    expected_effects = {
        "read_only": True,
        "sandboxed": True,
        "transactional": True,
        "external_writes": False,
    }
    for field, expected in expected_effects.items():
        actual = effects_obj.get(field)
        if type(actual) is not bool or actual is not expected:
            report.fail(
                "EFFECTS_UNSAFE",
                f"effects.{field} must be {str(expected).lower()}",
                "effects",
            )
            effects_ok = False
    report.check("effects", effects_ok)

    # Rollback gate.
    rollback_obj = capsule.get("rollback")
    rollback_ok = True
    if not isinstance(rollback_obj, Mapping):
        report.fail("ROLLBACK_INVALID", "rollback must be an object", "rollback")
        rollback_obj = {}
        rollback_ok = False
    strategy = rollback_obj.get("strategy")
    if not isinstance(strategy, str) or not strategy.strip():
        report.fail("ROLLBACK_STRATEGY_MISSING", "rollback.strategy must be non-empty", "rollback")
        rollback_ok = False
    if type(rollback_obj.get("verified")) is not bool or rollback_obj.get("verified") is not True:
        report.fail("ROLLBACK_UNVERIFIED", "rollback.verified must be true", "rollback")
        rollback_ok = False
    report.check("rollback", rollback_ok)

    return report.finish()


def _flatten_scopes(values: Optional[Sequence[Sequence[str]]]) -> list[str]:
    result: list[str] = []
    for group in values or []:
        result.extend(group)
    return result


def _json_dump_stdout(value: Mapping[str, Any]) -> None:
    json.dump(value, sys.stdout, ensure_ascii=True, sort_keys=True)
    sys.stdout.write("\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create and verify Semantic Airlock change capsules")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="write a non-passing change capsule")
    init_parser.add_argument("--base", required=True, help="base Git ref")
    init_parser.add_argument("--output", required=True, help="capsule JSON output path")
    init_parser.add_argument(
        "--scope",
        action="append",
        nargs="+",
        required=True,
        help="allowed path or glob; repeat or provide multiple values (GLOBAL permits all)",
    )
    init_parser.add_argument("--risk", required=True, choices=sorted(RISK_LEVELS))
    init_parser.add_argument("--author", required=True)
    init_parser.add_argument("--change-id", required=True, dest="change_id")

    verify_parser = subparsers.add_parser("verify", help="verify a change capsule")
    verify_parser.add_argument("--capsule", required=True, help="capsule JSON path")

    digest_parser = subparsers.add_parser("digest", help="print the current worktree digest")
    digest_parser.add_argument(
        "--exclude",
        action="append",
        nargs="+",
        default=[],
        help="metadata path(s) to exclude from the digest",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point.  Every operational failure is emitted as JSON."""

    parser = _build_parser()
    try:
        arguments = parser.parse_args(argv)
        if arguments.command == "init":
            capsule = init_capsule(
                base=arguments.base,
                output=arguments.output,
                scope=_flatten_scopes(arguments.scope),
                risk=arguments.risk,
                author=arguments.author,
                change_id=arguments.change_id,
            )
            _json_dump_stdout(capsule)
            return 0
        if arguments.command == "verify":
            report = verify_capsule(arguments.capsule)
            _json_dump_stdout(report)
            return 0 if report.get("ok") is True else 1
        if arguments.command == "digest":
            root = find_repo_root()
            exclusions = _flatten_scopes(arguments.exclude)
            digest = compute_worktree_digest(root, exclusions)
            _json_dump_stdout({"digest_algorithm": DIGEST_ALGORITHM, "worktree_digest": digest})
            return 0
        _json_dump_stdout(_error_report("COMMAND_INVALID", "unknown command"))
        return 1
    except AirlockError as exc:
        _json_dump_stdout(_error_report(exc.code, exc.message))
        return 1
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        _json_dump_stdout(_error_report("INTERNAL_ERROR", str(exc)))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
