#!/usr/bin/env python3
"""Read-only, bounded context discovery. Paths in reports are repository-relative.

Only explicitly requested files are fingerprinted; Python overviews use AST, never
imports. Optional references search those source files only. No cache is written.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

SOURCES = frozenset(".py .pyi .js .jsx .ts .tsx .c .h .cc .cpp .hpp .rs .go .java .sh .rb .sql".split())
MANIFESTS = ("pyproject.toml", "package.json", "Cargo.toml", "go.mod", "setup.cfg", "setup.py",
             "requirements.txt", "Pipfile", "pom.xml", "Makefile", "CMakeLists.txt", "pytest.ini")
RULES = ("AGENTS.md", "SKILL.md", "CLAUDE.md", ".cursorrules", ".editorconfig",
         "CONTRIBUTING.md", ".github/copilot-instructions.md")
MAX_BYTES = 1_048_576
TOOLKIT = Path(__file__).resolve().parent
STATE = TOOLKIT / ".state"


def _decode(data):
    return data.decode("utf-8", "surrogateescape")


def _git(cwd, *args, empty_ok=False):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    try:
        proc = subprocess.run(["git", "--no-pager", "-c", "core.fsmonitor=false", *args],
                              cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=10, check=False)
        return proc.stdout if proc.returncode in ((0, 1) if empty_ok else (0,)) else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _private(path):
    for part in path.parts:
        name = part.lower()
        if (name in {".git", ".ssh", ".aws", ".gnupg", ".azure", ".kube", ".netrc", ".pypirc", ".npmrc",
                     ".docker", ".kite_session", ".my.cnf", "secrets", ".secrets"}
                or name.startswith((".env", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"))
                or re.search(r"(^|[._-])(credentials?|secrets?|tokens?|passwords?|(?:api|access|private)[_-]?key|service[_-]?account)([._-]|$)", name)
                or Path(name).suffix in {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".session", ".kdbx"}):
            return True
    return False


def _checked(root, base, value):
    path = Path(value)
    if ".." in path.parts or "\x00" in str(path):
        raise ValueError("traversal or NUL in path")
    path = path if path.is_absolute() else base / path
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise ValueError("path outside Git root") from None
    if _private(relative):
        raise ValueError("Git metadata or credential-like path excluded")
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("symlink path excluded")
    if path == STATE or STATE in path.parents:
        raise ValueError("toolkit runtime state is not a project target")
    return path


def _bounded(items, limit, key="paths"):
    return {key: items[:limit], "truncated": len(items) > limit}


def _ancestors(root, path):
    while path.is_relative_to(root):
        yield path
        if path == root:
            break
        path = path.parent


def _facts(path, relative, limit, warnings):
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("only regular file targets are supported")
    facts = {"path": relative, "size_bytes": info.st_size, "sha256": None}
    if info.st_size > MAX_BYTES:
        warnings.append(f"{relative}: fingerprint/overview unavailable above {MAX_BYTES} bytes")
        return facts
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise ValueError("target changed during inspection; retry explicitly")
        data = stream.read(MAX_BYTES + 1)
        if len(data) != info.st_size or os.fstat(stream.fileno()).st_mtime_ns != info.st_mtime_ns:
            raise ValueError("target changed during inspection; retry explicitly")
    facts["sha256"] = hashlib.sha256(data).hexdigest()
    if path.suffix not in SOURCES:
        return facts
    if b"\x00" in data:
        warnings.append(f"{relative}: binary source overview unsupported")
        return facts
    facts["lines"] = len(data.splitlines())
    if path.suffix not in {".py", ".pyi"}:
        facts["symbols"] = None
        warnings.append(f"{relative}: symbol overview supports Python only")
        return facts
    try:
        nodes = sorted((n for n in ast.walk(ast.parse(data)) if isinstance(
            n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))), key=lambda n: n.lineno)
        facts.update(_bounded([{"name": n.name[:128], "kind": "class" if isinstance(n, ast.ClassDef) else "function",
                                "line": n.lineno, "end_line": n.end_lineno} for n in nodes], limit, "symbols"))
        facts["truncated"] |= any(len(n.name) > 128 for n in nodes[:limit])
    except (SyntaxError, ValueError, RecursionError) as exc:
        facts["symbols"] = None
        warnings.append(f"{relative}: Python overview unavailable ({type(exc).__name__})")
    return facts


def _nearby(root, cwd, targets, limit):
    directories = set(_ancestors(root, cwd))
    for target in targets:
        directories.update(_ancestors(root, target.parent))
    found = {"manifests": [], "rules": []}
    for kind, names in (("manifests", MANIFESTS), ("rules", RULES)):
        for directory in sorted(directories):
            for name in names:
                try:
                    candidate = _checked(root, directory, name)
                    if candidate.is_file():
                        found[kind].append(candidate.relative_to(root).as_posix())
                except (OSError, ValueError):
                    pass
    tests = set()
    for target in targets:
        if target.suffix not in SOURCES:
            continue
        stem, suffix = target.stem, ".py" if target.suffix == ".pyi" else target.suffix
        names = [f"test_{stem}{suffix}", f"{stem}_test{suffix}", f"{stem}.test{suffix}", f"{stem}.spec{suffix}"]
        for directory in _ancestors(root, target.parent):
            for folder in ("", "tests", "test", "__tests__", "spec"):
                for name in names + ([target.name] if folder else []):
                    try:
                        candidate = _checked(root, directory / folder, name)
                        if candidate != target and candidate.is_file():
                            tests.add(candidate.relative_to(root).as_posix())
                    except (OSError, ValueError):
                        pass
    manifests = set(found["manifests"])
    project = next((d for d in _ancestors(root, cwd) if any(
        (d / name).relative_to(root).as_posix() in manifests for name in MANIFESTS)), root)
    return (project.relative_to(root).as_posix(),
            {kind: _bounded(sorted(set(values)), limit) for kind, values in found.items()},
            {**_bounded(sorted(tests), limit, "suggestions"),
             "basis": "nearby filename heuristic; suggestions are not sufficient verification"})


def _history(root, targets, limit):
    raw = _git(root, "log", "--max-count=100", "--format=%x00", "--name-only", "-z",
               "--no-renames", "--no-ext-diff", "--no-textconv", "--no-show-signature")
    if raw is None:
        return {"status": "unknown", "cochanges": [], "truncated": False}
    # Double NUL separates headers; single NUL separates filenames (including spaces/newlines).
    commits = raw.split(b"\x00\x00")[1:]
    counts, bulk, matched = Counter(), 0, 0
    for chunk in commits:
        names = {_decode(p) for p in chunk.removeprefix(b"\x00").removeprefix(b"\n").split(b"\x00") if p}
        if len(names) > 40:
            bulk += 1
            continue
        if not names.intersection(targets):
            continue
        matched += 1
        for name in names.difference(targets):
            try:
                _checked(root, root, name)
                counts[name] += 1
            except (OSError, ValueError):
                pass
    rows = [{"path": p, "count": n} for p, n in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]
    return {"status": "sampled", "scope": "latest 100 commits; same-commit filenames, no rename following",
            "commits_scanned": len(commits), "target_commits": matched, "bulk_commits_skipped": bulk,
            "cochanges": rows[:limit], "truncated": len(commits) == 100 or len(rows) > limit}


def _references(root, targets, symbol, limit):
    result = {"status": "unknown", "symbol": symbol[:128] if isinstance(symbol, str) else None, "scope": targets, "locations": [],
              "basis": "lexical references within requested source files; not an actual call graph", "truncated": False}
    if not isinstance(symbol, str) or not symbol.isidentifier() or len(symbol) > 128 or not targets:
        result["reason"] = "requires an identifier and explicit source targets at most 1 MiB each"
        return result
    raw = _git(root, "grep", "--no-index", "--no-textconv", "-I", "-n", "-z", "-F", "-w", "-o",
               "-m", str(limit + 1), "-e", symbol, "--", *targets, empty_ok=True)
    if raw is not None:
        locations = sorted({(_decode(m[1]), int(m[2])) for m in re.finditer(rb"([^\x00]+)\x00([0-9]+)\x00[^\n]*\n", raw)})
        result.update(status="searched", locations=[f"{p}:{n}" for p, n in locations[:limit]],
                      truncated=len(locations) > limit)
    return result


def inspect_context(cwd: Path, paths: list[str], *, history=False, symbol=None, limit=8) -> dict:
    """Discover metadata without changing files/index. Errors describe invalid inputs.

    ``limit`` (1..32) bounds each collection, including requested targets. Absent
    history/references mean unknown, not evidence of safety or independence.
    """
    report = {"schema_version": 1, "repo": None, "targets": [], "targets_truncated": False,
              "dirty": {"known": False, "paths": [], "truncated": False}, "pointers": {},
              "tests": {"suggestions": [], "truncated": False},
              "history": {"status": "not_requested", "cochanges": [], "truncated": False},
              "references": {"status": "not_requested", "locations": [], "truncated": False},
              "warnings": [], "errors": []}
    warnings = report["warnings"]
    if type(limit) is not int or not 1 <= limit <= 32:
        report["errors"].append("limit must be an integer from 1 to 32")
        return report
    try:
        if ".." in Path(cwd).parts:
            raise ValueError("cwd traversal excluded")
        cwd = Path(os.path.abspath(cwd))
        if any(p.is_symlink() for p in (cwd, *cwd.parents)) or ".git" in cwd.parts:
            raise ValueError("cwd symlink or Git metadata path excluded")
        raw = _git(cwd, "rev-parse", "--show-toplevel")
        if raw is None:
            raise ValueError("Git worktree unavailable (not a repository, Git unavailable, or timeout)")
        root = Path(_decode(raw).removesuffix("\n"))
        _checked(root, root, cwd)
    except (OSError, ValueError) as exc:
        report["errors"].append(str(exc))
        return report
    head = _git(root, "rev-parse", "--verify", "HEAD")
    branch = _git(root, "symbolic-ref", "--quiet", "--short", "HEAD")
    report["repo"] = {"root": str(root), "cwd": cwd.relative_to(root).as_posix(),
                      "head": _decode(head).strip() if head else None,
                      "branch": _decode(branch).strip() if branch else None}
    raw = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=normal", "--ignore-submodules=all")
    if raw is None:
        warnings.append("Git dirty/conflict state unknown")
    else:
        entries, excluded, conflicts = [], 0, False
        records = iter(raw.split(b"\x00"))
        for record in records:
            if not record:
                continue
            code, name = _decode(record[:2]), _decode(record[3:])
            if "R" in code or "C" in code:
                next(records, None)  # porcelain -z puts the destination before the original name.
            conflicts |= "U" in code or code in {"AA", "DD"}
            try:
                _checked(root, root, name)
                entries.append({"path": name, "status": code})
            except (OSError, ValueError):
                excluded += 1
        report["dirty"] = {"known": True, **_bounded(sorted(entries, key=lambda row: row["path"]), limit),
                           "excluded_paths": excluded, "conflicts": conflicts,
                           "coverage": "untracked directories may be summarized; ignored files and submodules omitted"}
        if conflicts:
            warnings.append("Unmerged Git paths present")
    targets = []
    report["targets_truncated"] = len(paths) > limit
    for value in paths[:limit]:
        try:
            target = _checked(root, cwd, value)
            if target in targets:
                continue
            report["targets"].append(_facts(target, target.relative_to(root).as_posix(), limit, warnings))
            targets.append(target)
        except (OSError, ValueError) as exc:
            report["errors"].append({"path": value, "reason": str(exc)})
    project, report["pointers"], report["tests"] = _nearby(root, cwd, targets, limit)
    report["repo"]["project"] = project
    report["repo"]["project_basis"] = "nearest ancestor manifest/config; Git root fallback"
    if history:
        report["history"] = _history(root, {p.relative_to(root).as_posix() for p in targets}, limit) if targets else {
            "status": "unknown", "reason": "requires explicit valid file targets", "cochanges": [], "truncated": False}
        if report["history"]["status"] == "unknown":
            warnings.append("Requested history unavailable; no coupling conclusion")
    if symbol is not None:
        sources = [f["path"] for f in report["targets"] if Path(f["path"]).suffix in SOURCES and f["sha256"]]
        report["references"] = _references(root, sources, symbol, limit)
        if report["references"]["status"] == "unknown":
            warnings.append("Requested lexical reference search unavailable")
    report["warnings_truncated"] = len(warnings) > limit
    report["warnings"] = warnings[:limit]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--symbol")
    parser.add_argument("--limit", type=int, default=8)
    args = parser.parse_args(argv)
    report = inspect_context(args.cwd, args.paths, history=args.history, symbol=args.symbol, limit=args.limit)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
