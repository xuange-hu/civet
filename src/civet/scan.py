"""Filesystem walk and scan orchestration."""

from __future__ import annotations

import os
from collections.abc import Iterable

from .analyze import analyze_workflow
from .model import SEVERITY_RANK, ScanResult
from .parse import WORKFLOW_SUFFIXES, parse_workflow

DEFAULT_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    ".tox",
}

MAX_FILES = 500
MAX_BYTES = 2 * 1024 * 1024


def is_workflow_path(path: str) -> bool:
    """Only .github/workflows/*.yml is a workflow — path is part of the contract."""
    norm = path.replace("\\", "/")
    if not norm.endswith(WORKFLOW_SUFFIXES):
        return False
    return "/.github/workflows/" in norm or norm.startswith(".github/workflows/")


def discover(root: str, skip_dirs: Iterable[str] = ()) -> list[str]:
    """Walk ``root`` and return workflow paths, deterministically ordered."""
    skip = set(skip_dirs) or DEFAULT_SKIP_DIRS
    found: list[str] = []
    if os.path.isfile(root):
        return [root] if is_workflow_path(root) or root.endswith(WORKFLOW_SUFFIXES) else []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune in place: cheaper than filtering after the fact.
        # NOTE: compare the name exactly — `.github` starts with `.git`, so a
        # prefix test here silently drops every workflow in every repository.
        dirnames[:] = sorted(d for d in dirnames if d not in skip and d != ".git")
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if is_workflow_path(full):
                found.append(full)
    return found[:MAX_FILES]


def scan_path(
    root: str,
    skip_dirs: Iterable[str] = (),
    min_severity: str = "info",
    ignore_rules: Iterable[str] = (),
    ignore_groups: Iterable[str] = (),
) -> ScanResult:
    """Scan a file or a directory tree. Deterministic; never raises on bad YAML."""
    result = ScanResult(root=root)
    ignore_r = {r.upper() for r in ignore_rules}
    ignore_g = {g.lower() for g in ignore_groups}
    floor = SEVERITY_RANK.get(min_severity, 0)

    paths = discover(root, skip_dirs)
    if len(paths) == MAX_FILES:
        result.truncated = True
    result.files = paths

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(MAX_BYTES)
        except OSError as exc:
            result.errors.append(f"{path}: {exc}")
            continue
        try:
            wf = parse_workflow(path, text)
        except Exception as exc:  # noqa: BLE001 - a broken file must not kill the scan
            result.errors.append(f"{path}: unparseable ({type(exc).__name__}: {exc})")
            continue
        try:
            findings = analyze_workflow(wf)
        except Exception as exc:  # noqa: BLE001 - one bad step must not drop the file
            result.errors.append(f"{path}: rule error ({type(exc).__name__}: {exc})")
            continue

        rel = os.path.relpath(path, root) if os.path.isdir(root) else os.path.basename(path)
        for f in findings:
            if f.rule.id in ignore_r or f.rule.group in ignore_g:
                continue
            if SEVERITY_RANK.get(f.rule.severity, 0) < floor:
                continue
            f.path = rel.replace("\\", "/")
            result.findings.append(f)

    result.findings.sort(key=lambda f: (f.path, f.line, f.rule.id))
    return result


def has_severity_at_or_above(result: ScanResult, threshold: str) -> bool:
    floor = SEVERITY_RANK.get(threshold, 0)
    return any(SEVERITY_RANK.get(f.rule.severity, 0) >= floor for f in result.findings)
