"""Core data model. Kept dependency-free on purpose."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
# Display/report ordering: most severe first.
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
# Comparison ordering: most severe gets the HIGHEST rank. Keep these two apart
# — conflating them makes "--fail-on high" compare critical(0) >= high(1) and
# never fire.
SEVERITY_RANK = {s: len(SEVERITIES) - 1 - i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Rule:
    """A single check. ``group`` drives the ``--ignore-group`` filter."""

    id: str
    title: str
    severity: str
    group: str
    why: str
    fix: str
    cwe: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "group": self.group,
            "why": self.why,
            "fix": self.fix,
            "cwe": self.cwe,
        }


@dataclass
class Finding:
    rule: Rule
    path: str
    line: int
    snippet: str
    detail: str
    job: str = ""
    step: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule.id,
            "title": self.rule.title,
            "severity": self.rule.severity,
            "group": self.rule.group,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "detail": self.detail,
            "job": self.job,
            "step": self.step,
            "cwe": self.rule.cwe,
            "fix": self.rule.fix,
        }


@dataclass
class ScanResult:
    root: str
    files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.rule.severity] += 1
        return out

    @property
    def risk(self) -> int:
        """0-100 risk score: weighted sum, saturating at 100.

        Weight unit is 1 point, so 10 criticals (or 100 lows) saturate.
        Deterministic and monotone — two runs on the same tree always agree.
        """
        raw = sum(SEVERITY_WEIGHT[f.rule.severity] for f in self.findings)
        return min(100, raw)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": "civet",
            "root": self.root,
            "filesScanned": len(self.files),
            "files": self.files,
            "findings": [f.as_dict() for f in self.findings],
            "counts": self.counts,
            "risk": self.risk,
            "errors": self.errors,
        }
