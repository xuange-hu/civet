"""Output renderers: text (terminal), json, markdown, sarif."""

from __future__ import annotations

import json

from .model import SEVERITIES, ScanResult
from .rules import GROUPS, RULES

SEV_TAG = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def render_text(result: ScanResult, color: bool = True) -> str:
    out: list[str] = []
    n_files = len(result.files)
    out.append(f"  scanning {result.root}  ·  {n_files} workflow file(s)  ·  {len(RULES)} rules")
    out.append("")

    if not result.findings:
        out.append("  ✔ No findings in the scanned workflows.")
        out.append("")
        out.append(f"  Risk score: {result.risk}/100 → LOW RISK")
        return "\n".join(out)

    grouped: dict[str, list] = {}
    for f in result.findings:
        grouped.setdefault(f.path, []).append(f)

    for path in sorted(grouped):
        out.append(f"  {path}")
        for f in grouped[path]:
            out.append(f"    line {f.line:<4} {SEV_TAG[f.rule.severity]:<8} {f.rule.id}  {f.rule.title}")
            if f.job:
                out.append(f"                    job: {f.job}" + (f" / step: {f.step}" if f.step else ""))
            out.append(f"                    {f.detail}")
            if f.snippet:
                out.append(f"                    › {f.snippet.strip()[:110]}")
        out.append("")

    counts = result.counts
    summary = "  ".join(f"{SEV_TAG[s].lower()} {counts[s]}" for s in SEVERITIES if counts[s])
    out.append(f"  {len(result.findings)} findings  ·  {summary}")
    band = "CRITICAL RISK" if result.risk >= 70 else "HIGH RISK" if result.risk >= 40 else "MEDIUM RISK" if result.risk >= 15 else "LOW RISK"
    out.append(f"  Risk score: {result.risk}/100 → {band}")
    return "\n".join(out)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.as_dict(), indent=2, ensure_ascii=False)


def render_markdown(result: ScanResult) -> str:
    out: list[str] = ["# civet report", ""]
    out.append(f"- root: `{result.root}`")
    out.append(f"- workflows scanned: {len(result.files)}")
    out.append(f"- findings: {len(result.findings)}")
    out.append(f"- risk score: **{result.risk}/100**")
    out.append("")
    if not result.findings:
        out.append("No findings.")
        return "\n".join(out)
    out.append("| Severity | Rule | File:Line | Detail |")
    out.append("| --- | --- | --- | --- |")
    for f in result.findings:
        detail = f.detail.replace("|", "\\|")
        out.append(f"| {SEV_TAG[f.rule.severity]} | {f.rule.id} | `{f.path}:{f.line}` | {detail} |")
    return "\n".join(out)


def render_rules() -> str:
    out: list[str] = [f"civet — {len(RULES)} rules", ""]
    by_group: dict[str, list] = {}
    for r in RULES.values():
        by_group.setdefault(r.group, []).append(r)
    for group in GROUPS:
        rules = sorted(by_group.get(group, []), key=lambda r: r.id)
        if not rules:
            continue
        out.append(f"{group} — {GROUPS[group]}")
        for r in rules:
            out.append(f"  {r.id}  {SEV_TAG[r.severity]:<8} {r.title}")
        out.append("")
    return "\n".join(out).rstrip()


def render_explain(rule) -> str:
    return "\n".join(
        [
            f"{rule.id}  {SEV_TAG[rule.severity]}  [{rule.group}]",
            f"  {rule.title}",
            "",
            "  WHY",
            *[f"    {line}" for line in _wrap(rule.why)],
            "",
            "  FIX",
            *[f"    {line}" for line in _wrap(rule.fix)],
            "",
            f"  {rule.cwe}" if rule.cwe else "",
        ]
    ).rstrip()


def _wrap(text: str, width: int = 76) -> list[str]:
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines
