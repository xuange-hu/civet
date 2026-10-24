"""SARIF 2.1.0 output, so findings land in GitHub code scanning."""

from __future__ import annotations

import json
from typing import Any

from .model import ScanResult

SARIF_VERSION = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SEV_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def build_sarif(result: ScanResult) -> dict[str, Any]:
    rules_seen: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in result.findings:
        rid = f.rule.id
        if rid not in rules_seen:
            rules_seen[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.rule.title},
                "fullDescription": {"text": f"{f.rule.why}\n\nFix: {f.rule.fix}"},
                "help": {
                    "text": f"{f.rule.why}\n\nRemediation: {f.rule.fix}",
                    "markdown": f"**{f.rule.title}**\n\n{f.rule.why}\n\n**Fix:** {f.rule.fix}",
                },
                "properties": {
                    "tags": ["security", "github-actions", f.rule.group],
                    "security-severity": _score(f.rule.severity),
                },
                "defaultConfiguration": {"level": SEV_TO_LEVEL[f.rule.severity]},
            }
        results.append(
            {
                "ruleId": rid,
                "level": SEV_TO_LEVEL[f.rule.severity],
                "message": {"text": f.detail},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": max(1, f.line), "startColumn": 1},
                        }
                    }
                ],
                "properties": {
                    "job": f.job,
                    "step": f.step,
                    "snippet": f.snippet,
                },
            }
        )

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "civet",
                        "informationUri": "https://github.com/xuange-hu/civet",
                        "semanticVersion": "0.1.0",
                        "rules": [rules_seen[k] for k in sorted(rules_seen)],
                    }
                },
                "results": results,
                "properties": {
                    "risk": result.risk,
                    "counts": result.counts,
                },
            }
        ],
    }


def _score(severity: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}.get(severity, "5.0")


def render_sarif(result: ScanResult) -> str:
    return json.dumps(build_sarif(result), indent=2, ensure_ascii=False)
