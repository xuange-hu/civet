"""MCP surface — optional extra, imported only when the ``mcp`` package exists.

Kept importable-without-mcp: the module raises ImportError only at server
construction time, so ``civet --version`` never needs the optional dependency.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from .cli import build_parser  # noqa: F401  (documented entry point parity)
from .demo import write_demo
from .render import render_text
from .rules import RULES, get
from .scan import scan_path

TOOLS = ("civet_scan", "civet_explain", "civet_rules", "civet_demo")


def _payload(result) -> dict[str, Any]:
    d = result.as_dict()
    d["summary"] = render_text(result)
    return d


def civet_scan(
    path: str = ".",
    min_severity: str = "info",
    ignore_rules: str = "",
    ignore_groups: str = "",
    max_findings: int = 60,
) -> str:
    """Scan a repository's GitHub Actions workflows.

    Returns JSON: counts per severity, a risk score, and every finding with
    file:line evidence. Use min_severity to cut noise; use ignore_rules with a
    comma-separated list of rule ids for accepted risks.
    """
    if not os.path.exists(path):
        return json.dumps({"error": f"path not found: {path}", "tool": "civet"}, ensure_ascii=False)
    res = scan_path(
        path,
        min_severity=min_severity if min_severity in ("critical", "high", "medium", "low", "info") else "info",
        ignore_rules=[r for r in ignore_rules.split(",") if r.strip()],
        ignore_groups=[g for g in ignore_groups.split(",") if g.strip()],
    )
    d = _payload(res)
    d["findings"] = d["findings"][: max(1, int(max_findings))]
    d["truncatedFindings"] = len(res.findings) > max_findings
    return json.dumps(d, indent=2, ensure_ascii=False)


def civet_explain(rule_id: str) -> str:
    """Explain one rule: what the attack is, why it matters, how to fix it."""
    rule = get(rule_id)
    if rule is None:
        return json.dumps({"error": f"unknown rule {rule_id}", "known": sorted(RULES)}, ensure_ascii=False)
    return json.dumps({**rule.as_dict(), "narrative": f"{rule.why}\n\nFix: {rule.fix}"}, indent=2, ensure_ascii=False)


def civet_rules(group: str = "") -> str:
    """List rules, optionally filtered by group (injection/trigger/supply-chain/secrets/execution/artifact/hygiene)."""
    items = [r for r in RULES.values() if not group or r.group == group]
    return json.dumps(
        {"count": len(items), "rules": [r.as_dict() for r in sorted(items, key=lambda r: r.id)]},
        indent=2,
        ensure_ascii=False,
    )


def civet_demo() -> str:
    """Write a deliberately vulnerable workflow to a temp dir and scan it — one-call proof of value."""
    path = write_demo(os.path.join(tempfile.gettempdir(), "civet-demo-mcp"))
    res = scan_path(path)
    d = _payload(res)
    d["demoPath"] = path
    return json.dumps(d, indent=2, ensure_ascii=False)


def build_server():
    """Construct the MCP server. Requires the optional `mcp` extra."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(name="civet")

    @mcp.tool()
    def civet_scan_tool(
        path: str = ".",
        min_severity: str = "info",
        ignore_rules: str = "",
        ignore_groups: str = "",
        max_findings: int = 60,
    ) -> str:
        return civet_scan(path, min_severity, ignore_rules, ignore_groups, max_findings)

    @mcp.tool()
    def civet_explain_tool(rule_id: str) -> str:
        return civet_explain(rule_id)

    @mcp.tool()
    def civet_rules_tool(group: str = "") -> str:
        return civet_rules(group)

    @mcp.tool()
    def civet_demo_tool() -> str:
        return civet_demo()

    return mcp


def tool_manifest() -> list[dict[str, str]]:
    return [
        {"name": "civet_scan", "description": civet_scan.__doc__ or ""},
        {"name": "civet_explain", "description": civet_explain.__doc__ or ""},
        {"name": "civet_rules", "description": civet_rules.__doc__ or ""},
        {"name": "civet_demo", "description": civet_demo.__doc__ or ""},
    ]


def main() -> None:
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()
