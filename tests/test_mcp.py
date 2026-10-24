"""MCP surface, without requiring the optional `mcp` package."""

from __future__ import annotations

import json
import tempfile

import pytest

from civet import mcp_server

WORKFLOW = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl x | bash\n"


def _repo(tmp_path, body: str = WORKFLOW) -> str:
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    (d / "ci.yml").write_text(body, encoding="utf-8", newline="\n")
    return str(tmp_path)


def test_manifest_lists_every_tool():
    names = {t["name"] for t in mcp_server.tool_manifest()}
    assert names == set(mcp_server.TOOLS)
    assert len(names) == 4


def test_manifest_descriptions_are_non_empty():
    for tool in mcp_server.tool_manifest():
        assert tool["name"]
        assert len(tool["description"]) > 20, tool["name"]


def test_manifest_count_matches_decorated_tools():
    """A tool added to the server but not the manifest (or vice versa) is a bug."""
    with open(mcp_server.__file__, encoding="utf-8") as fh:
        body = fh.read()
    assert body.count("@mcp.tool()") == len(mcp_server.tool_manifest())


def test_civet_rules_returns_json():
    out = json.loads(mcp_server.civet_rules())
    assert out["count"] >= 30
    assert out["rules"][0]["id"].startswith("CIV")


def test_civet_rules_group_filter():
    out = json.loads(mcp_server.civet_rules("injection"))
    assert out["rules"]
    assert all(r["group"] == "injection" for r in out["rules"])


def test_civet_explain_known_and_unknown():
    ok = json.loads(mcp_server.civet_explain("CIV201"))
    assert ok["id"] == "CIV201" and "narrative" in ok
    bad = json.loads(mcp_server.civet_explain("CIV000"))
    assert "error" in bad


def test_civet_scan_on_missing_path_is_json_error():
    assert "error" in json.loads(mcp_server.civet_scan("/definitely/not/here"))


def test_civet_scan_on_real_path(tmp_path):
    out = json.loads(mcp_server.civet_scan(_repo(tmp_path)))
    assert out["findings"]
    assert "summary" in out


def test_civet_scan_respects_max_findings(tmp_path):
    out = json.loads(mcp_server.civet_scan(_repo(tmp_path), max_findings=1))
    assert len(out["findings"]) == 1
    assert out["truncatedFindings"] is True


def test_civet_scan_ignore_rules(tmp_path):
    out = json.loads(mcp_server.civet_scan(_repo(tmp_path), ignore_rules="CIV501,CIV301"))
    assert all(f["ruleId"] != "CIV501" for f in out["findings"])


def test_civet_demo_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    out = json.loads(mcp_server.civet_demo())
    assert out["findings"]
    assert out["demoPath"].endswith("workflows")


def test_build_server_requires_optional_dependency():
    """Without `mcp` installed this must skip, never silently pass a stub."""
    pytest.importorskip("mcp")
    assert mcp_server.build_server() is not None
