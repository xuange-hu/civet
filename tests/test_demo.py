"""The demo is the first thing a visitor runs; it must light up every rule."""

from __future__ import annotations

from civet.demo import DEMO_WORKFLOW, DEMO_WORKFLOW_2, write_demo
from civet.rules import GROUPS, RULES
from civet.scan import scan_path


def test_demo_writes_both_files(tmp_path):
    out = write_demo(str(tmp_path / "demo"))
    assert out.endswith("workflows") or "workflows" in out
    assert (tmp_path / "demo" / ".github" / "workflows" / "civet-demo.yml").exists()
    assert (tmp_path / "demo" / ".github" / "workflows" / "civet-demo-advanced.yml").exists()


def test_demo_files_parse_and_produce_findings(tmp_path):
    res = scan_path(write_demo(str(tmp_path / "demo")))
    assert len(res.files) == 2
    assert len(res.findings) >= 30
    assert res.errors == []


def test_demo_covers_every_rule(tmp_path):
    """A rule nobody can see fire is a rule nobody will trust."""
    res = scan_path(write_demo(str(tmp_path / "demo")))
    hit = {f.rule.id for f in res.findings}
    missing = sorted(set(RULES) - hit)
    assert missing == [], f"demo does not demonstrate: {missing}"


def test_demo_covers_every_group(tmp_path):
    res = scan_path(write_demo(str(tmp_path / "demo")))
    groups = {f.rule.group for f in res.findings}
    assert groups == set(GROUPS)


def test_demo_has_critical_findings(tmp_path):
    res = scan_path(write_demo(str(tmp_path / "demo")))
    assert res.counts["critical"] >= 2
    assert res.risk >= 70


def test_demo_text_is_lf_only():
    for body in (DEMO_WORKFLOW, DEMO_WORKFLOW_2):
        assert "\r" not in body


def test_demo_is_idempotent(tmp_path):
    a = scan_path(write_demo(str(tmp_path / "demo")))
    b = scan_path(write_demo(str(tmp_path / "demo")))
    assert [f.as_dict() for f in a.findings] == [f.as_dict() for f in b.findings]
