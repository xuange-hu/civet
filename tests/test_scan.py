"""Discovery, filtering and scoring."""

from __future__ import annotations

import os

import pytest

from civet.model import SEVERITY_RANK
from civet.scan import discover, has_severity_at_or_above, is_workflow_path, scan_path
from civet.yamlscan import loads

WORKFLOW = """\
name: CI
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://x.sh | bash
      - uses: actions/checkout@v4
"""


@pytest.fixture()
def repo(tmp_path):
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    (d / "ci.yml").write_text(WORKFLOW, encoding="utf-8", newline="\n")
    (tmp_path / "README.md").write_text("hello", encoding="utf-8")
    (tmp_path / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    return tmp_path


def test_is_workflow_path_requires_the_github_directory(repo):
    assert is_workflow_path(str(repo / ".github" / "workflows" / "ci.yml"))
    # a random yaml elsewhere is not a workflow
    assert not is_workflow_path(str(repo / "config.yaml"))


def test_discover_finds_workflows_under_dot_github(repo):
    """Regression: `.github` starts with `.git`; prefix pruning dropped it."""
    found = discover(str(repo))
    assert len(found) == 1
    assert found[0].endswith("ci.yml")


def test_discover_ignores_node_modules(repo):
    nm = repo / "node_modules" / "pkg" / ".github" / "workflows"
    nm.mkdir(parents=True)
    (nm / "evil.yml").write_text("on: push\n", encoding="utf-8")
    assert len(discover(str(repo))) == 1


def test_discover_on_a_single_file(repo):
    p = str(repo / ".github" / "workflows" / "ci.yml")
    assert discover(p) == [p]


def test_scan_path_counts_and_risk(repo):
    res = scan_path(str(repo))
    assert len(res.files) == 1
    assert res.risk > 0
    assert res.counts["high"] >= 1


def test_paths_are_relative_to_root(repo):
    res = scan_path(str(repo))
    assert all(not f.path.startswith("/") and ":\\" not in f.path for f in res.findings)
    assert res.findings[0].path.endswith("ci.yml")


def test_min_severity_filters(repo):
    allf = scan_path(str(repo))
    high = scan_path(str(repo), min_severity="high")
    assert len(high.findings) < len(allf.findings)
    assert all(SEVERITY_RANK[f.rule.severity] >= SEVERITY_RANK["high"] for f in high.findings)


def test_ignore_rule(repo):
    base = {f.rule.id for f in scan_path(str(repo)).findings}
    assert "CIV501" in base
    filtered = {f.rule.id for f in scan_path(str(repo), ignore_rules=["CIV501"]).findings}
    assert "CIV501" not in filtered


def test_ignore_group(repo):
    filtered = {f.rule.id for f in scan_path(str(repo), ignore_groups=["supply-chain"]).findings}
    assert "CIV301" not in filtered


def test_broken_yaml_is_reported_not_raised(tmp_path):
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    (d / "bad.yml").write_text("a: 1\nb: 2\noops\n", encoding="utf-8")
    res = scan_path(str(tmp_path))
    assert res.errors and res.findings == []


def test_has_severity_threshold(repo):
    res = scan_path(str(repo))
    assert has_severity_at_or_above(res, "high")
    assert has_severity_at_or_above(res, "low")
    assert not has_severity_at_or_above(res, "critical") or any(
        f.rule.severity == "critical" for f in res.findings
    )


def test_result_is_json_serialisable(repo):
    import json

    assert json.dumps(scan_path(str(repo)).as_dict())


def test_risk_saturates_at_100(tmp_path):
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    body = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
    for i in range(30):
        body += f"      - run: curl https://x{i}.sh | bash\n"
    (d / "many.yml").write_text(body, encoding="utf-8")
    assert scan_path(str(tmp_path)).risk == 100


def test_deterministic_ordering(repo):
    a = [f.as_dict() for f in scan_path(str(repo)).findings]
    b = [f.as_dict() for f in scan_path(str(repo)).findings]
    assert a == b


def test_workflow_parses_from_real_file(repo):
    wf = loads((repo / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    assert list(wf["jobs"]) == ["build"]


def test_skip_dir_option(repo):
    assert len(scan_path(str(repo), skip_dirs=[".github"]).files) == 0


def test_scan_missing_path_records_error():
    res = scan_path(os.path.join("definitely", "not", "here"))
    assert res.files == []
