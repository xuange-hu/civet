"""SARIF 2.1.0 shape — GitHub code scanning rejects malformed input."""

from __future__ import annotations

import json

from civet.demo import write_demo
from civet.sarif import build_sarif, render_sarif
from civet.scan import scan_path


def _result(tmp_path):
    return scan_path(write_demo(str(tmp_path / "demo")))


def test_schema_and_version(tmp_path):
    doc = build_sarif(_result(tmp_path))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")


def test_run_shape(tmp_path):
    doc = build_sarif(_result(tmp_path))
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "civet"
    assert run["results"]
    assert run["tool"]["driver"]["rules"]


def test_every_result_has_a_declared_rule(tmp_path):
    doc = build_sarif(_result(tmp_path))
    declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    for res in doc["runs"][0]["results"]:
        assert res["ruleId"] in declared


def test_rule_metadata(tmp_path):
    doc = build_sarif(_result(tmp_path))
    rule = next(r for r in doc["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "CIV201")
    assert rule["shortDescription"]["text"]
    assert "security" in rule["properties"]["tags"]
    assert float(rule["properties"]["security-severity"]) >= 7.0


def test_locations_have_line_numbers(tmp_path):
    doc = build_sarif(_result(tmp_path))
    for res in doc["runs"][0]["results"]:
        region = res["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_levels_map_from_severity(tmp_path):
    doc = build_sarif(_result(tmp_path))
    seen = {r["level"] for r in doc["runs"][0]["results"]}
    assert seen <= {"error", "warning", "note"}


def test_render_is_parseable_json(tmp_path):
    assert json.loads(render_sarif(_result(tmp_path)))


def test_empty_result_is_valid_sarif(tmp_path):
    (tmp_path / "empty").mkdir()
    doc = build_sarif(scan_path(str(tmp_path / "empty")))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
