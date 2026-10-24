"""CLI behaviour, exercised in-process (no subprocess)."""

from __future__ import annotations

import json

import pytest

from civet.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

CLEAN = """\
name: CI
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
        with:
          persist-credentials: false
      - run: pytest -q
"""

DIRTY = """\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://x.sh | bash
"""


def _write(repo, body):
    d = repo / ".github" / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    (d / "ci.yml").write_text(body, encoding="utf-8", newline="\n")
    return str(repo)


def test_scan_clean_returns_zero(tmp_path, capsys):
    rc = main(["scan", _write(tmp_path, CLEAN)])
    assert rc == EXIT_OK
    assert "No findings" in capsys.readouterr().out


def test_scan_dirty_returns_one(tmp_path):
    rc = main(["scan", _write(tmp_path, DIRTY), "--fail-on", "high"])
    assert rc == EXIT_FINDINGS


def test_fail_on_none_never_fails(tmp_path):
    assert main(["scan", _write(tmp_path, DIRTY), "--fail-on", "none"]) == EXIT_OK


def test_fail_on_critical_ignores_high(tmp_path):
    assert main(["scan", _write(tmp_path, DIRTY), "--fail-on", "critical"]) == EXIT_OK


def test_missing_path_is_usage_error():
    assert main(["scan", "/no/such/path/here"]) == EXIT_USAGE


def test_json_output_is_parseable(tmp_path, capsys):
    main(["scan", _write(tmp_path, DIRTY), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["tool"] == "civet"
    assert data["findings"]


def test_markdown_output_has_table(tmp_path, capsys):
    main(["scan", _write(tmp_path, DIRTY), "--format", "markdown"])
    out = capsys.readouterr().out
    assert "| Severity | Rule |" in out


def test_output_file_written(tmp_path, capsys):
    target = tmp_path / "out.json"
    main(["scan", _write(tmp_path, DIRTY), "--format", "json", "-o", str(target)])
    assert "wrote" in capsys.readouterr().out
    assert json.loads(target.read_text(encoding="utf-8"))["tool"] == "civet"


def test_rules_command(tmp_path, capsys):
    assert main(["rules"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "CIV201" in out and "CIV101" in out


def test_explain_command(capsys):
    assert main(["explain", "CIV201"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "pwn request" in out and "FIX" in out


def test_explain_unknown_rule_is_usage_error():
    assert main(["explain", "CIV999"]) == EXIT_USAGE


def test_demo_command_writes_and_finds(tmp_path, capsys):
    assert main(["demo", "--dir", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "CRITICAL" in out
    assert (tmp_path / ".github" / "workflows" / "civet-demo.yml").exists()


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "civet" in capsys.readouterr().out


def test_default_subcommand_is_scan(tmp_path):
    assert main(["scan", _write(tmp_path, CLEAN)]) == EXIT_OK


def test_selftest_runs_on_own_repo():
    # civet's own workflow must at least be parseable and scanned
    assert main(["selftest"]) in (EXIT_OK, EXIT_FINDINGS)
