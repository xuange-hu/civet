"""Command line interface. argparse on purpose — no click, no rich, no deps."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile

from . import __version__
from .demo import write_demo
from .model import SEVERITIES
from .render import (
    render_explain,
    render_json,
    render_markdown,
    render_rules,
    render_text,
)
from .rules import get
from .sarif import render_sarif
from .scan import has_severity_at_or_above, scan_path

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="civet",
        description="Deterministic security auditor for GitHub Actions workflows (zero dependencies).",
    )
    p.add_argument("--version", action="version", version=f"civet {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan a repository or a single workflow file")
    s.add_argument("path", nargs="?", default=".", help="file or directory (default: .)")
    s.add_argument("--format", choices=("text", "json", "sarif", "markdown"), default="text")
    s.add_argument("-o", "--output", help="write to a file instead of stdout")
    s.add_argument(
        "--fail-on",
        choices=SEVERITIES + ("none",),
        default="high",
        help="exit 1 when a finding at or above this severity exists (default: high)",
    )
    s.add_argument("--min-severity", choices=SEVERITIES, default="info", help="filter reported findings")
    s.add_argument("--ignore-rule", action="append", default=[], metavar="CIV101")
    s.add_argument("--ignore-group", action="append", default=[], metavar="hygiene")
    s.add_argument("--skip-dir", action="append", default=[], metavar="node_modules")

    sub.add_parser("rules", help="list every rule and its severity")

    e = sub.add_parser("explain", help="plain-language attack narrative for one rule")
    e.add_argument("rule", help="rule id, e.g. CIV201")

    d = sub.add_parser("demo", help="write a deliberately vulnerable workflow and scan it")
    d.add_argument("--dir", default=None, help="where to write the sample (default: temp dir)")
    d.add_argument("--format", choices=("text", "json", "markdown"), default="text")

    sub.add_parser("selftest", help="scan civet's own repository workflows")

    return p


def _emit(text: str, output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {output}")
    else:
        print(text)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.cmd or "scan"

    if cmd == "rules":
        _emit(render_rules(), None)
        return EXIT_OK

    if cmd == "explain":
        rule = get(args.rule)
        if rule is None:
            print(f"unknown rule: {args.rule} (try `civet rules`)", file=sys.stderr)
            return EXIT_USAGE
        _emit(render_explain(rule), None)
        return EXIT_OK

    if cmd == "demo":
        target = args.dir or os.path.join(tempfile.gettempdir(), "civet-demo")
        path = write_demo(target)
        res = scan_path(path)
        print(f"demo workflow: {path}\n")
        _emit(
            render_text(res)
            if args.format == "text"
            else render_json(res)
            if args.format == "json"
            else render_markdown(res),
            None,
        )
        return EXIT_OK

    if cmd == "selftest":
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        res = scan_path(root)
        _emit(render_text(res), None)
        return EXIT_FINDINGS if has_severity_at_or_above(res, "high") else EXIT_OK

    # ---- scan -------------------------------------------------------
    if not os.path.exists(args.path):
        print(f"path not found: {args.path}", file=sys.stderr)
        return EXIT_USAGE

    res = scan_path(
        args.path,
        skip_dirs=args.skip_dir,
        min_severity=args.min_severity,
        ignore_rules=args.ignore_rule,
        ignore_groups=args.ignore_group,
    )

    text = {
        "text": render_text,
        "json": render_json,
        "sarif": render_sarif,
        "markdown": render_markdown,
    }[args.format](res)
    _emit(text, args.output)

    for err in res.errors:
        print(f"warning: {err}", file=sys.stderr)

    if args.fail_on != "none" and has_severity_at_or_above(res, args.fail_on):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
