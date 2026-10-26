<div align="center">

# 🐱 civet

**A security auditor for GitHub Actions workflows that runs anywhere Python runs.**

36 deterministic rules · zero dependencies · evidence-first · SARIF for CI · MCP server

[![CI](https://github.com/xuange-hu/civet/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/civet/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/tests-172%20passing-brightgreen.svg)](tests/)
[![rules](https://img.shields.io/badge/rules-36-red.svg)](#rule-map)
[![Dependencies](https://img.shields.io/badge/dependencies-0-blue.svg)](pyproject.toml)
[![MCP](https://img.shields.io/badge/MCP-4%20tools-green.svg)](https://modelcontextprotocol.io)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](README.md) · [简体中文](README_CN.md)

</div>

---

## Why another workflow scanner

`zizmor` (6.7k★, Rust) and `actionlint` (4.3k★, Go) are excellent. They are also
**compiled binaries** you have to download, and `actionlint` does not do security
audits while `zizmor` does not do general linting.

`civet` is the third shape:

| | zizmor | actionlint | **civet** |
|---|---|---|---|
| Language | Rust binary | Go binary | **pure Python, 0 deps** |
| Install | download a release | download a release | **`pip install civet-audit`** |
| Works offline / air-gapped | needs a binary | needs a binary | **yes — stdlib only** |
| Parses YAML with | `serde_yaml` | custom | **its own reader, so it can keep line numbers** |
| Evidence (file:line + source) | yes | yes | **yes, plus the raw line under every finding** |
| Explains the attack | yes | partly | **`civet explain CIV201` — a narrative per rule** |
| SARIF 2.1.0 | yes | yes | yes |
| MCP server | no | no | **4 tools** |

The zero-dependency part is not austerity — it is the point. A scanner you cannot
run on the slim container that *is* your CI is a scanner you will not run.

## Install

```bash
pip install civet-audit
# or, without installing anything:
uvx --from civet-audit civet .
```

## Three steps

```bash
# 1. see it work, on a workflow that is broken on purpose
civet demo

# 2. scan your repository
civet scan .

# 3. understand the worst finding
civet explain CIV201
```

Requires Python ≥ 3.10. Nothing else. No API keys, no network calls, no LLM in
the loop — a scan is a pure function of the bytes on disk, so two runs on the
same tree always produce the same report.

## What the output looks like

Real output from `civet demo` (trimmed to high and above):

```
  scanning ./civet-demo  ·  2 workflow file(s)  ·  36 rules

  .github/workflows/civet-demo.yml
    line 13   HIGH     CIV205  Self-hosted runner reachable from a fork-triggered event
                    job: build
                    Job 'build' runs on a self-hosted runner under ['issue_comment', 'pull_request_target'].
                    › runs-on: self-hosted
    line 15   CRITICAL CIV201  pwn request: pull_request_target + checkout of PR head
                    job: build / step: actions/checkout@v4
                    pull_request_target checks out PR head code while holding a privileged token.
                    › - uses: actions/checkout@v4
    line 20   CRITICAL CIV101  Untrusted event data interpolated into run:
                    job: build / step: Greet the contributor
                    run: interpolates attacker-controlled `${{ github.event.pull_request.title }}`.
                    › - name: Greet the contributor
    line 23   HIGH     CIV501  Remote script piped into a shell
                    job: build / step: Install toolchain
                    Remote content is piped straight into an interpreter.
                    › - name: Install toolchain

  52 findings  ·  critical 3  high 10  medium 22  low 13
  Risk score: 100/100 → CRITICAL RISK
```

Every line carries: the **line number**, the **job and step** it belongs to, the
**reason** in concrete terms, and the **raw source line** (`›`) so you can check
the claim yourself instead of trusting it.

## `explain` — the part that teaches

```console
$ civet explain CIV201

CIV201  CRITICAL  [trigger]
  pwn request: pull_request_target + checkout of PR head

  WHY
    pull_request_target runs with the base repo's token, and checking out
    github.event.pull_request.head.sha executes the fork's code in that context.
    Any attacker PR gets a write-scoped token and access to secrets.

  FIX
    Use pull_request, or split into two workflows: an unprivileged build that
    uploads an artifact and a privileged workflow_run that consumes it.

  CWE-269
```

## Rule map

| Group | Rules | What it covers |
|---|---|---|
| `injection` | 5 | `${{ github.event.* }}` into `run:`, `github-script`, action inputs, untrusted `if:` |
| `trigger` | 6 | **pwn request**, `pull_request_target`, `workflow_run`, comment triggers, self-hosted + fork |
| `supply-chain` | 6 | SHA pinning, branch pins, `persist-credentials`, mutable images, reusable-workflow pins |
| `secrets` | 5 | `GITHUB_TOKEN` in `run:`, `secrets: inherit`, third-party secret handoff, job-level secrets |
| `execution` | 5 | `curl \| bash`, `eval`, unpinned `npx`/`uvx`, `set-output`, `GITHUB_ENV` writes |
| `artifact` | 3 | cache poisoning, artifact from privileged run, retention |
| `hygiene` | 6 | `permissions:`, `timeout-minutes`, environment protection, concurrency |

```bash
civet rules                     # all 36 with severity
civet rules | grep injection    # one group
```

## CI gate

```yaml
- name: Audit workflows
  run: |
    pip install civet-audit
    civet scan . --fail-on high --min-severity medium
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage error.
Default is `--fail-on high`.

Upload to code scanning:

```yaml
- run: civet scan . --format sarif -o civet.sarif --fail-on none
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: civet.sarif
```

Tuning, for when a finding is an accepted risk:

```bash
civet scan . --ignore-rule CIV301 --ignore-group hygiene
```

## MCP server

```bash
pip install "civet-audit[mcp]"
civet-mcp
```

Claude Code / Cursor config:

```json
{
  "mcpServers": {
    "civet": {
      "command": "uvx",
      "args": ["--from", "civet-audit[mcp]", "civet-mcp"]
    }
  }
}
```

| Tool | What it does |
|---|---|
| `civet_scan` | scan a path; returns counts, risk score, findings with evidence |
| `civet_explain` | the attack narrative and fix for one rule |
| `civet_rules` | list rules, optionally by group |
| `civet_demo` | write and scan a broken workflow — one-call proof of value |

## Design rules

1. **Deterministic.** No model, no network, no clock. Same bytes → same report.
2. **Evidence first.** `file:line`, the job, the step, and the raw source line.
3. **Zero dependencies in core.** `mcp` lives in an extra; the CLI never imports it.
4. **No silent failures.** Unparseable YAML is reported in `errors`, not swallowed.
5. **Say why.** Every rule carries an attack narrative and a minimal fix.

## Dogfood

`civet` audits the workflows of its author's other repositories. On first run it
found 19 findings across `vehsec` (2 workflows), 19 in `pcaplens`, 22 in
`skillvet` and 13 in `agent-scan` — including a real `curl … | sh` in a publish
pipeline. They are being fixed, not suppressed.

## Roadmap

- [ ] `--fix` for mechanical remediations (SHA pinning, `persist-credentials`)
- [ ] `actions/*` version→SHA resolution with a local cache
- [ ] GitLab CI and Jenkinsfile readers behind the same rule engine
- [ ] baseline file (`.civet-baseline.json`) for incremental adoption
- [ ] `environment` protection checks against the repository API

## Contributing

```bash
git clone https://github.com/xuange-hu/civet && cd civet
pip install -e ".[mcp]"
PYTHONPATH=src pytest -q     # 163 tests
```

Adding a rule means touching three places: `rules.py` (id, severity, why, fix),
`analyze.py` (the check), and `demo.py` (a line that proves it fires). A test in
`tests/test_rules.py` asserts the id; `test_demo.py` asserts the demo still
covers 100% of the registry.

## License

MIT
