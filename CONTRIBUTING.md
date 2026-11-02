# Contributing

**civet** — GitHub Actions workflow audit — is small on purpose: hand-written parsers, deterministic rules, no dependencies. Contributions that keep it that way are welcome.

## Setup

```bash
git clone https://github.com/xuange-hu/civet
cd civet
pip install -e ".[mcp]" pytest ruff
pytest                 # 179 tests
ruff check src tests
```

No `pip install` is needed to run the tests after a clone — the root
`conftest.py` puts `src/` on `sys.path`.

## Rules and where they live

`src/civet/rules.py` (CIV001…, 36 rules) with the risk model in `src/civet/analyze.py`.

## Adding a rule

1. **The entry** in `src/civet/rules.py` with a title, a severity, and both `why` and `fix`.
2. **The check** in `src/civet/analyze.py`.
3. **A trigger sample** and **a negative case** in `tests/`: the workflow that fires it and the workflow that must not.
4. **A line in the demo** so CI keeps asserting every rule still fires.

Then update the rule table and the test-count badge in `README.md`. CI warns
when the badge and pytest disagree.

## Rules of the road

- **Zero dependencies in `src/` outside `mcp_server.py`.** `tests/test_packaging.py`
  fails on an optional import leaking into a required path.
- **No network access.** Not in the scanner, not in the tests. Tests that need
  a file write it to `tmp_path`.
- **Every finding carries a location and its source text.** A report that says
  "something is wrong" without saying where gets closed and forgotten.
- **`absent` and `empty` are different.** Decide what the explicit empty form
  means before adding a rule that fires on a missing field.
- **Line numbers come from the parser.** Do not compute them in the rule.

## Commit and PR

- One logical change per commit.
- CI runs on 3.10–3.13 across Ubuntu and Windows. A test that passes only on
  your machine will be caught there, so run `pytest` before pushing.
