"""Rule-level behaviour. Each test pins one attack pattern to one rule id."""

from __future__ import annotations

from civet.analyze import analyze_workflow
from civet.model import SEVERITY_RANK
from civet.parse import parse_workflow
from civet.rules import GROUPS, RULES, get


def scan(yaml_text: str, name: str = ".github/workflows/w.yml"):
    wf = parse_workflow(name, yaml_text)
    return {f.rule.id for f in analyze_workflow(wf)}, analyze_workflow(wf)


def test_registry_is_well_formed():
    assert len(RULES) >= 30
    for rid, rule in RULES.items():
        assert rule.id == rid, rid
        assert rule.severity in SEVERITY_RANK, rid
        assert rule.group in GROUPS, rid
        assert rule.why and rule.fix, f"{rid} missing narrative"
        assert len(rule.why) > 40, f"{rid} why is too thin"


def test_rule_ids_are_unique_and_sorted_lookup():
    assert len(set(RULES)) == len(RULES)
    assert get("civ101") is RULES["CIV101"]  # lookup is case-insensitive
    assert get("CIV999") is None


def test_untrusted_event_data_in_run():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n")
    assert "CIV101" in ids


def test_head_ref_in_run_is_tainted():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.head_ref }}\n")
    assert "CIV102" in ids and "CIV101" not in ids


def test_github_script_interpolation():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/github-script@v7\n        with:\n          script: console.log('${{ github.event.issue.body }}')\n"
    )
    assert "CIV103" in ids


def test_action_input_receives_untrusted_value():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: x/y@v1\n        with:\n          msg: ${{ github.event.issue.body }}\n"
    )
    assert "CIV104" in ids


def test_bare_context_in_condition_is_detected():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo hi\n        if: github.event.issue.title == 'ship'\n"
    )
    assert "CIV105" in ids


def test_release_idiom_on_github_ref_is_not_a_finding():
    """startsWith(github.ref, 'refs/tags/v') is the standard release gate."""
    ids, _ = scan(
        "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 5\n    if: startsWith(github.ref, 'refs/tags/v')\n"
        "    steps:\n      - run: echo hi\n"
    )
    assert "CIV105" not in ids


def test_pwn_request_combination():
    ids, _ = scan(
        "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    assert "CIV201" in ids
    # the trigger-level rule is suppressed when the exploit-level one fires
    assert "CIV202" not in ids


def test_pull_request_target_alone_reports_trigger():
    ids, _ = scan("on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert "CIV202" in ids and "CIV201" not in ids


def test_workflow_run_trigger():
    ids, _ = scan("on:\n  workflow_run:\n    workflows: [CI]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert "CIV203" in ids


def test_comment_trigger():
    ids, _ = scan("on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert "CIV204" in ids


def test_self_hosted_with_fork_event():
    ids, _ = scan("on: pull_request\njobs:\n  a:\n    runs-on: self-hosted\n    steps:\n      - run: echo hi\n")
    assert "CIV205" in ids


def test_self_hosted_with_push_only_is_clean():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: self-hosted\n    steps:\n      - run: echo hi\n")
    assert "CIV205" not in ids


def test_push_without_branch_filter():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert "CIV206" in ids


def test_push_with_branch_filter_is_clean():
    ids, _ = scan("on:\n  push:\n    branches: [main]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert "CIV206" not in ids


def test_unpinned_action_tag():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
    assert "CIV301" in ids


def test_sha_pinned_action_is_clean():
    sha = "a" * 40
    ids, _ = scan(f"on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{sha}\n")
    assert "CIV301" not in ids and "CIV302" not in ids


def test_branch_pinned_action():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: some/tool@main\n")
    assert "CIV302" in ids


def test_checkout_persist_credentials():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
    assert "CIV303" in ids


def test_checkout_persist_credentials_false_is_clean():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"
    )
    assert "CIV303" not in ids


def test_container_latest():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    container: node:latest\n    steps:\n      - run: echo hi\n")
    assert "CIV304" in ids


def test_container_digest_pinned_is_clean():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    container: node@sha256:" + "b" * 64 + "\n    steps:\n      - run: echo hi\n"
    )
    assert "CIV304" not in ids


def test_third_party_receives_token():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: third/party@v1\n        with:\n          token: ${{ secrets.GITHUB_TOKEN }}\n"
    )
    assert "CIV305" in ids


def test_third_party_receives_other_secret():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: third/party@v1\n        with:\n          key: ${{ secrets.SLACK }}\n"
    )
    assert "CIV403" in ids


def test_first_party_action_with_secret_is_not_flagged():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/github-script@v7\n        with:\n          github-token: ${{ secrets.GITHUB_TOKEN }}\n"
    )
    assert "CIV305" not in ids and "CIV403" not in ids


def test_reusable_workflow_not_pinned():
    ids, _ = scan("on: push\njobs:\n  a:\n    uses: org/repo/.github/workflows/x.yml@main\n")
    assert "CIV306" in ids


def test_secrets_inherit():
    ids, _ = scan("on: push\njobs:\n  a:\n    uses: org/repo/.github/workflows/x.yml@" + "c" * 40 + "\n    secrets: inherit\n")
    assert "CIV402" in ids


def test_github_token_in_run():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ secrets.GITHUB_TOKEN }}\n")
    assert "CIV401" in ids


def test_job_level_secret_env():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      T: ${{ secrets.X }}\n    steps:\n      - run: echo hi\n"
    )
    assert "CIV404" in ids


def test_secret_in_condition():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    if: secrets.ENABLED == 'true'\n    steps:\n      - run: echo hi\n"
    )
    assert "CIV405" in ids


def test_curl_pipe_bash():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -fsSL https://x.sh | bash\n")
    assert "CIV501" in ids


def test_local_command_piped_into_python_is_not_a_finding():
    """Regression: `tool --json | python -c ...` never touches the network."""
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: |\n          tool scan --json | python -c \"import json,sys; print(json.load(sys.stdin))\"\n"
    )
    assert "CIV501" not in ids


def test_wget_piped_into_python_is_a_finding():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: wget -qO- https://x.sh | python3\n")
    assert "CIV501" in ids


def test_eval_of_variable():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: eval \"$CMD\"\n")
    assert "CIV502" in ids


def test_unpinned_npx():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npx some-cli --go\n")
    assert "CIV503" in ids


def test_pinned_npx_is_clean():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npx some-cli@1.2.3 --go\n")
    assert "CIV503" not in ids


def test_npx_with_variable_version_is_clean():
    """`npx pkg@$VERSION` is pinned by the caller, not resolved to latest."""
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: npx --yes some-tool@$VERSION --version\n"
    )
    assert "CIV503" not in ids


def test_set_output():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ::set-output name=x::1\n")
    assert "CIV504" in ids


def test_github_env_write():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"A=$B\" >> $GITHUB_ENV\n")
    assert "CIV505" in ids


def test_cache_key_from_event():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/cache@v4\n        with:\n          key: deps-${{ github.event.pull_request.head.sha }}\n"
    )
    assert "CIV601" in ids


def test_upload_artifact_from_pull_request_target():
    ids, _ = scan(
        "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact@v4\n"
    )
    assert "CIV602" in ids


def test_upload_artifact_without_retention():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact@v4\n")
    assert "CIV603" in ids


def test_missing_timeout():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert "CIV701" in ids


def test_continue_on_error_on_a_check():
    ids, _ = scan(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - name: Audit deps\n        run: npm audit\n        continue-on-error: true\n"
    )
    assert "CIV702" in ids


def test_missing_permissions_block():
    ids, _ = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert "CIV703" in ids


def test_write_all_permissions():
    ids, _ = scan("on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert "CIV704" in ids


def test_deploy_job_without_environment():
    ids, _ = scan("on: push\npermissions: {}\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
    assert "CIV705" in ids and "CIV706" in ids


def test_deploy_job_with_environment_is_clean():
    ids, _ = scan(
        "on: push\npermissions: {}\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    environment: production\n"
        "    concurrency:\n      group: deploy\n    steps:\n      - run: echo hi\n"
    )
    assert "CIV705" not in ids and "CIV706" not in ids


def test_clean_workflow_has_no_high_or_critical():
    _, findings = scan(
        "name: CI\non:\n  push:\n    branches: [main]\npermissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n"
        "      - uses: actions/checkout@" + "d" * 40 + "\n        with:\n          persist-credentials: false\n"
        "      - run: pytest\n"
    )
    high = [f for f in findings if f.rule.severity in ("critical", "high")]
    assert high == [], [f.rule.id for f in high]


def test_findings_carry_file_line_and_snippet():
    _, findings = scan("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl x | bash\n")
    f = next(x for x in findings if x.rule.id == "CIV501")
    assert f.path.endswith("w.yml")
    assert f.line == 6
    assert "curl" in f.snippet
    assert f.job == "a"
