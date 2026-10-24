"""Rule registry.

Every rule carries ``why`` (the attack, in concrete terms) and ``fix`` (the
minimal change). ``civet explain`` renders these, which is the difference
between "you have a finding" and "you understand the finding".
"""

from __future__ import annotations

from .model import Rule

GROUPS = {
    "injection": "Untrusted input reaching a shell or an interpreter",
    "trigger": "Workflow triggers that hand control to an outsider",
    "supply-chain": "Dependencies you execute but do not control",
    "secrets": "Token and secret exposure",
    "execution": "Dangerous execution patterns inside run:",
    "artifact": "Artifact and cache poisoning",
    "hygiene": "Configuration that limits blast radius",
}


def _r(*args, **kw) -> Rule:
    return Rule(*args, **kw)


RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        # ------------------------------------------------ injection
        _r(
            "CIV101",
            "Untrusted event data interpolated into run:",
            "critical",
            "injection",
            "Anything under github.event.* (issue title, PR body, branch name, commit "
            "message) is attacker-authored. Interpolating it into run: puts it in a shell "
            "command line on a runner that holds GITHUB_TOKEN — one $(...) away from full "
            "repo write and secret exfiltration.",
            "Pass it through env: and reference it as \"$TITLE\" inside the script, never "
            "inline in the run: text.",
            "CWE-94",
        ),
        _r(
            "CIV102",
            "Tainted context interpolated into run:",
            "high",
            "injection",
            "github.head_ref, github.actor, inputs.* and env values can be influenced by a "
            "fork or a workflow caller. The same shell-injection chain applies, just with a "
            "longer path from attacker to sink.",
            "Move the value into env: and quote the shell expansion.",
            "CWE-94",
        ),
        _r(
            "CIV103",
            "github-script executes an interpolated expression",
            "critical",
            "injection",
            "actions/github-script passes script: to a JS runtime. An interpolated "
            "expression becomes source code, not a string — template injection with "
            "runner privileges.",
            "Use env: plus process.env.NAME inside the script body.",
            "CWE-94",
        ),
        _r(
            "CIV104",
            "Expression interpolated into an action input",
            "medium",
            "injection",
            "with: values are passed to third-party action code. Many actions forward "
            "them to a shell or to a template, so untrusted data can land in an "
            "interpreter even though your own run: is clean.",
            "Only pass expressions whose origin you control; route untrusted values "
            "through a sanitising step first.",
            "CWE-74",
        ),
        _r(
            "CIV105",
            "Untrusted context used in a conditional",
            "medium",
            "injection",
            "if: expressions built from event data let a caller steer which branch runs. "
            "Gate-skipping (make an auth check evaluate false) is a common second stage.",
            "Gate on trusted signals — actor permission, label set by a maintainer — "
            "not on free-text event fields.",
            "CWE-807",
        ),
        # ------------------------------------------------ trigger
        _r(
            "CIV201",
            "pwn request: pull_request_target + checkout of PR head",
            "critical",
            "trigger",
            "pull_request_target runs with the base repo's token, and checking out "
            "github.event.pull_request.head.sha executes the fork's code in that context. "
            "Any attacker PR gets a write-scoped token and access to secrets.",
            "Use pull_request, or split into two workflows: an unprivileged build that "
            "uploads an artifact and a privileged workflow_run that consumes it.",
            "CWE-269",
        ),
        _r(
            "CIV202",
            "pull_request_target trigger",
            "high",
            "trigger",
            "This trigger runs in the base repository's context with access to secrets. It "
            "is safe only if the job never checks out or executes contributor code.",
            "Prefer pull_request; keep pull_request_target jobs free of any contributor "
            "content and drop permissions to the minimum.",
            "CWE-269",
        ),
        _r(
            "CIV203",
            "workflow_run trigger",
            "medium",
            "trigger",
            "workflow_run executes with the base token after an untrusted workflow "
            "finishes. Artifacts and caches it consumes were produced by the untrusted run "
            "— a classic privilege escalation channel.",
            "Validate artifact contents before use and never write untrusted artifacts "
            "into a privileged context.",
            "CWE-269",
        ),
        _r(
            "CIV204",
            "Comment-driven trigger",
            "medium",
            "trigger",
            "issue_comment and discussion_comment fire on text anyone who can comment can "
            "write. Bots that parse the comment body for commands are directly reachable.",
            "Verify comment author association (OWNER/MEMBER/COLLABORATOR) before acting "
            "on the body.",
            "CWE-269",
        ),
        _r(
            "CIV205",
            "Self-hosted runner reachable from a fork-triggered event",
            "high",
            "trigger",
            "A self-hosted runner is persistent state: cloud credentials, SSH keys, docker "
            "socket. Letting fork-triggered events land on it converts a PR into host "
            "compromise with no easy way to evict the attacker.",
            "Use GitHub-hosted runners for fork events, or require maintainer approval and "
            "an environment with reviewers.",
            "CWE-269",
        ),
        _r(
            "CIV206",
            "push trigger without branch filter",
            "low",
            "trigger",
            "Every branch push runs the workflow, including long-lived feature branches "
            "whose content may be stale or unreviewed — more jobs, more chances to "
            "expose a token.",
            "Add branches: [main] or paths: to narrow what can start a run.",
            "CWE-1188",
        ),
        # ------------------------------------------------ supply chain
        _r(
            "CIV301",
            "Action not pinned to an immutable commit SHA",
            "medium",
            "supply-chain",
            "A tag is a mutable pointer. Whoever controls the action repository can move "
            "v4 to new code and every workflow using it picks it up on the next run, with "
            "no diff in your repository.",
            "Pin to the 40-character commit SHA and keep the version in a trailing "
            "comment: uses: actions/checkout@<sha> # v4.2.2",
            "CWE-1357",
        ),
        _r(
            "CIV302",
            "Action pinned to a branch name",
            "medium",
            "supply-chain",
            "@main / @master moves on every commit. That is worse than a version tag: the "
            "action silently receives unreleased code, including code from a compromised "
            "maintainer account or a merge from a fork.",
            "Pin to a commit SHA, or at minimum a signed version tag.",
            "CWE-1357",
        ),
        _r(
            "CIV303",
            "checkout leaves the token in .git",
            "medium",
            "supply-chain",
            "actions/checkout stores GITHUB_TOKEN in .git/config by default. Any later "
            "step — including a third-party action — can read it back with plain git.",
            "Set persist-credentials: false unless a later step genuinely needs git auth.",
            "CWE-522",
        ),
        _r(
            "CIV304",
            "Container image pinned to a mutable tag",
            "low",
            "supply-chain",
            ":latest (or any floating tag) makes the build non-reproducible and hands the "
            "image author code execution in your job whenever they republish.",
            "Pin by digest: container: node@sha256:<digest>.",
            "CWE-1357",
        ),
        _r(
            "CIV305",
            "Third-party action receives a token input",
            "high",
            "supply-chain",
            "Passing secrets.GITHUB_TOKEN (or a PAT) into an action you do not control "
            "gives that action's authors repo-scoped write access on every run.",
            "Avoid the input, or vendor/pin the action to a reviewed SHA and scope the "
            "token with permissions:.",
            "CWE-522",
        ),
        _r(
            "CIV306",
            "Reusable workflow not pinned to a SHA",
            "medium",
            "supply-chain",
            "uses: org/repo/.github/workflows/x.yml@main re-resolves on every run, so the "
            "called workflow can change under you and inherits whatever secrets you pass.",
            "Pin the reusable workflow to a commit SHA.",
            "CWE-1357",
        ),
        # ------------------------------------------------ secrets
        _r(
            "CIV401",
            "secrets.GITHUB_TOKEN referenced inside run:",
            "high",
            "secrets",
            "The token lands in the process environment of a shell you wrote. Any command "
            "in that script — or anything it downloads — can print it, and the run log "
            "or an artifact will carry it out.",
            "Let actions authenticate themselves, or pass the token only to a step that "
            "needs it and set explicit minimal permissions.",
            "CWE-522",
        ),
        _r(
            "CIV402",
            "secrets: inherit on a reusable workflow call",
            "high",
            "secrets",
            "inherit forwards every secret in the repository to the called workflow, "
            "including ones that job has no business holding.",
            "List the exact secrets the callee needs instead of inheriting all.",
            "CWE-522",
        ),
        _r(
            "CIV403",
            "Secret passed to a third-party action",
            "medium",
            "secrets",
            "Third-party action inputs are visible to action code. A secret handed there "
            "is a secret handed to whoever can publish that action version.",
            "Prefer first-party actions for secrets, or pin to a reviewed SHA.",
            "CWE-522",
        ),
        _r(
            "CIV404",
            "Secret declared in job-level env",
            "medium",
            "secrets",
            "A job-level env: makes the secret visible to every step in the job, including "
            "steps you add later and third-party actions you did not audit.",
            "Scope the secret to the single step that needs it.",
            "CWE-522",
        ),
        _r(
            "CIV405",
            "Secret used in a conditional",
            "low",
            "secrets",
            "if: comparisons involving secrets create a presence oracle and are evaluated "
            "before permissions apply on some event types.",
            "Branch on an explicit boolean input, not on secret content.",
            "CWE-208",
        ),
        # ------------------------------------------------ execution
        _r(
            "CIV501",
            "Remote script piped into a shell",
            "high",
            "execution",
            "curl … | bash executes whatever the endpoint serves at that moment: a "
            "compromised CDN, a hijacked domain, or a maintainer account takeover. There "
            "is no integrity check in the pipeline.",
            "Download, verify a checksum or signature, then execute.",
            "CWE-494",
        ),
        _r(
            "CIV502",
            "Dynamic shell evaluation",
            "high",
            "execution",
            "eval, bash -c \"$VAR\" and sh -c with an interpolated value turn data into "
            "code. Combined with CIV101 this is the full RCE chain.",
            "Run the command directly; if you must build it, use an array or a here-doc "
            "with quoted expansions.",
            "CWE-78",
        ),
        _r(
            "CIV503",
            "Unpinned package executed on the fly",
            "medium",
            "execution",
            "npx pkg / uvx pkg resolves the newest published version at run time. A "
            "typosquat or a compromised release executes with your token.",
            "Pin the version: npx pkg@1.2.3, or install from a lockfile.",
            "CWE-1357",
        ),
        _r(
            "CIV504",
            "Deprecated set-output / save-state",
            "medium",
            "execution",
            "::set-output is removed and was injectable: a newline in the value injects a "
            "new workflow command, letting untrusted data define outputs.",
            "Use the $GITHUB_OUTPUT file with a delimiter, or upgrade the action.",
            "CWE-74",
        ),
        _r(
            "CIV505",
            "Dynamic write to GITHUB_ENV / GITHUB_PATH",
            "medium",
            "execution",
            "Appending untrusted text to $GITHUB_ENV sets variables — including "
            "PATH — for every later step. Writing a directory into GITHUB_PATH "
            "hijacks any subsequently invoked binary.",
            "Only write values you constructed, and validate before appending.",
            "CWE-427",
        ),
        # ------------------------------------------------ artifact / cache
        _r(
            "CIV601",
            "Cache key derived from untrusted input",
            "medium",
            "artifact",
            "A key built from PR-controlled data lets a fork poison the cache entry that a "
            "privileged later run restores — persisted code execution across workflows.",
            "Build cache keys from lockfile hashes, never from event data.",
            "CWE-349",
        ),
        _r(
            "CIV602",
            "Artifact uploaded from pull_request_target",
            "high",
            "artifact",
            "Artifacts produced in a privileged run and consumed by an untrusted one (or "
            "vice versa) are a data channel between trust zones.",
            "Keep privileged and untrusted runs in separate workflows with separate "
            "artifact namespaces.",
            "CWE-501",
        ),
        _r(
            "CIV603",
            "Artifact uploaded without retention limit",
            "low",
            "artifact",
            "Artifacts inherit the token's reach and stay downloadable by anyone with repo "
            "read access, long after the run matters.",
            "Set retention-days to the smallest value that still works.",
            "CWE-1188",
        ),
        # ------------------------------------------------ hygiene
        _r(
            "CIV701",
            "Job without timeout-minutes",
            "low",
            "hygiene",
            "A hung job on a self-hosted runner holds the machine (and any credentials on "
            "it) until GitHub's hard limit, and burns billed minutes elsewhere.",
            "Add timeout-minutes to every job.",
            "CWE-400",
        ),
        _r(
            "CIV702",
            "continue-on-error on a security step",
            "low",
            "hygiene",
            "A failing lint, audit or signature check that does not fail the build is not "
            "a gate — it is a log line.",
            "Remove continue-on-error from checks, or fail the job explicitly.",
            "CWE-1188",
        ),
        _r(
            "CIV703",
            "No explicit permissions block",
            "medium",
            "hygiene",
            "Without permissions: the token inherits the repository default, which is "
            "read-write on many older repositories. Every job then holds write scope it "
            "never asked for.",
            "Add permissions: contents: read at the top and widen per job only where "
            "needed.",
            "CWE-250",
        ),
        _r(
            "CIV704",
            "permissions: write-all",
            "medium",
            "hygiene",
            "write-all hands every scope, including id-token and packages, to every step "
            "in the workflow. Compromise of any single step is compromise of the repo.",
            "Enumerate the scopes the job actually needs.",
            "CWE-250",
        ),
        _r(
            "CIV705",
            "Deployment job without environment protection",
            "low",
            "hygiene",
            "Without environment: there are no required reviewers, no branch restriction "
            "and no secret scoping on the step that pushes to production.",
            "Declare environment: production and configure protection rules.",
            "CWE-1188",
        ),
        _r(
            "CIV706",
            "No concurrency group",
            "low",
            "hygiene",
            "Concurrent deploys race. The last writer wins, and a stale run can overwrite "
            "a newer one.",
            "Add concurrency: group: <name> with cancel-in-progress where safe.",
            "CWE-362",
        ),
    ]
}


def rule_ids() -> list[str]:
    return sorted(RULES)


def rules_by_group() -> dict[str, list[Rule]]:
    out: dict[str, list[Rule]] = {g: [] for g in GROUPS}
    for r in RULES.values():
        out.setdefault(r.group, []).append(r)
    return out


def get(rule_id: str) -> Rule | None:
    return RULES.get(rule_id.upper())
