"""The checks. One function per concern; every finding carries file:line evidence."""

from __future__ import annotations

import re
from collections.abc import Callable

from .model import Finding
from .parse import Job, Step, Workflow
from .rules import RULES

EXPR = re.compile(r"\$\{\{([^}]*)\}\}")

# Contexts a person outside the repository can influence.
TAINTED_EVENT = re.compile(r"github\.event\.")
TAINTED_SOFT = re.compile(
    r"github\.(head_ref|base_ref|actor|triggering_actor|ref)\b|inputs\.|needs\.[^.]+\.outputs\."
)
# For `if:` gating only. github.ref is deliberately excluded: gating on
# startsWith(github.ref, 'refs/tags/v') is the standard release idiom and
# requires push rights already, so flagging it is pure noise.
TAINTED_COND = re.compile(
    r"github\.event\.|github\.(head_ref|actor|triggering_actor)\b|inputs\.|needs\.[^.]+\.outputs\."
)

SHELL_PIPE = re.compile(
    # a network fetch piped into an interpreter
    r"(?:curl|wget)\b[^\n|]*\|[^\n]*(?:ba|z|fi|k)?sh\b|"
    r"(?:curl|wget)\b[^\n|]*\|[^\n]*(?:python|perl|ruby|node)[0-9.]*\b|"
    # anything piped into a shell is dynamic execution
    r"\|\s*(?:sudo\s+)?(?:ba|z|fi|k)?sh\b"
)
# `cmd | python -c "..."` is deliberately NOT flagged: the data never leaves the
# machine. Flagging it produced a false positive on a real CI step.
EVAL = re.compile(r"\beval\b|\b(?:ba|z|da)?sh\s+-c\s+[\"']?\$|\bexec\s+[\"']?\$")
TOOL_RUN = re.compile(r"\b(?:npx|uvx|pipx\s+run|go\s+run|bunx)\b")
OUTPUT_CMD = re.compile(r"::(?:set-output|save-state)\s+name=")
GITHUB_FILE = re.compile(r">>\s*\$?\{?GITHUB_(?:ENV|PATH|OUTPUT)\}?")
DEPLOY_RE = re.compile(r"deploy|release|publish|ship|terraform|\bprod\b", re.IGNORECASE)
SECURITY_STEP_RE = re.compile(r"audit|lint|scan|verify|signature|sign|sast|check", re.IGNORECASE)
FIRST_PARTY = ("actions/", "github/", "./", ".github/", "docker://")
SHA_PIN = re.compile(r"^[0-9a-f]{40}$")
BRANCH_REF = re.compile(r"^(?:main|master|develop|dev|latest|HEAD|stable|nightly)$", re.IGNORECASE)
VERSIONED = re.compile(r"@\d|==\d|@v?\d+\.\d+")


def _exprs(text: str) -> list[str]:
    return [m.group(1).strip() for m in EXPR.finditer(text or "")]


def _is_third_party(uses: str) -> bool:
    return bool(uses) and not uses.startswith(FIRST_PARTY)


def _action_ref(uses: str) -> str:
    return uses.split("@", 1)[1] if "@" in uses else ""


def _pinned(uses: str) -> bool:
    return bool(SHA_PIN.match(_action_ref(uses)))


def analyze_workflow(wf: Workflow) -> list[Finding]:
    """Run every rule against one workflow. Pure: no I/O, no clock."""
    out: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()

    def emit(rule_id: str, line: int, detail: str, job: str = "", step: str = "") -> None:
        rule = RULES.get(rule_id)
        if rule is None:
            return
        line = max(1, int(line or 1))
        key = (rule_id, line, step)
        if key in seen:
            return
        seen.add(key)
        out.append(
            Finding(
                rule=rule,
                path=wf.path,
                line=line,
                snippet=wf.source_line(line).strip()[:200],
                detail=detail,
                job=job,
                step=step,
            )
        )

    _check_workflow_level(wf, emit)
    for job in wf.jobs:
        _check_job(wf, job, emit)
        for step in job.steps:
            _check_step(wf, job, step, emit)

    triggers = check_event_triggers(wf)
    if any(f.rule.id == "CIV201" for f in out):
        # The exploit-level finding already states the trigger; do not double-report.
        triggers = [f for f in triggers if f.rule.id != "CIV202"]
    out.extend(triggers)

    out.sort(key=lambda f: (f.line, f.rule.id))
    return out


# --------------------------------------------------------------- workflow


def _check_workflow_level(wf: Workflow, emit: Callable[..., None]) -> None:
    events = wf.events
    on = wf.on

    perms = wf.permissions
    if perms is None:
        emit("CIV703", 1, "No top-level permissions: block; the token inherits the repository default.")
    elif str(perms).strip().lower() == "write-all":
        emit("CIV704", _line_of(on, 1) or 1, f"Workflow declares permissions: {perms}.")

    if "push" in events:
        push_cfg = on.get("push") if isinstance(on, dict) else None
        if not isinstance(push_cfg, dict) or not any(
            k in push_cfg for k in ("branches", "branches-ignore", "paths", "paths-ignore", "tags")
        ):
            emit("CIV206", wf.event_line("push"), "on: push has no branch/path filter.")


def _line_of(value: object, default: int = 0) -> int:
    return int(getattr(value, "line", 0) or default)


# --------------------------------------------------------------- job


def _check_job(wf: Workflow, job: Job, emit: Callable[..., None]) -> None:
    events = wf.events
    line = job.line or 1

    if job.permissions is not None:
        p = str(job.permissions).strip().lower()
        if p == "write-all":
            emit("CIV704", line, f"Job '{job.id}' declares permissions: write-all.", job.id)

    if job.uses:
        if not SHA_PIN.match(_action_ref(job.uses).split("/")[0]) and "@" in job.uses:
            ref = _action_ref(job.uses)
            if not SHA_PIN.match(ref):
                emit("CIV306", line, f"Reusable workflow '{job.uses}' is pinned to '{ref}', not a commit SHA.", job.id)
        if str(job.secrets).strip().lower() == "inherit":
            emit("CIV402", line, f"Job '{job.id}' forwards every repository secret via secrets: inherit.", job.id)

    if job.timeout_minutes is None:
        emit("CIV701", line, f"Job '{job.id}' has no timeout-minutes.", job.id)

    env = job.raw.get("env") or {}
    for k, v in (env.items() if isinstance(env, dict) else []):
        if "secrets." in str(v):
            emit("CIV404", _line_of(v) or line, f"Job-level env '{k}' holds a secret, visible to every step.", job.id)

    if job.if_ and "secrets." in job.if_:
        emit("CIV405", line, f"Job condition references a secret: {job.if_.strip()[:80]}", job.id)

    # job-level container image (steps are checked separately)
    container = job.raw.get("container")
    if isinstance(container, str) and container:
        if "@sha256:" not in container and (":latest" in container or ":" not in container.rsplit("/", 1)[-1]):
            emit("CIV304", line, f"Job container image '{container}' is not digest-pinned.", job.id)
    elif isinstance(container, dict) and container.get("image"):
        image = str(container["image"])
        if "@sha256:" not in image and (":latest" in image or ":" not in image.rsplit("/", 1)[-1]):
            emit("CIV304", line, f"Job container image '{image}' is not digest-pinned.", job.id)

    runs_on = str(job.runs_on).lower()
    fork_reachable = {"pull_request", "pull_request_target", "issue_comment", "discussion_comment", "fork", "watch"}
    if "self-hosted" in runs_on and (fork_reachable & set(events)):
        emit(
            "CIV205",
            line,
            f"Job '{job.id}' runs on a self-hosted runner under {sorted(fork_reachable & set(events))}.",
            job.id,
        )

    if DEPLOY_RE.search(job.id) or DEPLOY_RE.search(job.name):
        if not job.environment:
            emit("CIV705", line, f"Deployment-style job '{job.id}' has no environment: protection.", job.id)
        workflow_concurrency = wf.raw.get("concurrency") if hasattr(wf.raw, "get") else None
        if job.concurrency is None and workflow_concurrency is None:
            emit("CIV706", line, f"Deployment-style job '{job.id}' has no concurrency group.", job.id)


# --------------------------------------------------------------- step


def _check_step(wf: Workflow, job: Job, step: Step, emit: Callable[..., None]) -> None:
    line = step.line or job.line or 1
    jid = job.id
    label = step.label
    run = step.run or ""

    # --- injection -----------------------------------------------------
    if run:
        for expr in _exprs(run):
            if TAINTED_EVENT.search(expr):
                emit("CIV101", line, f"run: interpolates attacker-controlled `${{{{ {expr} }}}}`.", jid, label)
            elif TAINTED_SOFT.search(expr):
                emit("CIV102", line, f"run: interpolates influenced context `${{{{ {expr} }}}}`.", jid, label)

    if step.uses.startswith("actions/github-script"):
        script = str(step.with_.get("script", "") or "")
        for expr in _exprs(script):
            emit("CIV103", line, f"github-script executes interpolated `${{{{ {expr} }}}}` as JavaScript.", jid, label)

    for key, value in step.with_.items():
        text = str(value)
        for expr in _exprs(text):
            if TAINTED_EVENT.search(expr) or TAINTED_SOFT.search(expr):
                emit("CIV104", line, f"Action input '{key}' receives untrusted `${{{{ {expr} }}}}`.", jid, label)

    for cond in (step.if_,):
        if cond:
            fired = False
            for expr in _exprs(cond):
                if TAINTED_COND.search(expr):
                    emit("CIV105", line, f"Step condition depends on untrusted `${{{{ {expr} }}}}`.", jid, label)
                    fired = True
            # GitHub accepts bare contexts in `if:` with no ${{ }} — extremely
            # common in real workflows, so a template-only check misses it.
            if not fired and TAINTED_EVENT.search(cond):
                emit("CIV105", line, f"Step condition reads event data directly: {cond.strip()[:80]}", jid, label)

    if job.if_:
        fired = False
        for expr in _exprs(job.if_):
            if TAINTED_COND.search(expr):
                emit("CIV105", job.line or line, f"Job condition depends on untrusted `${{{{ {expr} }}}}`.", jid)
                fired = True
        if not fired and TAINTED_EVENT.search(job.if_):
            emit("CIV105", job.line or line, f"Job condition reads event data directly: {job.if_.strip()[:80]}", jid)

    # --- triggers ------------------------------------------------------
    events = set(wf.events)
    if "pull_request_target" in events:
        ref = str(step.with_.get("ref", "") or "")
        if step.uses.startswith("actions/checkout") and (
            "pull_request.head" in ref or "head_ref" in ref or "github.head_ref" in run
        ):
            emit(
                "CIV201",
                line,
                "pull_request_target checks out PR head code while holding a privileged token.",
                jid,
                label,
            )
        if step.uses.startswith("actions/upload-artifact"):
            emit("CIV602", line, "Artifact published from a pull_request_target run.", jid, label)

    # --- supply chain --------------------------------------------------
    uses = step.uses
    if uses and not uses.startswith("./") and not uses.startswith("docker://"):
        ref = _action_ref(uses)
        if not ref:
            emit("CIV301", line, f"'{uses}' has no version pin at all.", jid, label)
        elif SHA_PIN.match(ref):
            pass
        elif BRANCH_REF.match(ref):
            emit("CIV302", line, f"'{uses}' is pinned to a moving branch.", jid, label)
        else:
            emit("CIV301", line, f"'{uses}' uses tag '{ref}' instead of a commit SHA.", jid, label)

    if uses.startswith("docker://"):
        image = uses[len("docker://") :]
        if "@sha256:" not in image and (":latest" in image or ":" not in image.rsplit("/", 1)[-1]):
            emit("CIV304", line, f"Container image '{image}' is not digest-pinned.", jid, label)

    if uses.startswith("actions/checkout") and str(step.with_.get("persist-credentials", "")).lower() != "false":
        emit("CIV303", line, "checkout does not set persist-credentials: false.", jid, label)

    # --- secrets -------------------------------------------------------
    if "secrets.GITHUB_TOKEN" in run:
        emit("CIV401", line, "run: references secrets.GITHUB_TOKEN directly.", jid, label)

    if _is_third_party(uses):
        for key, value in step.with_.items():
            v = str(value)
            if "secrets." not in v:
                continue
            if "GITHUB_TOKEN" in v or "secrets.PAT" in v or "secrets.GH_" in v:
                emit("CIV305", line, f"Third-party action '{uses}' receives a token via '{key}'.", jid, label)
            else:
                emit("CIV403", line, f"Third-party action input '{key}' receives a secret.", jid, label)
            break

    # --- execution -----------------------------------------------------
    if SHELL_PIPE.search(run):
        emit("CIV501", line, "Remote content is piped straight into an interpreter.", jid, label)
    if EVAL.search(run):
        emit("CIV502", line, "Shell evaluation builds a command from a variable.", jid, label)
    if TOOL_RUN.search(run) and not VERSIONED.search(run):
        emit("CIV503", line, "Package runner resolves the newest published version at run time.", jid, label)
    if OUTPUT_CMD.search(run):
        emit("CIV504", line, "Uses the removed set-output/save-state workflow command.", jid, label)
    if GITHUB_FILE.search(run) and re.search(r"\$\(|`|\$\w+|GITHUB_(?:ENV|PATH|OUTPUT)", run):
        emit("CIV505", line, "Writes a dynamic value into GITHUB_ENV/GITHUB_PATH.", jid, label)

    # --- artifact / cache ----------------------------------------------
    if uses.startswith(("actions/cache", "actions/cache/restore", "actions/cache/save")) or "cache" in uses:
        blob = " ".join(str(v) for v in (step.with_.get("key"), step.with_.get("restore-keys"), step.with_.get("path")))
        for expr in _exprs(blob):
            if TAINTED_EVENT.search(expr) or TAINTED_SOFT.search(expr):
                emit("CIV601", line, f"Cache key derives from untrusted `${{{{ {expr} }}}}`.", jid, label)

    if uses.startswith("actions/upload-artifact") and "retention-days" not in step.with_:
        emit("CIV603", line, "upload-artifact sets no retention-days.", jid, label)

    # --- hygiene -------------------------------------------------------
    if step.continue_on_error and SECURITY_STEP_RE.search(label or run):
        emit("CIV702", line, f"'{label}' is a check but cannot fail the build.", jid, label)


def check_event_triggers(wf: Workflow) -> list[Finding]:
    """Trigger rules are workflow-level and must fire even with no jobs."""
    out: list[Finding] = []
    seen: set[str] = set()

    def emit(rule_id: str, line: int, detail: str, job: str = "", step: str = "") -> None:
        rule = RULES.get(rule_id)
        if rule is None or rule_id in seen:
            return
        seen.add(rule_id)
        out.append(
            Finding(
                rule=rule,
                path=wf.path,
                line=max(1, line or 1),
                snippet=wf.source_line(max(1, line or 1)).strip()[:200],
                detail=detail,
                job=job,
                step=step,
            )
        )

    events = set(wf.events)
    if "pull_request_target" in events:
        emit("CIV202", wf.event_line("pull_request_target") or 1, "Workflow can be started by an outsider's PR.")
    if "workflow_run" in events:
        emit("CIV203", wf.event_line("workflow_run") or 1, "Workflow consumes the output of an untrusted run.")
    if {"issue_comment", "discussion_comment"} & events:
        ev = min({"issue_comment", "discussion_comment"} & events)
        emit("CIV204", wf.event_line(ev) or 1, f"Workflow starts from comment text ({ev}).")
    return out
