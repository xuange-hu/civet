"""Turn a parsed workflow into a typed model the rules can walk."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .yamlscan import L, M, loads

WORKFLOW_SUFFIXES = (".yml", ".yaml")


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return ""
    return str(value)


def _as_map(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, str):
        return [value]
    return []


def _line_of(value: Any, default: int = 0) -> int:
    return int(getattr(value, "line", 0) or default)


@dataclass
class Step:
    job: str
    index: int
    name: str
    line: int
    uses: str = ""
    run: str = ""
    if_: str = ""
    with_: dict = field(default_factory=dict)
    env: dict = field(default_factory=dict)
    continue_on_error: bool = False
    timeout_minutes: int | None = None
    raw: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.name or self.uses or f"step[{self.index}]"


@dataclass
class Job:
    id: str
    line: int
    name: str = ""
    runs_on: str = ""
    if_: str = ""
    permissions: Any = None
    environment: Any = None
    timeout_minutes: int | None = None
    uses: str = ""
    secrets: Any = None
    concurrency: Any = None
    steps: list[Step] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class Workflow:
    path: str
    text: str
    raw: Any
    line_count: int

    @property
    def on(self) -> Any:
        return _as_map(self.raw).get("on") or _as_map(self.raw).get("on_")

    @property
    def events(self) -> list[str]:
        """Trigger event names — accepts mapping, sequence, or bare string."""
        on = self.on
        if isinstance(on, dict):
            return [str(k) for k in on]
        if isinstance(on, list):
            return [str(v) for v in on]
        if isinstance(on, str) and on:
            return [on]
        return []

    def event_line(self, event: str) -> int:
        on = self.on
        if isinstance(on, dict) and event in on:
            return int(getattr(on, "klines", {}).get(event, 0))
        if isinstance(on, list) and event in on:
            for i, v in enumerate(on):
                if str(v) == event:
                    return int(getattr(on, "ilines", {}).get(i, 0))
        return _line_of(on)

    @property
    def permissions(self) -> Any:
        return _as_map(self.raw).get("permissions")

    @property
    def jobs(self) -> list[Job]:
        return build_jobs(self)

    def source_line(self, n: int) -> str:
        if 1 <= n <= self.line_count:
            return self.text.splitlines()[n - 1].rstrip()
        return ""

    def line_of_key(self, key: str, default: int = 0) -> int:
        return int(_as_map(self.raw).get(key, None) and _line_of(_as_map(self.raw).get(key)) or default)


def build_steps(job_id: str, raw_job: dict) -> list[Step]:
    steps: list[Step] = []
    for i, raw_step in enumerate(_as_list(raw_job.get("steps"))):
        if not isinstance(raw_step, dict):
            continue
        name = _as_str(raw_step.get("name"))
        line = _line_of(raw_step.get("name")) or _line_of(raw_step.get("uses")) or _line_of(raw_step.get("run"))
        if not line:
            line = int(getattr(raw_step, "line", 0))
        timeout = raw_step.get("timeout-minutes")
        steps.append(
            Step(
                job=job_id,
                index=i,
                name=name,
                line=line,
                uses=_as_str(raw_step.get("uses")),
                run=_as_str(raw_step.get("run")),
                if_=_as_str(raw_step.get("if")),
                with_=_as_map(raw_step.get("with")),
                env=_as_map(raw_step.get("env")),
                continue_on_error=bool(raw_step.get("continue-on-error")),
                timeout_minutes=int(timeout) if isinstance(timeout, (int, float)) else None,
                raw=raw_step,
            )
        )
    return steps


def build_jobs(wf: Workflow) -> list[Job]:
    out: list[Job] = []
    raw_jobs = _as_map(_as_map(wf.raw).get("jobs"))
    for job_id, raw_job in raw_jobs.items():
        raw_job = _as_map(raw_job)
        timeout = raw_job.get("timeout-minutes")
        out.append(
            Job(
                id=str(job_id),
                line=int(getattr(raw_job, "line", 0) or getattr(raw_jobs, "klines", {}).get(job_id, 0)),
                name=_as_str(raw_job.get("name")),
                runs_on=_as_str(raw_job.get("runs-on")),
                if_=_as_str(raw_job.get("if")),
                permissions=raw_job.get("permissions"),
                environment=raw_job.get("environment"),
                timeout_minutes=int(timeout) if isinstance(timeout, (int, float)) else None,
                uses=_as_str(raw_job.get("uses")),
                secrets=raw_job.get("secrets"),
                concurrency=raw_job.get("concurrency"),
                steps=build_steps(str(job_id), raw_job),
                raw=raw_job,
            )
        )
    return out


def parse_workflow(path: str, text: str) -> Workflow:
    raw = loads(text)
    return Workflow(
        path=path,
        text=text,
        raw=raw,
        line_count=len(text.splitlines()),
    )


__all__ = ["WORKFLOW_SUFFIXES", "Job", "L", "M", "Step", "Workflow", "parse_workflow"]
