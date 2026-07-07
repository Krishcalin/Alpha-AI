"""Autopilot orchestrator — seed from a template, then chain tools from findings.

Loop: run the queued steps via the dispatcher → collect + dedupe findings → ask
the planner for follow-on steps → repeat until the queue drains, a round cap, or
a step cap. Every step runs at most once (keyed by tool+target+params). The
dispatcher is injected so the loop is fully unit-testable with a fake.
"""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, Field

from alpha_ai.agents.planner import Engagement, PlanContext, Planner, RulePlanner, Step
from alpha_ai.agents.templates import seed_steps
from alpha_ai.core.dedup import dedupe_findings
from alpha_ai.core.models import Finding, ToolResult


class _Dispatcher(Protocol):
    async def run_tool(self, tool_name: str, target: str, use_cache: bool = True, **kwargs: Any) -> ToolResult:
        ...


class ExecutedStep(BaseModel):
    tool: str
    target: str
    reason: str = ""
    ok: bool = True
    finding_count: int = 0
    error: str | None = None


class OrchestrationResult(BaseModel):
    template: str
    target: str
    rounds: int
    steps: list[ExecutedStep] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)


def _summary(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {"total": len(findings)}
    for f in findings:
        out[f.severity.value] = out.get(f.severity.value, 0) + 1
    return out


class Orchestrator:
    def __init__(
        self,
        dispatcher: _Dispatcher,
        planner: Planner | None = None,
        available_tools: set[str] | None = None,
        max_rounds: int = 3,
        max_steps: int = 50,
        use_cache: bool = True,
    ) -> None:
        self.dispatcher = dispatcher
        self.planner = planner or RulePlanner()
        self._available = available_tools
        self.max_rounds = max_rounds
        self.max_steps = max_steps
        self.use_cache = use_cache

    def _available_tools(self) -> set[str]:
        if self._available is not None:
            return self._available
        from alpha_ai.core.registry import registry  # lazy: avoid import cycle at module load
        return {s.name for s in registry.all()}

    async def run(self, engagement: Engagement, template: str) -> OrchestrationResult:
        available = self._available_tools()
        queue: list[Step] = seed_steps(template, engagement)
        ran: set[str] = set()
        executed: list[ExecutedStep] = []
        findings: list[Finding] = []
        rounds = 0

        while queue and rounds < self.max_rounds and len(ran) < self.max_steps:
            batch, queue = queue, []
            for step in batch:
                if len(ran) >= self.max_steps:
                    break
                key = step.key()
                if key in ran:
                    continue
                ran.add(key)

                if step.tool not in available:
                    executed.append(ExecutedStep(
                        tool=step.tool, target=step.target, reason=step.reason,
                        ok=False, error="tool not available",
                    ))
                    continue

                try:
                    res = await self.dispatcher.run_tool(
                        step.tool, target=step.target, use_cache=self.use_cache, **step.kwargs
                    )
                except Exception as e:  # authz/tool-missing/etc — record and keep going
                    executed.append(ExecutedStep(
                        tool=step.tool, target=step.target, reason=step.reason,
                        ok=False, error=f"{type(e).__name__}: {e}",
                    ))
                    continue

                findings.extend(res.findings)
                executed.append(ExecutedStep(
                    tool=step.tool, target=step.target, reason=step.reason,
                    ok=res.success, finding_count=len(res.findings),
                ))

            findings = dedupe_findings(findings)
            ctx = PlanContext(engagement=engagement, findings=findings, ran=ran, available=available)
            for s in self.planner.next_steps(ctx):
                if s.key() not in ran:
                    queue.append(s)
            rounds += 1

        findings = dedupe_findings(findings)
        return OrchestrationResult(
            template=template,
            target=engagement.target,
            rounds=rounds,
            steps=executed,
            findings=findings,
            summary=_summary(findings),
        )
