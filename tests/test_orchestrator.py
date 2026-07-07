"""Tests for the autopilot Orchestrator loop (Phase 3) with a fake dispatcher."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from alpha_ai.agents.orchestrator import Orchestrator
from alpha_ai.agents.planner import Engagement
from alpha_ai.core.models import CommandResult, Finding, Severity, ToolResult

ALL_TOOLS = {
    "nmap", "subfinder", "nuclei", "nikto", "gobuster",
    "enum4linux", "crackmapexec",
}


class FakeDispatcher:
    """Records calls; returns scripted findings per tool."""

    def __init__(self, scripts: dict[str, Callable[[str], list[Finding]]] | None = None) -> None:
        self.scripts = scripts or {}
        self.calls: list[tuple[str, str, dict]] = []

    async def run_tool(self, tool_name: str, target: str, use_cache: bool = True, **kwargs):
        self.calls.append((tool_name, target, kwargs))
        findings = self.scripts.get(tool_name, lambda _t: [])(target)
        return ToolResult(
            tool=tool_name,
            target=target,
            args=kwargs,
            command=CommandResult(command=[tool_name], returncode=0, stdout="", stderr="", duration_sec=0.0),
            findings=findings,
        )


def _open_port(port: str, target: str) -> Finding:
    return Finding(tool="nmap", target=target, title=f"Open port {port}",
                   severity=Severity.INFO, evidence={"port": port})


@pytest.mark.asyncio
async def test_external_pentest_chains_from_open_ports() -> None:
    # nmap reports 445 + 80 on the target → orchestrator should expand to SMB + web tools.
    def nmap_findings(target: str) -> list[Finding]:
        return [_open_port("445", target), _open_port("80", target)]

    fake = FakeDispatcher({"nmap": nmap_findings})
    orch = Orchestrator(fake, available_tools=ALL_TOOLS)
    result = await orch.run(Engagement(target="example.com"), "external-pentest")

    called = {c[0] for c in fake.calls}
    assert "nmap" in called          # seed
    assert "subfinder" in called     # seed (domain target)
    assert {"enum4linux", "crackmapexec"} <= called  # from 445
    assert {"nuclei", "nikto", "gobuster"} <= called  # from 80

    # web tools were pointed at a URL, not the bare host
    web = [c for c in fake.calls if c[0] == "nuclei"][0]
    assert web[1] == "http://example.com"

    assert result.template == "external-pentest"
    assert result.summary["total"] == 2  # two port findings, deduped


@pytest.mark.asyncio
async def test_no_step_runs_twice() -> None:
    def nmap_findings(target: str) -> list[Finding]:
        return [_open_port("445", target)]

    fake = FakeDispatcher({"nmap": nmap_findings})
    orch = Orchestrator(fake, available_tools=ALL_TOOLS)
    await orch.run(Engagement(target="10.0.0.5"), "external-pentest")

    keys = [(c[0], c[1], tuple(sorted(c[2].items()))) for c in fake.calls]
    assert len(keys) == len(set(keys)), "a step was executed more than once"


@pytest.mark.asyncio
async def test_unavailable_tool_recorded_not_crashed() -> None:
    fake = FakeDispatcher({"nmap": lambda t: [_open_port("445", t)]})
    # enum4linux/crackmapexec intentionally absent from availability
    orch = Orchestrator(fake, available_tools={"nmap"})
    result = await orch.run(Engagement(target="10.0.0.5"), "external-pentest")

    assert not any(c[0] == "enum4linux" for c in fake.calls)  # never dispatched
    # nmap ran fine
    assert any(s.tool == "nmap" and s.ok for s in result.steps)


@pytest.mark.asyncio
async def test_dispatcher_error_is_caught() -> None:
    class Boom(FakeDispatcher):
        async def run_tool(self, tool_name, target, use_cache=True, **kwargs):
            if tool_name == "nmap":
                raise RuntimeError("scan failed")
            return await super().run_tool(tool_name, target, use_cache=use_cache, **kwargs)

    orch = Orchestrator(Boom(), available_tools=ALL_TOOLS)
    result = await orch.run(Engagement(target="10.0.0.5"), "external-pentest")
    nmap_step = [s for s in result.steps if s.tool == "nmap"][0]
    assert nmap_step.ok is False
    assert "scan failed" in (nmap_step.error or "")


@pytest.mark.asyncio
async def test_unknown_template_rejected() -> None:
    with pytest.raises(ValueError):
        await Orchestrator(FakeDispatcher(), available_tools=ALL_TOOLS).run(
            Engagement(target="x"), "does-not-exist"
        )
