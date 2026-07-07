"""masscan wrapper — high-speed port scanning."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.masscan import parse_masscan

_runner = CommandRunner()


async def masscan_scan(
    target: str,
    ports: str = "1-1000",
    rate: int = 1000,
    timeout: float = 600.0,
) -> ToolResult:
    """Run a high-speed masscan against *target*.

    Args:
        target: Host, IP, or CIDR. Must be authorized.
        ports: Port spec (e.g. "80,443", "1-65535").
        rate: Packets per second (masscan --rate).
    """
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "-oJ", "-"]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_masscan(cmd_result.stdout, target=target)

    return ToolResult(
        tool="masscan",
        target=target,
        args={"ports": ports, "rate": rate},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="masscan",
        category=ToolCategory.RECON,
        description="High-speed asynchronous port scanning (masscan). Requires root.",
        fn=masscan_scan,
        parameters={
            "target": {"type": "string", "required": True},
            "ports": {"type": "string", "default": "1-1000"},
            "rate": {"type": "integer", "default": 1000},
        },
        requires_root=True,
    )
)
