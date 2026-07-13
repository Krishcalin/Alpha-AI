"""amass wrapper — passive/active subdomain enumeration."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.amass import parse_amass

_runner = CommandRunner()


async def amass_scan(
    target: str,
    passive: bool = True,
    brute: bool = False,
    timeout: float = 600.0,
) -> ToolResult:
    """Enumerate subdomains of *target* (a root domain) with amass.

    Args:
        target: Root domain (e.g. "example.com"). Must be authorized.
        passive: Passive mode only — no direct target resolution (-passive).
        brute: Enable subdomain brute forcing (-brute).
    """
    cmd = ["amass", "enum", "-d", target]
    if passive:
        cmd.append("-passive")
    if brute:
        cmd.append("-brute")

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_amass(cmd_result.stdout, target=target)

    return ToolResult(
        tool="amass",
        target=target,
        args={"passive": passive, "brute": brute},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="amass",
        category=ToolCategory.RECON,
        description="Subdomain enumeration (passive + optional brute) for a root domain (amass).",
        fn=amass_scan,
        parameters={
            "target": {"type": "string", "required": True, "description": "root domain"},
            "passive": {"type": "boolean", "default": True},
            "brute": {"type": "boolean", "default": False},
        },
    )
)
