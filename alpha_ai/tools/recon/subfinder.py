"""subfinder wrapper — passive subdomain enumeration."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.subfinder import parse_subfinder

_runner = CommandRunner()


async def subfinder_scan(
    target: str,
    all_sources: bool = False,
    recursive: bool = False,
    timeout: float = 300.0,
) -> ToolResult:
    """Enumerate subdomains of *target* (a root domain) with subfinder.

    Args:
        target: Root domain (e.g. "example.com"). Must be authorized.
        all_sources: Use all sources, including slow ones (-all).
        recursive: Only use sources that can handle subdomains recursively (-recursive).
    """
    cmd = ["subfinder", "-d", target, "-oJ", "-silent"]
    if all_sources:
        cmd.append("-all")
    if recursive:
        cmd.append("-recursive")

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_subfinder(cmd_result.stdout, target=target)

    return ToolResult(
        tool="subfinder",
        target=target,
        args={"all_sources": all_sources, "recursive": recursive},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="subfinder",
        category=ToolCategory.RECON,
        description="Passive subdomain enumeration for a root domain (subfinder).",
        fn=subfinder_scan,
        parameters={
            "target": {"type": "string", "required": True, "description": "root domain"},
            "all_sources": {"type": "boolean", "default": False},
            "recursive": {"type": "boolean", "default": False},
        },
    )
)
