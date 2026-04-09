"""enum4linux wrapper — SMB/Samba enumeration."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.enum4linux import parse_enum4linux

_runner = CommandRunner()


async def enum4linux_scan(
    target: str,
    aggressive: bool = False,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 600.0,
) -> ToolResult:
    """Run enum4linux against an SMB target."""
    cmd = ["enum4linux"]
    cmd.append("-A" if aggressive else "-a")
    if username:
        cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    cmd.append(target)

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_enum4linux(cmd_result.stdout, target=target)

    return ToolResult(
        tool="enum4linux",
        target=target,
        args={"aggressive": aggressive, "username": username},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="enum4linux",
        category=ToolCategory.NETWORK,
        description="SMB/Samba enumeration (shares, users, OS, policies).",
        fn=enum4linux_scan,
        parameters={
            "target": {"type": "string", "required": True},
            "aggressive": {"type": "boolean", "default": False},
            "username": {"type": "string"},
            "password": {"type": "string"},
        },
    )
)
