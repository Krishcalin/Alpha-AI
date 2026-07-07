"""certipy wrapper — Active Directory Certificate Services (ADCS) enumeration."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.certipy import parse_certipy

_runner = CommandRunner()


async def certipy_scan(
    target: str,
    domain: str,
    username: str,
    password: str | None = None,
    hashes: str | None = None,
    vulnerable_only: bool = True,
    timeout: float = 600.0,
) -> ToolResult:
    """Enumerate ADCS templates/CAs on *target* (a DC) and flag ESC* abuses with certipy.

    Args:
        target: Domain controller host/IP (used as -dc-ip). Must be authorized.
        domain: AD domain (e.g. "corp.local").
        username: Domain user for the -u user@domain identity.
        password: Password (or use *hashes*).
        hashes: NT hash for pass-the-hash (-hashes).
        vulnerable_only: Restrict output to vulnerable templates (-vulnerable).
    """
    cmd = [
        "certipy", "find",
        "-u", f"{username}@{domain}",
        "-dc-ip", target,
        "-stdout", "-json",
    ]
    if password is not None:
        cmd += ["-p", password]
    if hashes:
        cmd += ["-hashes", hashes]
    if vulnerable_only:
        cmd.append("-vulnerable")

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_certipy(cmd_result.stdout, target=target)

    return ToolResult(
        tool="certipy",
        target=target,
        args={"domain": domain, "username": username, "vulnerable_only": vulnerable_only},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="certipy",
        category=ToolCategory.AD,
        description="ADCS enumeration and ESC1-ESC8 misconfiguration discovery (certipy find).",
        fn=certipy_scan,
        parameters={
            "target": {"type": "string", "required": True, "description": "DC host/IP"},
            "domain": {"type": "string", "required": True},
            "username": {"type": "string", "required": True},
            "password": {"type": "string"},
            "hashes": {"type": "string", "description": "NT hash for pass-the-hash"},
            "vulnerable_only": {"type": "boolean", "default": True},
        },
    )
)
