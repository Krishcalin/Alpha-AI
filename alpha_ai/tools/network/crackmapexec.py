"""crackmapexec wrapper — network/AD pentesting swiss-army knife."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.crackmapexec import parse_crackmapexec

_runner = CommandRunner()


async def crackmapexec_scan(
    target: str,
    protocol: str = "smb",
    username: str | None = None,
    password: str | None = None,
    hash: str | None = None,
    domain: str | None = None,
    module: str | None = None,
    shares: bool = False,
    users: bool = False,
    timeout: float = 600.0,
) -> ToolResult:
    """Run crackmapexec against *target*.

    Args:
        target: Host, IP, or CIDR.
        protocol: smb, winrm, ldap, mssql, ssh, ftp, rdp, vnc.
        username, password: Credentials.
        hash: NT hash for pass-the-hash.
        domain: AD domain.
        module: CME module name (e.g. "lsassy", "spider_plus").
        shares: Add --shares flag.
        users: Add --users flag.
    """
    cmd = ["crackmapexec", protocol, target]
    if username:
        cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    if hash:
        cmd += ["-H", hash]
    if domain:
        cmd += ["-d", domain]
    if module:
        cmd += ["-M", module]
    if shares:
        cmd.append("--shares")
    if users:
        cmd.append("--users")

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_crackmapexec(cmd_result.stdout, target=target)

    return ToolResult(
        tool="crackmapexec",
        target=target,
        args={
            "protocol": protocol,
            "username": username,
            "domain": domain,
            "module": module,
            "shares": shares,
            "users": users,
        },
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="crackmapexec",
        category=ToolCategory.NETWORK,
        description="Multi-protocol network pentesting tool (SMB/WinRM/LDAP/MSSQL/SSH/FTP/RDP/VNC).",
        fn=crackmapexec_scan,
        parameters={
            "target": {"type": "string", "required": True},
            "protocol": {
                "type": "string",
                "default": "smb",
                "enum": ["smb", "winrm", "ldap", "mssql", "ssh", "ftp", "rdp", "vnc"],
            },
            "username": {"type": "string"},
            "password": {"type": "string"},
            "hash": {"type": "string", "description": "NT hash for pass-the-hash"},
            "domain": {"type": "string"},
            "module": {"type": "string"},
            "shares": {"type": "boolean", "default": False},
            "users": {"type": "boolean", "default": False},
        },
    )
)
