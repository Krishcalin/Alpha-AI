"""kerbrute wrapper — Kerberos pre-auth user enumeration and password spraying."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.kerbrute import parse_kerbrute

_runner = CommandRunner()


async def kerbrute_scan(
    target: str,
    domain: str,
    mode: str = "userenum",
    userlist: str | None = None,
    password: str | None = None,
    dc: str | None = None,
    timeout: float = 600.0,
) -> ToolResult:
    """Run kerbrute against a domain via *target* (the KDC/DC).

    Args:
        target: DC / KDC host or IP. Must be authorized.
        domain: Kerberos realm (e.g. "lab.internal").
        mode: "userenum" (enumerate valid users) or "passwordspray" (test one password).
        userlist: Path to a username wordlist (required for both modes).
        password: Single password to spray (required for passwordspray).
        dc: Explicit domain controller (--dc); defaults to *target*.
    """
    if mode not in {"userenum", "passwordspray"}:
        raise ValueError(f"unsupported kerbrute mode: {mode}")

    cmd = ["kerbrute", mode, "-d", domain, "--dc", dc or target]
    if userlist:
        cmd.append(userlist)
    if mode == "passwordspray" and password is not None:
        cmd.append(password)

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_kerbrute(cmd_result.stdout, target=target)

    return ToolResult(
        tool="kerbrute",
        target=target,
        args={"domain": domain, "mode": mode, "userlist": userlist, "dc": dc or target},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="kerbrute",
        category=ToolCategory.AD,
        description="Kerberos user enumeration and password spraying against a DC (kerbrute).",
        fn=kerbrute_scan,
        parameters={
            "target": {"type": "string", "required": True, "description": "DC/KDC host"},
            "domain": {"type": "string", "required": True},
            "mode": {"type": "string", "default": "userenum", "enum": ["userenum", "passwordspray"]},
            "userlist": {"type": "string", "description": "path to username wordlist"},
            "password": {"type": "string", "description": "password to spray (passwordspray mode)"},
            "dc": {"type": "string", "description": "explicit domain controller"},
        },
    )
)
