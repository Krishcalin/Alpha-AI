"""hydra wrapper — network login brute-forcer."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.hydra import parse_hydra

_runner = CommandRunner()


async def hydra_scan(
    target: str,
    service: str = "ssh",
    username: str | None = None,
    username_list: str | None = None,
    password: str | None = None,
    password_list: str | None = None,
    port: int | None = None,
    threads: int = 16,
    stop_on_first: bool = True,
    extra_args: list[str] | None = None,
    timeout: float = 1800.0,
) -> ToolResult:
    """Run hydra against *target*.

    Args:
        target: Host or IP (must be authorized).
        service: ssh, ftp, smb, mysql, postgres, rdp, http-get, http-post-form, etc.
        username / username_list: Single user or path to wordlist (mutually exclusive).
        password / password_list: Single password or path to wordlist (mutually exclusive).
        port: Override the service's default port.
        threads: -t flag (parallel tasks).
        stop_on_first: Add -f to exit on first valid pair.
    """
    if not (username or username_list):
        raise ValueError("hydra: provide username or username_list")
    if not (password or password_list):
        raise ValueError("hydra: provide password or password_list")

    cmd = ["hydra", "-I", "-t", str(threads)]
    if username:
        cmd += ["-l", username]
    else:
        cmd += ["-L", username_list]
    if password:
        cmd += ["-p", password]
    else:
        cmd += ["-P", password_list]
    if port:
        cmd += ["-s", str(port)]
    if stop_on_first:
        cmd.append("-f")
    if extra_args:
        cmd.extend(extra_args)
    cmd += [target, service]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_hydra(cmd_result.stdout, target=target)

    return ToolResult(
        tool="hydra",
        target=target,
        args={
            "service": service,
            "username": username,
            "username_list": username_list,
            "password_list": password_list,
            "port": port,
            "threads": threads,
            "stop_on_first": stop_on_first,
        },
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="hydra",
        category=ToolCategory.CRED,
        description="Network login brute-forcer (SSH/FTP/SMB/RDP/HTTP/MySQL/Postgres/...).",
        fn=hydra_scan,
        parameters={
            "target": {"type": "string", "required": True},
            "service": {"type": "string", "default": "ssh"},
            "username": {"type": "string"},
            "username_list": {"type": "string", "description": "Path to username wordlist"},
            "password": {"type": "string"},
            "password_list": {"type": "string", "description": "Path to password wordlist"},
            "port": {"type": "integer"},
            "threads": {"type": "integer", "default": 16},
            "stop_on_first": {"type": "boolean", "default": True},
        },
    )
)
