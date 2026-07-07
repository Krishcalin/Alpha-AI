"""nikto wrapper — web server misconfiguration and vulnerability scanning."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.nikto import parse_nikto

_runner = CommandRunner()


async def nikto_scan(
    target: str,
    port: int | None = None,
    ssl: bool = False,
    tuning: str | None = None,
    timeout: float = 900.0,
) -> ToolResult:
    """Run nikto against a web *target*.

    Args:
        target: Host or URL. Must be authorized.
        port: Target port (nikto -p).
        ssl: Force SSL/TLS (nikto -ssl).
        tuning: nikto -Tuning string (e.g. "123bde") to scope test categories.
    """
    cmd = ["nikto", "-h", target, "-Format", "csv", "-output", "-", "-nointeractive"]
    if port is not None:
        cmd += ["-p", str(port)]
    if ssl:
        cmd.append("-ssl")
    if tuning:
        cmd += ["-Tuning", tuning]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_nikto(cmd_result.stdout, target=target)

    return ToolResult(
        tool="nikto",
        target=target,
        args={"port": port, "ssl": ssl, "tuning": tuning},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="nikto",
        category=ToolCategory.WEB,
        description="Web server misconfiguration and known-vulnerability scanning (nikto).",
        fn=nikto_scan,
        parameters={
            "target": {"type": "string", "required": True, "format": "url"},
            "port": {"type": "integer"},
            "ssl": {"type": "boolean", "default": False},
            "tuning": {"type": "string", "description": "nikto -Tuning categories"},
        },
    )
)
