"""sqlmap wrapper — automated SQL injection detection."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.sqlmap import parse_sqlmap

_runner = CommandRunner()


async def sqlmap_scan(
    target: str,
    data: str | None = None,
    cookie: str | None = None,
    level: int = 1,
    risk: int = 1,
    technique: str = "BEUSTQ",
    timeout: float = 1200.0,
) -> ToolResult:
    """Run sqlmap in non-interactive batch mode against *target* (URL).

    Args:
        target: Target URL.
        data: POST data string.
        cookie: Cookie header.
        level: Detection level (1-5).
        risk: Risk level (1-3).
        technique: Injection techniques (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline).
    """
    cmd = [
        "sqlmap",
        "-u", target,
        "--batch",
        "--level", str(level),
        "--risk", str(risk),
        "--technique", technique,
        "--disable-coloring",
    ]
    if data:
        cmd += ["--data", data]
    if cookie:
        cmd += ["--cookie", cookie]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_sqlmap(cmd_result.stdout, target=target)

    return ToolResult(
        tool="sqlmap",
        target=target,
        args={
            "data": data,
            "cookie": cookie,
            "level": level,
            "risk": risk,
            "technique": technique,
        },
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="sqlmap",
        category=ToolCategory.WEB,
        description="Automated SQL injection detection and exploitation (sqlmap).",
        fn=sqlmap_scan,
        parameters={
            "target": {"type": "string", "required": True, "format": "url"},
            "data": {"type": "string", "description": "POST data string"},
            "cookie": {"type": "string"},
            "level": {"type": "integer", "default": 1, "min": 1, "max": 5},
            "risk": {"type": "integer", "default": 1, "min": 1, "max": 3},
            "technique": {"type": "string", "default": "BEUSTQ"},
        },
    )
)
