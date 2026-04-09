"""nuclei wrapper — template-based vulnerability scanning."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.nuclei import parse_nuclei_jsonl

_runner = CommandRunner()


async def nuclei_scan(
    target: str,
    severity: str | None = None,
    tags: list[str] | None = None,
    templates: str | None = None,
    rate_limit: int = 150,
    timeout: float = 1200.0,
) -> ToolResult:
    """Run a nuclei scan against *target* (URL).

    Args:
        target: Target URL (must be authorized).
        severity: Comma-separated severities to include (e.g. "high,critical").
        tags: List of template tags to include.
        templates: Path or selector for templates (-t).
        rate_limit: Requests per second.
    """
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-rl", str(rate_limit)]
    if severity:
        cmd += ["-severity", severity]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    if templates:
        cmd += ["-t", templates]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_nuclei_jsonl(cmd_result.stdout, target=target)

    return ToolResult(
        tool="nuclei",
        target=target,
        args={
            "severity": severity,
            "tags": tags or [],
            "templates": templates,
            "rate_limit": rate_limit,
        },
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="nuclei",
        category=ToolCategory.WEB,
        description="Template-based vulnerability scanner (nuclei) for web targets.",
        fn=nuclei_scan,
        parameters={
            "target": {"type": "string", "required": True, "format": "url"},
            "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
            "tags": {"type": "array", "items": "string"},
            "templates": {"type": "string"},
            "rate_limit": {"type": "integer", "default": 150},
        },
    )
)
