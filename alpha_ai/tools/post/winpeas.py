"""winpeas wrapper — ingest a captured winPEAS output file.

Local-only: no remote target, no network whitelist. The *target* is the path to
the winPEAS output the operator captured on the compromised Windows host.
"""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.parsers.peass import parse_peass
from alpha_ai.tools.post._ingest import read_result_file


async def winpeas_ingest(target: str) -> ToolResult:
    """Parse a captured winPEAS output file at *target* into privesc findings.

    Args:
        target: Path to the winPEAS output file (run with ANSI color for best results).
    """
    raw, cmd_result = read_result_file("winpeas", target)
    findings = parse_peass(raw, target=target, tool="winpeas") if cmd_result.returncode == 0 else []

    return ToolResult(
        tool="winpeas",
        target=target,
        args={},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="winpeas",
        category=ToolCategory.POST,
        description="Ingest a captured winPEAS output file and extract Windows privesc vectors (local-only).",
        fn=winpeas_ingest,
        parameters={
            "target": {"type": "string", "required": True, "description": "Path to winPEAS output file"},
        },
        requires_authorization=False,
    )
)
