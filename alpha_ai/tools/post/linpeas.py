"""linpeas wrapper — ingest a captured linpeas.sh output file.

Local-only: no remote target, no network whitelist. The *target* is the path to
the linpeas output the operator captured on the compromised Linux host.
"""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.parsers.peass import parse_peass
from alpha_ai.tools.post._ingest import read_result_file


async def linpeas_ingest(target: str) -> ToolResult:
    """Parse a captured linpeas output file at *target* into privesc findings.

    Args:
        target: Path to the linpeas.sh output file (ANSI color preserved is best).
    """
    raw, cmd_result = read_result_file("linpeas", target)
    findings = parse_peass(raw, target=target, tool="linpeas") if cmd_result.returncode == 0 else []

    return ToolResult(
        tool="linpeas",
        target=target,
        args={},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="linpeas",
        category=ToolCategory.POST,
        description="Ingest a captured linpeas.sh output file and extract Linux privesc vectors (local-only).",
        fn=linpeas_ingest,
        parameters={
            "target": {"type": "string", "required": True, "description": "Path to linpeas output file"},
        },
        requires_authorization=False,
    )
)
