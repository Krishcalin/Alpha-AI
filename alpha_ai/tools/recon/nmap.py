"""nmap wrapper — port discovery + service detection."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.nmap import parse_nmap_xml

_runner = CommandRunner()


async def nmap_scan(
    target: str,
    ports: str = "1-1000",
    service_detection: bool = True,
    timing: int = 4,
    extra_args: list[str] | None = None,
    timeout: float = 600.0,
) -> ToolResult:
    """Run an nmap scan against *target*.

    Args:
        target: Host, IP, or CIDR. Must be authorized.
        ports: Port spec (e.g. "1-1000", "22,80,443", "-" for all).
        service_detection: Adds -sV.
        timing: nmap -T flag, 0-5.
        extra_args: Additional CLI arguments appended verbatim.
    """
    cmd = ["nmap", "-Pn", f"-T{timing}", "-p", ports, "-oX", "-"]
    if service_detection:
        cmd.append("-sV")
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(target)

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_nmap_xml(cmd_result.stdout, target=target)

    return ToolResult(
        tool="nmap",
        target=target,
        args={
            "ports": ports,
            "service_detection": service_detection,
            "timing": timing,
            "extra_args": extra_args or [],
        },
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="nmap",
        category=ToolCategory.RECON,
        description="Port scanning and service detection with nmap.",
        fn=nmap_scan,
        parameters={
            "target": {"type": "string", "required": True},
            "ports": {"type": "string", "default": "1-1000"},
            "service_detection": {"type": "boolean", "default": True},
            "timing": {"type": "integer", "default": 4, "min": 0, "max": 5},
            "extra_args": {"type": "array", "items": "string"},
        },
        requires_root=False,
    )
)
