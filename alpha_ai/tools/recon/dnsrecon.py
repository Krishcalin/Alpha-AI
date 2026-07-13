"""dnsrecon wrapper — DNS record enumeration + zone-transfer testing."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.dnsrecon import parse_dnsrecon

_runner = CommandRunner()


async def dnsrecon_scan(
    target: str,
    scan_type: str = "std",
    dictionary: str | None = None,
    timeout: float = 300.0,
) -> ToolResult:
    """Enumerate DNS records for *target* with dnsrecon.

    Args:
        target: Domain (e.g. "example.com"). Must be authorized.
        scan_type: dnsrecon -t type (std, axfr, brt, srv, ...).
        dictionary: Wordlist for subdomain brute forcing (-D), used with scan_type="brt".
    """
    cmd = ["dnsrecon", "-d", target, "-t", scan_type]
    if dictionary and scan_type == "brt":
        cmd += ["-D", dictionary]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_dnsrecon(cmd_result.stdout, target=target)

    return ToolResult(
        tool="dnsrecon",
        target=target,
        args={"scan_type": scan_type, "dictionary": dictionary},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="dnsrecon",
        category=ToolCategory.RECON,
        description="DNS record enumeration and zone-transfer testing (dnsrecon).",
        fn=dnsrecon_scan,
        parameters={
            "target": {"type": "string", "required": True, "description": "domain"},
            "scan_type": {"type": "string", "default": "std"},
            "dictionary": {"type": "string", "description": "wordlist for -t brt"},
        },
    )
)
