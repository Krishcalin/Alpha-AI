"""wpscan wrapper — WordPress vulnerability scanning."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.wpscan import parse_wpscan

_runner = CommandRunner()


async def wpscan_scan(
    target: str,
    enumerate: str = "vp,vt,u",
    api_token: str | None = None,
    timeout: float = 900.0,
) -> ToolResult:
    """Run wpscan against a WordPress *target*.

    Args:
        target: WordPress site URL. Must be authorized.
        enumerate: wpscan --enumerate spec (vp=vuln plugins, vt=vuln themes, u=users).
        api_token: WPScan API token for vulnerability data (--api-token).
    """
    cmd = [
        "wpscan", "--url", target,
        "--format", "json",
        "--enumerate", enumerate,
        "--no-banner",
        "--disable-tls-checks",
    ]
    if api_token:
        cmd += ["--api-token", api_token]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_wpscan(cmd_result.stdout, target=target)

    return ToolResult(
        tool="wpscan",
        target=target,
        args={"enumerate": enumerate, "api_token": bool(api_token)},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="wpscan",
        category=ToolCategory.WEB,
        description="WordPress vulnerability scanning — core, plugins, themes, users (wpscan).",
        fn=wpscan_scan,
        parameters={
            "target": {"type": "string", "required": True, "format": "url"},
            "enumerate": {"type": "string", "default": "vp,vt,u"},
            "api_token": {"type": "string", "description": "WPScan API token"},
        },
    )
)
