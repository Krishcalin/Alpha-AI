"""gobuster wrapper — directory/file brute forcing."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.gobuster import parse_gobuster

_runner = CommandRunner()

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


async def gobuster_scan(
    target: str,
    wordlist: str = DEFAULT_WORDLIST,
    extensions: str | None = None,
    threads: int = 30,
    status_codes: str = "200,204,301,302,307,401,403",
    timeout: float = 900.0,
) -> ToolResult:
    """Run gobuster dir mode against *target* (URL)."""
    cmd = [
        "gobuster", "dir",
        "-u", target,
        "-w", wordlist,
        "-t", str(threads),
        "-s", status_codes,
        "--no-error",
        "-q",
    ]
    if extensions:
        cmd += ["-x", extensions]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_gobuster(cmd_result.stdout, target=target)

    return ToolResult(
        tool="gobuster",
        target=target,
        args={
            "wordlist": wordlist,
            "extensions": extensions,
            "threads": threads,
            "status_codes": status_codes,
        },
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="gobuster",
        category=ToolCategory.WEB,
        description="Directory and file brute-forcing for web targets (gobuster dir).",
        fn=gobuster_scan,
        parameters={
            "target": {"type": "string", "required": True, "format": "url"},
            "wordlist": {"type": "string", "default": DEFAULT_WORDLIST},
            "extensions": {"type": "string", "description": "e.g. 'php,html,txt'"},
            "threads": {"type": "integer", "default": 30},
            "status_codes": {"type": "string", "default": "200,204,301,302,307,401,403"},
        },
    )
)
