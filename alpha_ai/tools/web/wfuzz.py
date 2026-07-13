"""wfuzz wrapper — web content/parameter fuzzing."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.wfuzz import parse_wfuzz

_runner = CommandRunner()

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


async def wfuzz_scan(
    target: str,
    wordlist: str = DEFAULT_WORDLIST,
    hide_codes: str = "404",
    threads: int = 40,
    timeout: float = 900.0,
) -> ToolResult:
    """Fuzz *target* with wfuzz. The URL must contain the FUZZ keyword.

    Args:
        target: URL with a FUZZ marker (e.g. "http://host/FUZZ"). Must be authorized.
        wordlist: Payload wordlist (-z file,<wordlist>).
        hide_codes: Comma-separated HTTP codes to hide from results (--hc).
        threads: Concurrent requests (-t).
    """
    cmd = [
        "wfuzz", "-c",
        "-z", f"file,{wordlist}",
        "--hc", hide_codes,
        "-t", str(threads),
        "-o", "json",
        "-u", target,
    ]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    findings = parse_wfuzz(cmd_result.stdout, target=target)

    return ToolResult(
        tool="wfuzz",
        target=target,
        args={"wordlist": wordlist, "hide_codes": hide_codes, "threads": threads},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="wfuzz",
        category=ToolCategory.WEB,
        description="Web content/parameter fuzzer; the target URL must contain FUZZ (wfuzz).",
        fn=wfuzz_scan,
        parameters={
            "target": {"type": "string", "required": True, "format": "url", "description": "URL with FUZZ"},
            "wordlist": {"type": "string", "default": DEFAULT_WORDLIST},
            "hide_codes": {"type": "string", "default": "404"},
            "threads": {"type": "integer", "default": 40},
        },
    )
)
