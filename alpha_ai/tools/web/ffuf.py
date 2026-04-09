"""ffuf wrapper — fast web fuzzer."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.ffuf import parse_ffuf_json

_runner = CommandRunner()

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


async def ffuf_scan(
    target: str,
    wordlist: str = DEFAULT_WORDLIST,
    match_codes: str = "200,204,301,302,307,401,403",
    threads: int = 40,
    timeout: float = 900.0,
) -> ToolResult:
    """Run ffuf against *target*. Use FUZZ keyword in the URL.

    Example: target = "https://example.com/FUZZ"
    """
    if "FUZZ" not in target:
        target = target.rstrip("/") + "/FUZZ"

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = Path(tmp.name)

    try:
        cmd = [
            "ffuf",
            "-u", target,
            "-w", wordlist,
            "-mc", match_codes,
            "-t", str(threads),
            "-of", "json",
            "-o", str(out_path),
            "-s",
        ]
        cmd_result = await _runner.run(cmd, timeout=timeout)
        json_text = out_path.read_text() if out_path.exists() else ""
    finally:
        if out_path.exists():
            try:
                out_path.unlink()
            except OSError:
                pass

    findings = parse_ffuf_json(json_text, target=target)

    return ToolResult(
        tool="ffuf",
        target=target,
        args={
            "wordlist": wordlist,
            "match_codes": match_codes,
            "threads": threads,
        },
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="ffuf",
        category=ToolCategory.WEB,
        description="Fast web fuzzer (ffuf). Use FUZZ keyword in the target URL.",
        fn=ffuf_scan,
        parameters={
            "target": {"type": "string", "required": True, "description": "URL with FUZZ keyword"},
            "wordlist": {"type": "string", "default": DEFAULT_WORDLIST},
            "match_codes": {"type": "string", "default": "200,204,301,302,307,401,403"},
            "threads": {"type": "integer", "default": 40},
        },
    )
)
