"""John the Ripper wrapper — offline password hash cracking.

Local-only (like searchsploit): no remote target, no network whitelist. The
*target* is the path to the hash file being cracked — it keys the cache and
identifies the run.
"""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.john import parse_john

_runner = CommandRunner()


async def john_crack(
    target: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    hash_format: str | None = None,
    rules: bool = False,
    timeout: float = 1800.0,
) -> ToolResult:
    """Crack the hashes in *target* with John the Ripper.

    Args:
        target: Path to the hash file (John-compatible format).
        wordlist: Path to the wordlist (--wordlist).
        hash_format: Force a hash format, e.g. "nt", "sha512crypt" (--format).
        rules: Enable word-mangling rules (--rules).
    """
    cmd = ["john", f"--wordlist={wordlist}"]
    if hash_format:
        cmd.append(f"--format={hash_format}")
    if rules:
        cmd.append("--rules")
    cmd.append(target)

    cmd_result = await _runner.run(cmd, timeout=timeout)
    # John prints cracked passwords to stdout; status/logs go to stderr.
    findings = parse_john(cmd_result.stdout, target=target)

    return ToolResult(
        tool="john",
        target=target,
        args={"wordlist": wordlist, "hash_format": hash_format, "rules": rules},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="john",
        category=ToolCategory.CRED,
        description="Offline password hash cracking with John the Ripper (local-only). Target is the hash file.",
        fn=john_crack,
        parameters={
            "target": {"type": "string", "required": True, "description": "Path to hash file"},
            "wordlist": {"type": "string", "default": "/usr/share/wordlists/rockyou.txt"},
            "hash_format": {"type": "string", "description": "Force hash format, e.g. nt, sha512crypt"},
            "rules": {"type": "boolean", "default": False},
        },
        requires_authorization=False,
    )
)
