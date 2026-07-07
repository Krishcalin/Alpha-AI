"""hashcat wrapper — GPU-accelerated offline password hash cracking.

Local-only (like searchsploit): no remote target, no network whitelist. The
*target* is the path to the hash file being cracked — it keys the cache and
identifies the run.
"""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.hashcat import parse_hashcat

_runner = CommandRunner()


async def hashcat_crack(
    target: str,
    mode: int = 1000,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    attack_mode: int = 0,
    rules: str | None = None,
    timeout: float = 1800.0,
) -> ToolResult:
    """Crack the hashes in *target* with hashcat.

    Args:
        target: Path to the hash file (one hash per line).
        mode: hashcat hash-type (-m). Default 1000 = NTLM (pairs with secretsdump).
        wordlist: Path to the wordlist.
        attack_mode: hashcat attack mode (-a). Default 0 = straight (dictionary).
        rules: Path to a rules file (-r) for word mangling.
    """
    cmd = [
        "hashcat",
        "-m", str(mode),
        "-a", str(attack_mode),
        target,
        wordlist,
        "--potfile-disable",
        "--quiet",
    ]
    if rules:
        cmd += ["-r", rules]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    # With --quiet, stdout carries only the cracked hash:plaintext pairs.
    findings = parse_hashcat(cmd_result.stdout, target=target)

    return ToolResult(
        tool="hashcat",
        target=target,
        args={"mode": mode, "wordlist": wordlist, "attack_mode": attack_mode, "rules": rules},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="hashcat",
        category=ToolCategory.CRED,
        description="GPU-accelerated offline hash cracking with hashcat (local-only). Target is the hash file.",
        fn=hashcat_crack,
        parameters={
            "target": {"type": "string", "required": True, "description": "Path to hash file"},
            "mode": {"type": "integer", "default": 1000, "description": "hashcat -m hash-type (1000 = NTLM)"},
            "wordlist": {"type": "string", "default": "/usr/share/wordlists/rockyou.txt"},
            "attack_mode": {"type": "integer", "default": 0, "description": "hashcat -a attack mode"},
            "rules": {"type": "string", "description": "Path to rules file (-r)"},
        },
        requires_authorization=False,
    )
)
