"""Parse hashcat crack output.

Run with ``--quiet`` so stdout carries only the cracked pairs, one per line, in
hashcat's ``hash:plaintext`` format:

    31d6cfe0d16ae931b73c59d7e0c089c0:Winter2026
    5f4dcc3b5aa765d61d8327deb882cf99:password

The separator is the first colon (hashcat's convention for simple hash types).
Each cracked credential is CRITICAL — a usable plaintext password.
"""

from __future__ import annotations

from alpha_ai.core.models import Finding, Severity


def parse_hashcat(stdout: str, target: str) -> list[Finding]:
    """Convert hashcat --quiet stdout into one CRITICAL Finding per cracked hash."""
    findings: list[Finding] = []
    if not stdout.strip():
        return findings

    seen: set[tuple[str, str]] = set()
    for line in stdout.splitlines():
        line = line.rstrip("\r")
        if ":" not in line:
            continue
        hash_val, _, plain = line.partition(":")
        hash_val = hash_val.strip()
        if not hash_val:
            continue
        key = (hash_val, plain)
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            Finding(
                tool="hashcat",
                target=target,
                title=f"Hash cracked: {hash_val[:16]}…",
                severity=Severity.CRITICAL,
                description="hashcat recovered a plaintext password from the supplied hash",
                evidence={"hash": hash_val, "password": plain},
            )
        )
    return findings
