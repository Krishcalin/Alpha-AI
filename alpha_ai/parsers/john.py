"""Parse John the Ripper crack output.

John prints recovered passwords to *stdout* (informational/status lines go to
stderr), one per line, in the classic console format:

    password123      (Administrator)
    Winter2026       (CORP\\jdoe)

Each cracked credential is CRITICAL — a usable plaintext password.
"""

from __future__ import annotations

import re

from alpha_ai.core.models import Finding, Severity

# "<plaintext>      (<username>)"  — password left, username in trailing parens
_CRACK_RE = re.compile(r"^(?P<password>.*\S)\s+\((?P<user>[^)]+)\)\s*$", re.MULTILINE)


def parse_john(stdout: str, target: str) -> list[Finding]:
    """Convert John stdout into one CRITICAL Finding per cracked credential."""
    findings: list[Finding] = []
    if not stdout.strip():
        return findings

    seen: set[tuple[str, str]] = set()
    for m in _CRACK_RE.finditer(stdout):
        user = m.group("user").strip()
        password = m.group("password")
        key = (user, password)
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            Finding(
                tool="john",
                target=target,
                title=f"Password cracked: {user}",
                severity=Severity.CRITICAL,
                description=f"John the Ripper recovered the plaintext password for {user}",
                evidence={"account": user, "password": password},
            )
        )
    return findings
