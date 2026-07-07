"""Parse subfinder JSON-lines output (-oJ / -json).

Each line is a JSON object:
    {"host": "www.example.com", "input": "example.com", "source": ["crtsh"]}
"""

from __future__ import annotations

import json

from alpha_ai.core.models import Finding, Severity


def parse_subfinder(stdout: str, target: str) -> list[Finding]:
    """Convert subfinder JSON-lines output into one Finding per discovered subdomain."""
    findings: list[Finding] = []
    if not stdout.strip():
        return findings

    seen: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = rec.get("host") or rec.get("subdomain")
        if not host or host in seen:
            continue
        seen.add(host)

        source = rec.get("source") or rec.get("sources") or []
        if isinstance(source, str):
            source = [source]

        findings.append(
            Finding(
                tool="subfinder",
                target=target,
                title=f"Subdomain discovered: {host}",
                severity=Severity.INFO,
                description=f"Passive subdomain enumeration found {host}",
                evidence={"host": host, "source": source},
            )
        )
    return findings
