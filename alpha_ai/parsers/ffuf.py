"""Parse ffuf JSON output (-of json) into Findings."""

from __future__ import annotations

import json

from alpha_ai.core.models import Finding, Severity


def parse_ffuf_json(json_text: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    if not json_text.strip():
        return findings
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return findings

    for r in data.get("results", []):
        url = r.get("url", "")
        status = int(r.get("status", 0))
        length = int(r.get("length", 0))
        words = int(r.get("words", 0))
        sev = Severity.LOW if status == 200 else Severity.INFO
        findings.append(
            Finding(
                tool="ffuf",
                target=target,
                title=f"Match {url} (HTTP {status})",
                severity=sev,
                description=f"ffuf matched {url}",
                evidence={
                    "url": url,
                    "status": status,
                    "length": length,
                    "words": words,
                    "input": r.get("input", {}),
                },
            )
        )
    return findings
