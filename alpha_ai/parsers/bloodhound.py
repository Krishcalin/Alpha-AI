"""Parse bloodhound-python collector output.

bloodhound-python is a *collector*, not a finding engine — it enumerates the domain
and writes JSON (zipped) for the BloodHound UI. Its progress log looks like:
    INFO: Found 42 users
    INFO: Found 15 computers
    INFO: Found 30 groups
    INFO: Compressing output into 20260707_bloodhound.zip

We surface INFO findings summarizing what was collected plus a pointer to the artifact.
Progress is logged to stderr, so the wrapper passes stdout+stderr as one blob.
"""

from __future__ import annotations

import re

from alpha_ai.core.models import Finding, Severity

_FOUND_RE = re.compile(r"Found (?P<count>\d+) (?P<kind>[A-Za-z]+)")
_ZIP_RE = re.compile(r"(?:Compressing output into|output into)\s+(?P<zip>\S+\.zip)")


def parse_bloodhound(output: str, target: str) -> list[Finding]:
    """Convert bloodhound-python progress output into collection-summary Findings."""
    findings: list[Finding] = []
    if not output.strip():
        return findings

    seen_kinds: set[str] = set()
    for m in _FOUND_RE.finditer(output):
        kind = m.group("kind").lower()
        if kind in seen_kinds:
            continue
        seen_kinds.add(kind)
        count = int(m.group("count"))
        findings.append(
            Finding(
                tool="bloodhound",
                target=target,
                title=f"Collected {count} {kind}",
                severity=Severity.INFO,
                description=f"BloodHound enumeration found {count} {kind} in the domain",
                evidence={"kind": kind, "count": count},
            )
        )

    zip_m = _ZIP_RE.search(output)
    if zip_m:
        findings.append(
            Finding(
                tool="bloodhound",
                target=target,
                title=f"BloodHound collection written: {zip_m.group('zip')}",
                severity=Severity.INFO,
                description="Import this archive into the BloodHound UI to map AD attack paths.",
                evidence={"artifact": zip_m.group("zip")},
            )
        )
    return findings
