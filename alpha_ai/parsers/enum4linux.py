"""Parse enum4linux text output for shares, users, OS, and policy.

enum4linux has no machine-readable format; we extract section markers.
"""

from __future__ import annotations

import re

from alpha_ai.core.models import Finding, Severity

_SHARE_RE = re.compile(r"^\s*([A-Za-z0-9_$\-\.]+)\s+(Disk|IPC|Printer)\s*", re.MULTILINE)
_USER_RE = re.compile(r"user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]")
_OS_RE = re.compile(r"OS=\[([^\]]+)\]\s+Server=\[([^\]]+)\]")


def parse_enum4linux(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []

    for m in _SHARE_RE.finditer(stdout):
        share, kind = m.group(1), m.group(2)
        if share.lower() in {"sharename", "----"}:
            continue
        sev = Severity.MEDIUM if kind == "Disk" and share.upper() not in {"IPC$", "PRINT$"} else Severity.INFO
        findings.append(
            Finding(
                tool="enum4linux",
                target=target,
                title=f"SMB share '{share}' ({kind})",
                severity=sev,
                description=f"enum4linux discovered share {share} of type {kind}",
                evidence={"share": share, "type": kind},
            )
        )

    for m in _USER_RE.finditer(stdout):
        findings.append(
            Finding(
                tool="enum4linux",
                target=target,
                title=f"SMB user enumerated: {m.group(1)}",
                severity=Severity.LOW,
                description="User account discovered via SAMR/RPC enumeration",
                evidence={"user": m.group(1), "rid": m.group(2)},
            )
        )

    os_m = _OS_RE.search(stdout)
    if os_m:
        findings.append(
            Finding(
                tool="enum4linux",
                target=target,
                title=f"OS fingerprint: {os_m.group(1)}",
                severity=Severity.INFO,
                description="OS/Server banner via SMB session setup",
                evidence={"os": os_m.group(1), "server": os_m.group(2)},
            )
        )

    return findings
