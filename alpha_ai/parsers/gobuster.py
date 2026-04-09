"""Parse gobuster dir/dns text output into Findings.

gobuster lines look like:
    /admin                (Status: 301) [Size: 178] [--> /admin/]
    /backup.zip           (Status: 200) [Size: 4096]
"""

from __future__ import annotations

import re

from alpha_ai.core.models import Finding, Severity

_LINE_RE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)\s*\[Size:\s*(?P<size>\d+)\]"
    r"(?:\s*\[-->\s*(?P<redirect>[^\]]+)\])?"
)


def _severity_for_path(path: str, status: int) -> Severity:
    sensitive = ("admin", "backup", ".git", ".env", "config", "wp-admin", "phpmyadmin")
    p = path.lower()
    if any(s in p for s in sensitive) and status < 400:
        return Severity.MEDIUM
    if status == 200:
        return Severity.LOW
    return Severity.INFO


def parse_gobuster(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("=") or line.startswith("["):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        status = int(m.group("status"))
        path = m.group("path")
        findings.append(
            Finding(
                tool="gobuster",
                target=target,
                title=f"Discovered {path} (HTTP {status})",
                severity=_severity_for_path(path, status),
                description=f"gobuster found {path} returning HTTP {status}",
                evidence={
                    "path": path,
                    "status": status,
                    "size": int(m.group("size")),
                    "redirect": m.group("redirect"),
                },
            )
        )
    return findings
