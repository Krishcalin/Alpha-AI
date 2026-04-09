"""Parse crackmapexec text output.

CME prefixes lines with: PROTO  HOST  PORT  HOSTNAME  [STATUS] message
We extract [+] success markers (creds, pwn3d!, valid sessions).
"""

from __future__ import annotations

import re

from alpha_ai.core.models import Finding, Severity

_LINE_RE = re.compile(
    r"^(?P<proto>SMB|WINRM|MSSQL|LDAP|SSH|FTP|RDP|VNC)\s+"
    r"(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<hostname>\S+)\s+"
    r"\[(?P<status>[+\-*])\]\s+(?P<msg>.*)$",
    re.MULTILINE,
)


def _classify(msg: str) -> Severity:
    low = msg.lower()
    if "pwn3d" in low or "(pwn3d!)" in low:
        return Severity.CRITICAL
    if "[+]" in msg or "successfully" in low:
        return Severity.HIGH
    return Severity.INFO


def parse_crackmapexec(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _LINE_RE.finditer(stdout):
        if m.group("status") != "+":
            continue
        msg = m.group("msg").strip()
        findings.append(
            Finding(
                tool="crackmapexec",
                target=m.group("host"),
                title=f"{m.group('proto')} success on {m.group('host')}: {msg[:80]}",
                severity=_classify(msg),
                description=msg,
                evidence={
                    "protocol": m.group("proto"),
                    "host": m.group("host"),
                    "port": int(m.group("port")),
                    "hostname": m.group("hostname"),
                    "message": msg,
                },
            )
        )
    return findings
