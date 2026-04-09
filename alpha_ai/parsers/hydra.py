"""Parse hydra text output for valid credentials.

hydra success lines look like:
    [22][ssh] host: 10.0.0.5   login: root   password: toor
    [445][smb] host: 10.0.0.5   login: admin   password: P@ssw0rd
"""

from __future__ import annotations

import re

from alpha_ai.core.models import Finding, Severity

_LINE_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<proto>[a-zA-Z0-9_\-]+)\]\s+host:\s*(?P<host>\S+)"
    r"\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)"
)


def parse_hydra(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _LINE_RE.finditer(stdout):
        host = m.group("host")
        proto = m.group("proto")
        login = m.group("login")
        password = m.group("password")
        findings.append(
            Finding(
                tool="hydra",
                target=host,
                title=f"Valid {proto.upper()} credentials on {host}: {login}",
                severity=Severity.CRITICAL,
                description=f"hydra brute-forced valid {proto} credentials",
                evidence={
                    "host": host,
                    "port": int(m.group("port")),
                    "protocol": proto,
                    "login": login,
                    "password": password,
                },
                references=[
                    "https://attack.mitre.org/techniques/T1110/",
                ],
            )
        )
    return findings
