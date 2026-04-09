"""Parse sqlmap text output for injection findings.

sqlmap is verbose; we extract a few high-signal markers.
"""

from __future__ import annotations

import re

from alpha_ai.core.models import Finding, Severity

_PARAM_RE = re.compile(
    r"Parameter:\s*(?P<param>[^\(]+)\((?P<location>[^\)]+)\).*?"
    r"Type:\s*(?P<type>[^\n]+).*?"
    r"Title:\s*(?P<title>[^\n]+).*?"
    r"Payload:\s*(?P<payload>[^\n]+)",
    re.DOTALL,
)
_DBMS_RE = re.compile(r"back-end DBMS:\s*(?P<dbms>[^\n]+)")


def parse_sqlmap(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    if "is vulnerable" not in stdout and "Parameter:" not in stdout:
        return findings

    dbms_match = _DBMS_RE.search(stdout)
    dbms = dbms_match.group("dbms").strip() if dbms_match else "unknown"

    for m in _PARAM_RE.finditer(stdout):
        findings.append(
            Finding(
                tool="sqlmap",
                target=target,
                title=f"SQL injection in parameter '{m.group('param').strip()}' ({m.group('location').strip()})",
                severity=Severity.CRITICAL,
                description=f"sqlmap confirmed SQL injection — {m.group('title').strip()}",
                evidence={
                    "parameter": m.group("param").strip(),
                    "location": m.group("location").strip(),
                    "type": m.group("type").strip(),
                    "payload": m.group("payload").strip(),
                    "dbms": dbms,
                },
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            )
        )
    return findings
