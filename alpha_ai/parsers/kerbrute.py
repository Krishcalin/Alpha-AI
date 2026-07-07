"""Parse kerbrute output (userenum / passwordspray / bruteuser).

Relevant lines:
    ... >  [+] VALID USERNAME:      admin@lab.internal
    ... >  [+] VALID LOGIN:         lab.internal\\jdoe:Winter2026
"""

from __future__ import annotations

import re

from alpha_ai.core.models import Finding, Severity

_USERNAME_RE = re.compile(r"VALID USERNAME:\s*(?P<user>\S+)")
_LOGIN_RE = re.compile(r"VALID LOGIN:\s*(?P<cred>\S+)")


def parse_kerbrute(stdout: str, target: str) -> list[Finding]:
    """Convert kerbrute output into Findings.

    VALID LOGIN → CRITICAL (working credential); VALID USERNAME → LOW (enumerated user).
    """
    findings: list[Finding] = []
    if not stdout.strip():
        return findings

    seen_users: set[str] = set()
    seen_logins: set[str] = set()

    for line in stdout.splitlines():
        login = _LOGIN_RE.search(line)
        if login:
            cred = login.group("cred")
            if cred in seen_logins:
                continue
            seen_logins.add(cred)
            user, _, password = cred.partition(":")
            findings.append(
                Finding(
                    tool="kerbrute",
                    target=target,
                    title=f"Valid Kerberos credential: {user}",
                    severity=Severity.CRITICAL,
                    description=f"kerbrute confirmed working credential {cred}",
                    evidence={"account": user, "password": password},
                )
            )
            continue

        username = _USERNAME_RE.search(line)
        if username:
            user = username.group("user")
            if user in seen_users:
                continue
            seen_users.add(user)
            findings.append(
                Finding(
                    tool="kerbrute",
                    target=target,
                    title=f"Valid domain username: {user}",
                    severity=Severity.LOW,
                    description=f"kerbrute enumerated existing account {user}",
                    evidence={"account": user},
                )
            )
    return findings
