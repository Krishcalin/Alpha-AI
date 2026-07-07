"""Parse impacket-secretsdump output.

The money lines are NTLM hash dumps in the classic pwdump format:
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    CORP.LOCAL\\krbtgt:502:aad3b435...:5f4dcc3b5aa765d61d8327deb882cf99:::

Each dumped hash is a CRITICAL finding (offline-crackable / pass-the-hash material).
"""

from __future__ import annotations

import re

from alpha_ai.core.models import Finding, Severity

# account:rid:lmhash:nthash:::
_HASH_RE = re.compile(
    r"^(?P<account>[^:\r\n]+):(?P<rid>\d+):"
    r"(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::\s*$",
    re.MULTILINE,
)


def parse_secretsdump(stdout: str, target: str) -> list[Finding]:
    """Convert secretsdump output into one CRITICAL Finding per dumped NTLM hash."""
    findings: list[Finding] = []
    if not stdout.strip():
        return findings

    seen: set[tuple[str, str]] = set()
    for m in _HASH_RE.finditer(stdout):
        account = m.group("account").strip()
        nt = m.group("nt").lower()
        key = (account, nt)
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            Finding(
                tool="secretsdump",
                target=target,
                title=f"NTLM hash dumped: {account}",
                severity=Severity.CRITICAL,
                description=f"secretsdump recovered the NTLM hash for {account} (RID {m.group('rid')})",
                evidence={
                    "account": account,
                    "rid": m.group("rid"),
                    "lm_hash": m.group("lm").lower(),
                    "nt_hash": nt,
                    "machine_account": account.endswith("$"),
                },
            )
        )
    return findings
