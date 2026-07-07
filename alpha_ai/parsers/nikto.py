"""Parse nikto CSV output (-Format csv -output -).

Each data row is:
    "host","ip","port","OSVDB-id","HTTP-method","uri","description"
"""

from __future__ import annotations

import csv
import io

from alpha_ai.core.models import Finding, Severity


def parse_nikto(stdout: str, target: str) -> list[Finding]:
    """Convert nikto CSV output into Findings (one per reported item)."""
    findings: list[Finding] = []
    if not stdout.strip():
        return findings

    reader = csv.reader(io.StringIO(stdout))
    for row in reader:
        # nikto rows have 7 columns; skip banners / short lines.
        if len(row) < 7:
            continue
        host, ip, port, osvdb, method, uri, description = row[:7]
        if not description.strip():
            continue

        refs: list[str] = []
        osvdb = osvdb.strip()
        if osvdb and osvdb != "0":
            refs.append(f"https://www.osvdb.org/{osvdb}")

        findings.append(
            Finding(
                tool="nikto",
                target=host or target,
                title=f"{method} {uri}".strip() or "nikto finding",
                severity=Severity.MEDIUM,
                description=description.strip(),
                evidence={
                    "ip": ip,
                    "port": port,
                    "osvdb": osvdb,
                    "method": method,
                    "uri": uri,
                },
                references=refs,
            )
        )
    return findings
