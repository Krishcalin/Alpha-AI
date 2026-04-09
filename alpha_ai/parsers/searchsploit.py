"""Parse searchsploit JSON output (-j flag).

Output shape:
    {
      "RESULTS_EXPLOIT": [
        {"Title": "...", "EDB-ID": "12345", "Path": "...", "Type": "...",
         "Platform": "...", "Date_Published": "..."},
        ...
      ],
      "RESULTS_SHELLCODE": [...]
    }
"""

from __future__ import annotations

import json

from alpha_ai.core.models import Finding, Severity


def _severity_for_type(type_: str) -> Severity:
    t = (type_ or "").lower()
    if t in {"remote", "webapps"}:
        return Severity.HIGH
    if t in {"local", "dos"}:
        return Severity.MEDIUM
    return Severity.LOW


def parse_searchsploit_json(json_text: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    if not json_text.strip():
        return findings
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return findings

    for entry in data.get("RESULTS_EXPLOIT", []) or []:
        title = entry.get("Title", "Unknown exploit")
        edb_id = entry.get("EDB-ID", "")
        type_ = entry.get("Type", "")
        platform = entry.get("Platform", "")
        path = entry.get("Path", "")
        date = entry.get("Date_Published", "")

        refs = []
        if edb_id:
            refs.append(f"https://www.exploit-db.com/exploits/{edb_id}")

        findings.append(
            Finding(
                tool="searchsploit",
                target=target,
                title=f"Exploit available: {title}",
                severity=_severity_for_type(type_),
                description=f"Exploit-DB entry {edb_id} ({type_}/{platform}, published {date})",
                evidence={
                    "edb_id": edb_id,
                    "type": type_,
                    "platform": platform,
                    "path": path,
                    "date": date,
                },
                references=refs,
            )
        )
    return findings
