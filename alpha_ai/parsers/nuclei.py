"""Parse nuclei -jsonl output into Finding objects."""

from __future__ import annotations

import json

from alpha_ai.core.models import Finding, Severity

_SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def parse_nuclei_jsonl(jsonl_text: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in jsonl_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = data.get("info", {})
        sev_raw = (info.get("severity") or "info").lower()
        cve_list = info.get("classification", {}).get("cve-id") or []
        if isinstance(cve_list, str):
            cve_list = [cve_list]

        findings.append(
            Finding(
                tool="nuclei",
                target=data.get("host") or data.get("matched-at") or target,
                title=info.get("name", data.get("template-id", "nuclei finding")),
                severity=_SEV_MAP.get(sev_raw, Severity.INFO),
                description=info.get("description", ""),
                evidence={
                    "template-id": data.get("template-id"),
                    "matched-at": data.get("matched-at"),
                    "type": data.get("type"),
                },
                references=info.get("reference") or [],
                cve=cve_list,
            )
        )
    return findings
