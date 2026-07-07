"""Parse certipy `find` output (ADCS misconfiguration discovery).

Dual-mode: certipy can emit JSON or a human text report depending on version/flags,
so the parser tries JSON first and falls back to scanning the text report.

JSON shape (certipy find -json):
    {
      "Certificate Templates": {
        "0": {"Template Name": "ESC1-Tmpl", "Enabled": true,
              "[!] Vulnerabilities": {"ESC1": "'CORP\\Domain Users' can enroll ..."}}
      },
      "Certificate Authorities": {
        "0": {"CA Name": "corp-CA", "[!] Vulnerabilities": {"ESC7": "..."}}
      }
    }

Each ESC* vulnerability is a CRITICAL finding (ADCS abuse → domain compromise).
"""

from __future__ import annotations

import json
import re

from alpha_ai.core.models import Finding, Severity

_ESC_LINE_RE = re.compile(r"(?P<esc>ESC\d+)\s*:\s*(?P<desc>.+)")
_NAME_LINE_RE = re.compile(r"(?:Template Name|CA Name)\s*:\s*(?P<name>.+)")


def _finding(esc: str, name: str, desc: str) -> Finding:
    return Finding(
        tool="certipy",
        target=name,
        title=f"ADCS {esc} on {name}",
        severity=Severity.CRITICAL,
        description=f"{esc}: {desc}".strip(),
        evidence={"esc": esc, "object": name, "detail": desc.strip()},
        references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
    )


def _parse_json(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for section in ("Certificate Templates", "Certificate Authorities"):
        entries = data.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for entry in entries.values():
            if not isinstance(entry, dict):
                continue
            name = entry.get("Template Name") or entry.get("CA Name") or "unknown"
            vulns = next(
                (v for k, v in entry.items() if "Vulnerabilities" in k and isinstance(v, dict)),
                {},
            )
            for esc, desc in vulns.items():
                findings.append(_finding(esc, name, str(desc)))
    return findings


def _parse_text(stdout: str) -> list[Finding]:
    findings: list[Finding] = []
    current = "unknown"
    for line in stdout.splitlines():
        name_m = _NAME_LINE_RE.search(line)
        if name_m:
            current = name_m.group("name").strip()
            continue
        esc_m = _ESC_LINE_RE.search(line)
        if esc_m:
            findings.append(_finding(esc_m.group("esc"), current, esc_m.group("desc").strip()))
    return findings


def parse_certipy(stdout: str, target: str) -> list[Finding]:
    """Convert certipy find output into one CRITICAL Finding per ESC* vulnerability."""
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            return _parse_json(data)
    except json.JSONDecodeError:
        pass
    return _parse_text(stdout)
