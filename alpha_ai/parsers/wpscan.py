"""Parse wpscan JSON output (--format json).

Relevant shape:
    {
      "version": {"number": "5.7", "vulnerabilities": [ {..} ]},
      "main_theme": {"slug": "...", "vulnerabilities": [ {..} ]},
      "plugins": {"<slug>": {"version": {...}, "vulnerabilities": [ {..} ]}},
      "interesting_findings": [ {"to_s": "...", "type": "...", "url": "..."} ]
    }

Each vulnerability:
    {"title": "...", "references": {"cve": ["2021-..."], "url": ["..."]}}
"""

from __future__ import annotations

import json

from alpha_ai.core.models import Finding, Severity


def _vuln_findings(vulns: list, target: str, component: str) -> list[Finding]:
    out: list[Finding] = []
    for v in vulns or []:
        if not isinstance(v, dict):
            continue
        title = v.get("title", "Unknown vulnerability")
        refs = v.get("references", {}) or {}
        cves = [f"CVE-{c}" if not str(c).upper().startswith("CVE") else str(c)
                for c in (refs.get("cve") or [])]
        urls = list(refs.get("url") or [])
        out.append(
            Finding(
                tool="wpscan",
                target=target,
                title=f"[{component}] {title}",
                severity=Severity.HIGH,
                description=f"WordPress {component} vulnerability: {title}",
                evidence={"component": component, "fixed_in": v.get("fixed_in", "")},
                references=urls,
                cve=cves,
            )
        )
    return out


def parse_wpscan(stdout: str, target: str) -> list[Finding]:
    """Convert wpscan JSON output into Findings (vulnerabilities + interesting findings)."""
    findings: list[Finding] = []
    if not stdout.strip():
        return findings
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return findings
    if not isinstance(data, dict):
        return findings

    version = data.get("version") or {}
    findings += _vuln_findings(version.get("vulnerabilities"), target, "core")

    theme = data.get("main_theme") or {}
    findings += _vuln_findings(
        theme.get("vulnerabilities"), target, f"theme:{theme.get('slug', 'unknown')}"
    )

    for slug, plugin in (data.get("plugins") or {}).items():
        if isinstance(plugin, dict):
            findings += _vuln_findings(plugin.get("vulnerabilities"), target, f"plugin:{slug}")

    for item in data.get("interesting_findings") or []:
        if not isinstance(item, dict):
            continue
        desc = item.get("to_s", "") or item.get("type", "interesting finding")
        urls = item.get("url")
        refs = [urls] if isinstance(urls, str) else list(urls or [])
        findings.append(
            Finding(
                tool="wpscan",
                target=target,
                title=f"Interesting finding: {item.get('type', 'info')}",
                severity=Severity.INFO,
                description=desc,
                evidence={"type": item.get("type", "")},
                references=refs,
            )
        )
    return findings
