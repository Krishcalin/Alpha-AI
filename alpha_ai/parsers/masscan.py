"""Parse masscan JSON output (-oJ -).

masscan emits a (loosely-formatted) JSON array, one record per host:
    [
    {   "ip": "10.0.0.5", "timestamp": "...", "ports": [
            {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }
    ,
    ...
    ]

The array is often not strictly valid (leading/trailing commas), so we parse
line-oriented record blocks defensively rather than json.loads-ing the whole doc.
"""

from __future__ import annotations

import json

from alpha_ai.core.models import Finding, Severity


def parse_masscan(stdout: str, target: str) -> list[Finding]:
    """Convert masscan -oJ output into one Finding per open port."""
    findings: list[Finding] = []
    text = stdout.strip()
    if not text:
        return findings

    # Try the whole document first; fall back to per-record recovery.
    records: list[dict] = []
    try:
        loaded = json.loads(text)
        if isinstance(loaded, list):
            records = [r for r in loaded if isinstance(r, dict)]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not (line.startswith("{") and line.endswith("}")):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for rec in records:
        ip = rec.get("ip", target)
        for port in rec.get("ports", []) or []:
            if port.get("status", "open") != "open":
                continue
            portid = port.get("port", "?")
            proto = port.get("proto", "tcp")
            findings.append(
                Finding(
                    tool="masscan",
                    target=ip,
                    title=f"Open port {portid}/{proto}",
                    severity=Severity.INFO,
                    description=f"masscan found {portid}/{proto} open on {ip}",
                    evidence={
                        "port": portid,
                        "protocol": proto,
                        "reason": port.get("reason", ""),
                        "ttl": port.get("ttl", ""),
                    },
                )
            )
    return findings
