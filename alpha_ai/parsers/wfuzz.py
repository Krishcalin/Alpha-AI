"""Parse wfuzz JSON output (``-o json``).

The json printer emits a JSON list of result objects, e.g.:

    [{"code": 200, "chars": 1256, "words": 42, "lines": 30,
      "payload": {"FUZZ": "admin"}, "location": ""}]

We reconstruct the matched URL by substituting the payload into the target's
FUZZ keyword when it is present, else fall back to a reported ``location`` /
``url`` field. Severity mirrors ffuf: HTTP 200 → LOW, everything else → INFO.
"""

from __future__ import annotations

import json
from typing import Any

from alpha_ai.core.models import Finding, Severity


def _payload_str(payload: Any) -> str:
    """Flatten wfuzz's payload (str | {"FUZZ": ...} | list) to a single value."""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        if "FUZZ" in payload:
            return str(payload["FUZZ"])
        for v in payload.values():
            return str(v)
        return ""
    if isinstance(payload, list) and payload:
        return str(payload[0])
    return "" if payload is None else str(payload)


def parse_wfuzz(stdout: str, target: str) -> list[Finding]:
    """Convert wfuzz JSON output into one Finding per matched result."""
    findings: list[Finding] = []
    text = stdout.strip()
    if not text:
        return findings

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return findings
    if not isinstance(data, list):
        return findings

    seen: set[str] = set()
    for rec in data:
        if not isinstance(rec, dict):
            continue

        payload = _payload_str(rec.get("payload"))
        location = rec.get("location") or rec.get("url") or ""
        if "FUZZ" in target and payload:
            url = target.replace("FUZZ", payload)
        elif location:
            url = str(location)
        else:
            url = target

        try:
            code = int(rec.get("code"))
        except (TypeError, ValueError):
            code = 0

        key = f"{code}|{url}|{payload}"
        if key in seen:
            continue
        seen.add(key)

        severity = Severity.LOW if code == 200 else Severity.INFO
        findings.append(
            Finding(
                tool="wfuzz",
                target=target,
                title=f"{code} {url}".strip(),
                severity=severity,
                description=f"wfuzz matched payload {payload!r} (HTTP {code})",
                evidence={
                    "code": code,
                    "payload": payload,
                    "url": url,
                    "chars": rec.get("chars"),
                    "words": rec.get("words"),
                    "lines": rec.get("lines"),
                },
            )
        )
    return findings
