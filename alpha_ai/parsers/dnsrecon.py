"""Parse dnsrecon standard stdout output.

dnsrecon prints one record per line: a status marker, the record type, then the
record fields:

    [*]      A example.com 93.184.216.34
    [*]      MX example.com mail.example.com 10
    [+]      NS example.com ns1.example.com

A successful zone transfer — a notable misconfiguration — is reported as:

    [+] Zone Transfer was successful!!
"""

from __future__ import annotations

from alpha_ai.core.models import Finding, Severity

_RECORD_TYPES = {
    "A", "AAAA", "NS", "MX", "SOA", "TXT", "SRV", "CNAME",
    "PTR", "HINFO", "SPF", "DNSKEY", "NSEC", "RRSIG",
}


def parse_dnsrecon(stdout: str, target: str) -> list[Finding]:
    """Convert dnsrecon output into DNS-record + zone-transfer Findings."""
    findings: list[Finding] = []
    if not stdout.strip():
        return findings

    seen: set[str] = set()
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue

        if "zone transfer was successful" in line.lower():
            if "axfr" not in seen:
                seen.add("axfr")
                findings.append(
                    Finding(
                        tool="dnsrecon",
                        target=target,
                        title="DNS zone transfer allowed (AXFR)",
                        severity=Severity.HIGH,
                        description=(
                            "A DNS zone transfer succeeded — the entire zone can be "
                            "enumerated by any client, exposing internal hostnames."
                        ),
                        evidence={"line": line},
                        references=["https://attack.mitre.org/techniques/T1590/002/"],
                    )
                )
            continue

        # Strip a leading status marker like "[*]", "[+]", "[-]".
        body = line
        if body.startswith("[") and "]" in body:
            body = body.split("]", 1)[1].strip()

        toks = body.split()
        if len(toks) < 2:
            continue
        rtype = toks[0].upper()
        if rtype not in _RECORD_TYPES:
            continue

        name = toks[1]
        data = " ".join(toks[2:])
        key = f"{rtype}|{name}|{data}"
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            Finding(
                tool="dnsrecon",
                target=target,
                title=f"{rtype} record: {name}",
                severity=Severity.INFO,
                description=f"{rtype} {name} {data}".strip(),
                evidence={"type": rtype, "name": name, "data": data},
            )
        )
    return findings
