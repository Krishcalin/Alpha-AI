"""Parse amass subdomain enumeration output (plain FQDN-per-line).

``amass enum -d <domain>`` prints one discovered name per line to stdout.
Some invocations (``-src``) prefix a bracketed source tag, and the ``-o``
visualization format appends record annotations:

    www.example.com
    [crtsh]     mail.example.com
    ns1.example.com --> ns_record --> a.iana-servers.net

Per line we take the first token that is the scanned domain or a subdomain of
it, so all three shapes above yield the leading host.
"""

from __future__ import annotations

from alpha_ai.core.models import Finding, Severity


def parse_amass(stdout: str, target: str) -> list[Finding]:
    """Convert amass output into one Finding per discovered subdomain."""
    findings: list[Finding] = []
    if not stdout.strip():
        return findings

    dom = target.strip().lower().strip(".")
    if not dom:
        return findings

    seen: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        for tok in line.replace(",", " ").split():
            host = tok.strip().lower().strip(".")
            if not host or host in seen:
                continue
            if host == dom or host.endswith("." + dom):
                seen.add(host)
                findings.append(
                    Finding(
                        tool="amass",
                        target=target,
                        title=f"Subdomain discovered: {host}",
                        severity=Severity.INFO,
                        description=f"amass enumeration found {host}",
                        evidence={"host": host},
                    )
                )
                break  # one subdomain per line
    return findings
