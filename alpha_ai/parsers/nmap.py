"""Parse nmap XML output into Finding objects."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from alpha_ai.core.models import Finding, Severity


def parse_nmap_xml(xml_text: str, target: str) -> list[Finding]:
    """Convert an nmap -oX XML document to a list of Findings (one per open port)."""
    findings: list[Finding] = []
    if not xml_text.strip():
        return findings

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        addr_el = host.find("address")
        host_addr = addr_el.get("addr") if addr_el is not None else target

        for port in host.findall(".//port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")
            service_el = port.find("service")
            service = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""

            banner = " ".join(filter(None, [product, version])).strip()
            findings.append(
                Finding(
                    tool="nmap",
                    target=host_addr,
                    title=f"Open port {portid}/{protocol} ({service})",
                    severity=Severity.INFO,
                    description=f"{service} {banner}".strip(),
                    evidence={
                        "port": portid,
                        "protocol": protocol,
                        "service": service,
                        "product": product,
                        "version": version,
                    },
                )
            )
    return findings
