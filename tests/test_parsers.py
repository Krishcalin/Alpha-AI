"""Parser unit tests."""

from __future__ import annotations

from alpha_ai.core.models import Severity
from alpha_ai.parsers.nmap import parse_nmap_xml
from alpha_ai.parsers.nuclei import parse_nuclei_jsonl

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NUCLEI_JSONL = (
    '{"template-id":"http-missing-security-headers","host":"http://x","matched-at":"http://x",'
    '"info":{"name":"Missing Security Headers","severity":"info","description":"d"}}\n'
    '{"template-id":"CVE-2024-1234","host":"http://x","matched-at":"http://x/login",'
    '"info":{"name":"RCE","severity":"critical","description":"bad",'
    '"classification":{"cve-id":"CVE-2024-1234"}}}\n'
)


def test_nmap_parser_open_ports_only() -> None:
    findings = parse_nmap_xml(NMAP_XML, target="127.0.0.1")
    assert len(findings) == 1
    assert findings[0].evidence["port"] == "22"
    assert findings[0].evidence["service"] == "ssh"
    assert "OpenSSH" in findings[0].description


def test_nmap_parser_handles_empty() -> None:
    assert parse_nmap_xml("", target="x") == []
    assert parse_nmap_xml("<not-xml", target="x") == []


def test_nuclei_parser_severity_mapping() -> None:
    findings = parse_nuclei_jsonl(NUCLEI_JSONL, target="http://x")
    assert len(findings) == 2
    sev = {f.title: f.severity for f in findings}
    assert sev["Missing Security Headers"] == Severity.INFO
    assert sev["RCE"] == Severity.CRITICAL
    assert findings[1].cve == ["CVE-2024-1234"]
