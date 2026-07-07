"""Parser tests for Phase 2 tool-breadth additions:
subfinder, masscan, nikto, wpscan, kerbrute.
"""

from __future__ import annotations

from alpha_ai.core.models import Severity
from alpha_ai.parsers.kerbrute import parse_kerbrute
from alpha_ai.parsers.masscan import parse_masscan
from alpha_ai.parsers.nikto import parse_nikto
from alpha_ai.parsers.subfinder import parse_subfinder
from alpha_ai.parsers.wpscan import parse_wpscan


# ── subfinder ────────────────────────────────────────────────────────────────
def test_subfinder_parses_and_dedupes() -> None:
    out = (
        '{"host":"www.example.com","input":"example.com","source":["crtsh"]}\n'
        '{"host":"mail.example.com","input":"example.com","source":["dnsdumpster"]}\n'
        '{"host":"www.example.com","input":"example.com","source":["wayback"]}\n'  # dup
    )
    findings = parse_subfinder(out, target="example.com")
    assert len(findings) == 2
    hosts = {f.evidence["host"] for f in findings}
    assert hosts == {"www.example.com", "mail.example.com"}
    assert all(f.severity == Severity.INFO for f in findings)


def test_subfinder_empty_and_garbage() -> None:
    assert parse_subfinder("", target="x") == []
    assert parse_subfinder("not json\n---\n", target="x") == []


# ── masscan ──────────────────────────────────────────────────────────────────
def test_masscan_parses_open_ports() -> None:
    out = (
        "[\n"
        '{   "ip": "10.0.0.5", "timestamp": "1700000000", '
        '"ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }\n'
        ",\n"
        '{   "ip": "10.0.0.5", "timestamp": "1700000001", '
        '"ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }\n'
        "]\n"
    )
    findings = parse_masscan(out, target="10.0.0.5")
    assert len(findings) == 2
    ports = {f.evidence["port"] for f in findings}
    assert ports == {80, 443}
    assert all(f.severity == Severity.INFO for f in findings)


def test_masscan_empty_and_garbage() -> None:
    assert parse_masscan("", target="x") == []
    assert parse_masscan("garbage not json", target="x") == []


# ── nikto ────────────────────────────────────────────────────────────────────
def test_nikto_parses_csv_rows() -> None:
    out = (
        '"localhost","127.0.0.1","80","0","GET","/","The anti-clickjacking X-Frame-Options header is not present."\n'
        '"localhost","127.0.0.1","80","3268","GET","/admin/","Directory indexing found."\n'
    )
    findings = parse_nikto(out, target="http://localhost")
    assert len(findings) == 2
    assert all(f.severity == Severity.MEDIUM for f in findings)
    admin = [f for f in findings if f.evidence["uri"] == "/admin/"][0]
    assert admin.references == ["https://www.osvdb.org/3268"]


def test_nikto_empty_and_short_rows() -> None:
    assert parse_nikto("", target="x") == []
    assert parse_nikto('"only","three","cols"\n', target="x") == []


# ── wpscan ───────────────────────────────────────────────────────────────────
def test_wpscan_parses_vulns_and_findings() -> None:
    payload = (
        '{"version":{"number":"5.7","vulnerabilities":['
        '{"title":"WP Core XSS","references":{"cve":["2021-1234"],"url":["http://x"]},"fixed_in":"5.8"}]},'
        '"plugins":{"contact-form-7":{"vulnerabilities":['
        '{"title":"CF7 SQLi","references":{"cve":["2020-9999"],"url":[]}}]}},'
        '"interesting_findings":[{"to_s":"robots.txt found","type":"robots_txt","url":"http://x/robots.txt"}]}'
    )
    findings = parse_wpscan(payload, target="http://blog.test")
    titles = {f.title for f in findings}
    assert any("WP Core XSS" in t for t in titles)
    assert any("CF7 SQLi" in t for t in titles)

    core = [f for f in findings if "WP Core XSS" in f.title][0]
    assert core.severity == Severity.HIGH
    assert core.cve == ["CVE-2021-1234"]

    info = [f for f in findings if f.severity == Severity.INFO]
    assert len(info) == 1
    assert "robots.txt" in info[0].description


def test_wpscan_empty_and_garbage() -> None:
    assert parse_wpscan("", target="x") == []
    assert parse_wpscan("not json", target="x") == []
    assert parse_wpscan("[1,2,3]", target="x") == []  # not a dict


# ── kerbrute ─────────────────────────────────────────────────────────────────
def test_kerbrute_userenum_and_login() -> None:
    out = (
        "2026/07/07 12:00:00 >  [+] VALID USERNAME:\t admin@lab.internal\n"
        "2026/07/07 12:00:01 >  [+] VALID USERNAME:\t admin@lab.internal\n"  # dup
        "2026/07/07 12:00:02 >  [+] VALID LOGIN:\t lab.internal\\jdoe:Winter2026\n"
    )
    findings = parse_kerbrute(out, target="10.0.0.10")
    users = [f for f in findings if f.severity == Severity.LOW]
    logins = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(users) == 1  # deduped
    assert users[0].evidence["account"] == "admin@lab.internal"
    assert len(logins) == 1
    assert logins[0].evidence["account"] == "lab.internal\\jdoe"
    assert logins[0].evidence["password"] == "Winter2026"


def test_kerbrute_empty() -> None:
    assert parse_kerbrute("", target="x") == []
    assert parse_kerbrute("Done! No valid users\n", target="x") == []
