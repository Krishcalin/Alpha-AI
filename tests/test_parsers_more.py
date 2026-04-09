"""Parser tests for gobuster, ffuf, sqlmap, enum4linux, crackmapexec."""

from __future__ import annotations

from alpha_ai.core.models import Severity
from alpha_ai.parsers.crackmapexec import parse_crackmapexec
from alpha_ai.parsers.enum4linux import parse_enum4linux
from alpha_ai.parsers.ffuf import parse_ffuf_json
from alpha_ai.parsers.gobuster import parse_gobuster
from alpha_ai.parsers.sqlmap import parse_sqlmap


def test_gobuster_parses_lines_and_marks_sensitive_paths() -> None:
    out = (
        "/admin                (Status: 301) [Size: 178] [--> /admin/]\n"
        "/index.html           (Status: 200) [Size: 1024]\n"
        "/.env                 (Status: 200) [Size: 64]\n"
    )
    findings = parse_gobuster(out, target="http://x")
    assert len(findings) == 3
    by_path = {f.evidence["path"]: f for f in findings}
    assert by_path["/admin"].severity == Severity.MEDIUM
    assert by_path["/.env"].severity == Severity.MEDIUM
    assert by_path["/index.html"].severity == Severity.LOW
    assert by_path["/admin"].evidence["redirect"] == "/admin/"


def test_ffuf_parses_results() -> None:
    payload = (
        '{"results":['
        '{"url":"http://x/admin","status":200,"length":1024,"words":50,"input":{"FUZZ":"admin"}},'
        '{"url":"http://x/missing","status":404,"length":0,"words":0,"input":{"FUZZ":"missing"}}'
        ']}'
    )
    findings = parse_ffuf_json(payload, target="http://x/FUZZ")
    assert len(findings) == 2
    assert findings[0].severity == Severity.LOW
    assert findings[1].severity == Severity.INFO
    assert findings[0].evidence["url"] == "http://x/admin"


def test_ffuf_handles_garbage() -> None:
    assert parse_ffuf_json("", target="x") == []
    assert parse_ffuf_json("{not-json", target="x") == []


def test_sqlmap_extracts_injection() -> None:
    out = (
        "[INFO] testing connection to the target URL\n"
        "sqlmap identified the following injection point(s):\n"
        "---\n"
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
        "    Payload: id=1 AND 1=1\n"
        "---\n"
        "back-end DBMS: MySQL >= 5.0\n"
    )
    findings = parse_sqlmap(out, target="http://x/?id=1")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.evidence["parameter"] == "id"
    assert f.evidence["dbms"].startswith("MySQL")


def test_sqlmap_no_injection_returns_empty() -> None:
    assert parse_sqlmap("[INFO] no injection found\n", target="x") == []


def test_enum4linux_parses_shares_users_os() -> None:
    out = (
        "OS=[Windows Server 2019] Server=[Samba 4.10]\n"
        "\n"
        "        Sharename       Type      Comment\n"
        "        ---------       ----      -------\n"
        "        ADMIN$          Disk      Remote Admin\n"
        "        backup          Disk      Backups\n"
        "        IPC$            IPC       IPC Service\n"
        "\n"
        "user:[alice] rid:[0x3e8]\n"
        "user:[bob] rid:[0x3e9]\n"
    )
    findings = parse_enum4linux(out, target="10.0.0.5")
    titles = [f.title for f in findings]
    assert any("backup" in t for t in titles)
    assert any("alice" in t for t in titles)
    assert any("Windows Server 2019" in t for t in titles)


def test_crackmapexec_parses_pwn3d() -> None:
    out = (
        "SMB         10.0.0.5      445    DC01             [*] Windows 10\n"
        "SMB         10.0.0.5      445    DC01             [+] CORP\\admin:Pass123 (Pwn3d!)\n"
        "SMB         10.0.0.6      445    WKS01            [-] CORP\\guest:'' STATUS_LOGON_FAILURE\n"
    )
    findings = parse_crackmapexec(out, target="10.0.0.0/24")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].evidence["protocol"] == "SMB"
    assert findings[0].evidence["host"] == "10.0.0.5"
