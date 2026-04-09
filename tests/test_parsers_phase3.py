"""Parser tests for hydra and searchsploit."""

from __future__ import annotations

from alpha_ai.core.models import Severity
from alpha_ai.parsers.hydra import parse_hydra
from alpha_ai.parsers.searchsploit import parse_searchsploit_json


def test_hydra_parses_valid_credentials() -> None:
    out = (
        "Hydra v9.5 starting...\n"
        "[DATA] attacking ssh://10.0.0.5:22/\n"
        "[22][ssh] host: 10.0.0.5   login: root   password: toor\n"
        "[445][smb] host: 10.0.0.5   login: admin   password: P@ssw0rd\n"
        "1 of 1 target successfully completed\n"
    )
    findings = parse_hydra(out, target="10.0.0.5")
    assert len(findings) == 2
    assert all(f.severity == Severity.CRITICAL for f in findings)
    by_proto = {f.evidence["protocol"]: f for f in findings}
    assert by_proto["ssh"].evidence["login"] == "root"
    assert by_proto["ssh"].evidence["port"] == 22
    assert by_proto["smb"].evidence["password"] == "P@ssw0rd"


def test_hydra_no_creds_returns_empty() -> None:
    assert parse_hydra("0 valid passwords found\n", target="10.0.0.5") == []


def test_searchsploit_parses_exploits() -> None:
    payload = (
        '{"RESULTS_EXPLOIT":['
        '{"Title":"Apache 2.4.49 - Path Traversal","EDB-ID":"50383",'
        '"Path":"linux/webapps/50383.sh","Type":"webapps","Platform":"linux",'
        '"Date_Published":"2021-10-05"},'
        '{"Title":"Linux Kernel - Local PrivEsc","EDB-ID":"12345",'
        '"Path":"linux/local/12345.c","Type":"local","Platform":"linux",'
        '"Date_Published":"2020-01-01"}'
        '],"RESULTS_SHELLCODE":[]}'
    )
    findings = parse_searchsploit_json(payload, target="Apache 2.4.49")
    assert len(findings) == 2
    by_id = {f.evidence["edb_id"]: f for f in findings}
    assert by_id["50383"].severity == Severity.HIGH  # webapps
    assert by_id["12345"].severity == Severity.MEDIUM  # local
    assert "exploit-db.com/exploits/50383" in by_id["50383"].references[0]


def test_searchsploit_handles_empty_and_garbage() -> None:
    assert parse_searchsploit_json("", target="x") == []
    assert parse_searchsploit_json("not json", target="x") == []
    assert parse_searchsploit_json('{"RESULTS_EXPLOIT":[]}', target="x") == []
