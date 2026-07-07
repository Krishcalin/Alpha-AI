"""Parser tests for the Phase 2 AD block: secretsdump, certipy, bloodhound."""

from __future__ import annotations

from alpha_ai.core.models import Severity
from alpha_ai.parsers.bloodhound import parse_bloodhound
from alpha_ai.parsers.certipy import parse_certipy
from alpha_ai.parsers.secretsdump import parse_secretsdump


# ── secretsdump ──────────────────────────────────────────────────────────────
def test_secretsdump_parses_ntlm_hashes() -> None:
    out = (
        "[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\n"
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "CORP.LOCAL\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::\n"
        "WS01$:1104:aad3b435b51404eeaad3b435b51404ee:0102030405060708090a0b0c0d0e0f10:::\n"
    )
    findings = parse_secretsdump(out, target="10.0.0.5")
    assert len(findings) == 4
    assert all(f.severity == Severity.CRITICAL for f in findings)

    krbtgt = [f for f in findings if f.evidence["account"] == "CORP.LOCAL\\krbtgt"][0]
    assert krbtgt.evidence["rid"] == "502"
    assert krbtgt.evidence["nt_hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert krbtgt.evidence["machine_account"] is False

    machine = [f for f in findings if f.evidence["account"] == "WS01$"][0]
    assert machine.evidence["machine_account"] is True


def test_secretsdump_dedupes_same_account_and_hash() -> None:
    line = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    findings = parse_secretsdump(line * 3, target="x")
    assert len(findings) == 1


def test_secretsdump_empty_and_noise() -> None:
    assert parse_secretsdump("", target="x") == []
    assert parse_secretsdump("[*] Cleaning up...\n[-] error\n", target="x") == []


# ── certipy ──────────────────────────────────────────────────────────────────
def test_certipy_parses_json_vulnerabilities() -> None:
    payload = (
        '{"Certificate Templates": {'
        '"0": {"Template Name": "ESC1-Tmpl", "Enabled": true, '
        '"[!] Vulnerabilities": {"ESC1": "Domain Users can enroll and supply SAN"}}},'
        '"Certificate Authorities": {'
        '"0": {"CA Name": "corp-CA", '
        '"[!] Vulnerabilities": {"ESC7": "Domain Users have ManageCA"}}}}'
    )
    findings = parse_certipy(payload, target="dc.corp.local")
    assert len(findings) == 2
    assert all(f.severity == Severity.CRITICAL for f in findings)
    escs = {f.evidence["esc"] for f in findings}
    assert escs == {"ESC1", "ESC7"}

    esc1 = [f for f in findings if f.evidence["esc"] == "ESC1"][0]
    assert esc1.evidence["object"] == "ESC1-Tmpl"
    assert esc1.references == ["https://posts.specterops.io/certified-pre-owned-d95910965cd2"]


def test_certipy_text_fallback() -> None:
    text = (
        "Certificate Templates\n"
        "  Template Name : VulnTemplate\n"
        "  ESC1 : 'CORP\\\\Domain Users' can enroll and request as any user\n"
    )
    findings = parse_certipy(text, target="dc")
    assert len(findings) == 1
    assert findings[0].evidence["esc"] == "ESC1"
    assert findings[0].evidence["object"] == "VulnTemplate"


def test_certipy_empty() -> None:
    assert parse_certipy("", target="x") == []
    assert parse_certipy("{}", target="x") == []


# ── bloodhound ───────────────────────────────────────────────────────────────
def test_bloodhound_parses_collection_summary() -> None:
    out = (
        "INFO: Found 42 users\n"
        "INFO: Found 15 computers\n"
        "INFO: Found 30 groups\n"
        "INFO: Found 42 users\n"  # dup kind
        "INFO: Compressing output into 20260707_bloodhound.zip\n"
    )
    findings = parse_bloodhound(out, target="dc.corp.local")
    assert all(f.severity == Severity.INFO for f in findings)

    kinds = {f.evidence.get("kind") for f in findings if "kind" in f.evidence}
    assert kinds == {"users", "computers", "groups"}

    artifact = [f for f in findings if "artifact" in f.evidence]
    assert len(artifact) == 1
    assert artifact[0].evidence["artifact"] == "20260707_bloodhound.zip"


def test_bloodhound_empty() -> None:
    assert parse_bloodhound("", target="x") == []
