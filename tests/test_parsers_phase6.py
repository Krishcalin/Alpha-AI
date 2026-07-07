"""Parser tests for the Phase 2 Cred block: john, hashcat."""

from __future__ import annotations

from alpha_ai.core.models import Severity
from alpha_ai.parsers.hashcat import parse_hashcat
from alpha_ai.parsers.john import parse_john


# ── john ─────────────────────────────────────────────────────────────────────
def test_john_parses_cracked_credentials() -> None:
    out = (
        "Winter2026       (CORP\\jdoe)\n"
        "password123      (Administrator)\n"
        "Winter2026       (CORP\\jdoe)\n"  # dup -> deduped
    )
    findings = parse_john(out, target="/tmp/hashes.txt")
    assert len(findings) == 2
    assert all(f.severity == Severity.CRITICAL for f in findings)

    jdoe = [f for f in findings if f.evidence["account"] == "CORP\\jdoe"][0]
    assert jdoe.evidence["password"] == "Winter2026"


def test_john_ignores_status_lines() -> None:
    # John sends these to stderr, but be defensive if any leak into stdout:
    # a plain status sentence has no trailing "(user)" and must not match.
    out = "Session completed\nProceeding with wordlist mode\n"
    assert parse_john(out, target="x") == []


def test_john_empty() -> None:
    assert parse_john("", target="x") == []


# ── hashcat ──────────────────────────────────────────────────────────────────
def test_hashcat_parses_hash_plaintext_pairs() -> None:
    out = (
        "31d6cfe0d16ae931b73c59d7e0c089c0:Winter2026\n"
        "5f4dcc3b5aa765d61d8327deb882cf99:password\n"
        "31d6cfe0d16ae931b73c59d7e0c089c0:Winter2026\n"  # dup -> deduped
    )
    findings = parse_hashcat(out, target="/tmp/ntlm.txt")
    assert len(findings) == 2
    assert all(f.severity == Severity.CRITICAL for f in findings)

    pw = [f for f in findings if f.evidence["hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"][0]
    assert pw.evidence["password"] == "password"


def test_hashcat_preserves_colons_in_plaintext() -> None:
    # Separator is the FIRST colon; plaintext may itself contain colons.
    out = "5f4dcc3b5aa765d61d8327deb882cf99:pa:ss:word\n"
    findings = parse_hashcat(out, target="x")
    assert len(findings) == 1
    assert findings[0].evidence["password"] == "pa:ss:word"


def test_hashcat_empty_and_noise() -> None:
    # --quiet guarantees stdout is only cracked pairs; a colon-free line is skipped.
    assert parse_hashcat("", target="x") == []
    assert parse_hashcat("no colon here at all\n", target="x") == []
