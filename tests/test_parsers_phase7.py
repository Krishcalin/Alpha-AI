"""Parser tests for the Phase 2 Post block: linpeas / winpeas (shared PEASS parser)."""

from __future__ import annotations

from alpha_ai.core.models import Severity
from alpha_ai.parsers.peass import parse_peass

RED_YELLOW = "\x1b[1;31;103m"  # 99% PE vector
BOLD_RED = "\x1b[1;31m"        # special / interesting
RESET = "\x1b[0m"


def test_peass_red_yellow_is_critical_with_section() -> None:
    out = (
        "╔══════════╣ Interesting Files - SUID\n"
        f"  {RED_YELLOW}/usr/bin/pkexec{RESET} (Vulnerable to CVE-2021-4034)\n"
    )
    findings = parse_peass(out, target="/tmp/linpeas.txt", tool="linpeas")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.tool == "linpeas"
    assert "pkexec" in f.title
    assert f.evidence["section"] == "Interesting Files - SUID"
    assert f.evidence["highlights"] == ["/usr/bin/pkexec"]


def test_peass_bold_red_is_high() -> None:
    out = f"  Sudo version {BOLD_RED}1.8.31{RESET}\n"
    findings = parse_peass(out, target="/tmp/linpeas.txt", tool="linpeas")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_peass_dedupes_identical_highlighted_lines() -> None:
    line = f"  {RED_YELLOW}writable /etc/passwd{RESET}\n"
    findings = parse_peass(line * 3, target="x", tool="winpeas")
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(crit) == 1


def test_peass_no_highlights_emits_info_note() -> None:
    # ANSI-stripped capture: real content but no PEASS color left.
    out = "System Information\nLinux host 5.15.0\nsudo version 1.8.31\n"
    findings = parse_peass(out, target="/tmp/plain.txt", tool="linpeas")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "no color highlights" in findings[0].title.lower()
    assert findings[0].evidence["line_count"] == 3


def test_peass_mixed_and_empty() -> None:
    out = (
        "╔══════════╣ Cron jobs\n"
        f"  {RED_YELLOW}/etc/cron.d/backup writable{RESET}\n"
        f"  interesting: {BOLD_RED}root cron{RESET}\n"
    )
    findings = parse_peass(out, target="x", tool="linpeas")
    sevs = {f.severity for f in findings}
    assert Severity.CRITICAL in sevs and Severity.HIGH in sevs
    assert all(f.evidence["section"] == "Cron jobs" for f in findings)

    assert parse_peass("", target="x", tool="linpeas") == []
    assert parse_peass("   \n  \n", target="x", tool="linpeas") == []
