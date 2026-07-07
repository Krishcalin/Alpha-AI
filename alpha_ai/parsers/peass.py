"""Parse PEASS-ng (linpeas / winpeas) enumeration output.

linpeas and winpeas share one color scheme (PEASS-ng), so one parser serves both.
Their whole value is the color highlighting they apply to privesc-relevant lines:

    RED-on-YELLOW  (ESC[1;31;103m …)  = "99% a PE vector"      -> CRITICAL
    bold RED       (ESC[1;31m …)      = highlighted / special   -> HIGH

Section banners look like ``╔══════════╣ Basic information`` — we track the most
recent one so each finding carries the section it came from.

If the captured output has no PEASS highlights at all (a common result of piping
through a tool that stripped ANSI), we emit a single INFO finding so the operator
knows the ingest succeeded but needs manual review.
"""

from __future__ import annotations

import re

from alpha_ai.core.models import Finding, Severity

# PEASS-ng highlight escape codes (see linpeas.sh SED_RED / SED_RED_YELLOW).
_RED_YELLOW = "\x1b[1;31;103m"          # 99% privesc vector
_BOLD_RED = "\x1b[1;31m"                # special / interesting

_HIGHLIGHT_RE = re.compile(r"\x1b\[1;31(?:;103)?m(.*?)\x1b\[0m", re.DOTALL)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SECTION_RE = re.compile(r"╣\s*(?P<title>.+)")

_MAX_TITLE = 180


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _clean(text: str) -> str:
    return " ".join(_strip_ansi(text).split())


def parse_peass(output: str, target: str, tool: str = "peass") -> list[Finding]:
    """Convert PEASS-ng output into Findings, one per highlighted line."""
    findings: list[Finding] = []
    if not output.strip():
        return findings

    current_section = ""
    seen: set[tuple[str, str]] = set()
    highlighted_any = False

    for raw_line in output.splitlines():
        # Update section context from banner lines (strip ANSI first).
        stripped = _strip_ansi(raw_line)
        if "╣" in stripped:
            m = _SECTION_RE.search(stripped)
            if m:
                current_section = m.group("title").strip(" ═╗╔║╝╚╬╠").strip()
            continue

        has_red_yellow = _RED_YELLOW in raw_line
        has_bold_red = _BOLD_RED in raw_line
        if not (has_red_yellow or has_bold_red):
            continue

        highlighted_any = True
        severity = Severity.CRITICAL if has_red_yellow else Severity.HIGH
        title = _clean(raw_line)
        if not title:
            continue
        if len(title) > _MAX_TITLE:
            title = title[:_MAX_TITLE] + "…"

        key = (severity.value, title)
        if key in seen:
            continue
        seen.add(key)

        tokens = [_clean(t) for t in _HIGHLIGHT_RE.findall(raw_line)]
        tokens = [t for t in tokens if t]

        findings.append(
            Finding(
                tool=tool,
                target=target,
                title=title,
                severity=severity,
                description=(
                    "PEASS-ng flagged a probable privilege-escalation vector"
                    if has_red_yellow
                    else "PEASS-ng highlighted a notable item"
                ),
                evidence={
                    "section": current_section,
                    "highlights": tokens,
                    "confidence": "99% PE vector" if has_red_yellow else "special",
                },
            )
        )

    if not highlighted_any:
        line_count = len(output.splitlines())
        findings.append(
            Finding(
                tool=tool,
                target=target,
                title="PEASS output ingested — no color highlights detected",
                severity=Severity.INFO,
                description=(
                    f"Parsed {line_count} lines but found no PEASS highlights; the capture "
                    "likely stripped ANSI color. Review the raw output manually."
                ),
                evidence={"line_count": line_count},
            )
        )
    return findings
