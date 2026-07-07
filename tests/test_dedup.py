"""Tests for finding deduplication (Phase 3)."""

from __future__ import annotations

from alpha_ai.core.dedup import dedupe_findings, finding_key
from alpha_ai.core.models import Finding, Severity


def _f(tool="nmap", target="10.0.0.5", title="Open port 445/tcp", evidence=None):
    return Finding(tool=tool, target=target, title=title, severity=Severity.INFO, evidence=evidence or {"port": "445"})


def test_identical_findings_collapse() -> None:
    findings = [_f(), _f(), _f()]
    assert len(dedupe_findings(findings)) == 1


def test_distinct_findings_preserved_in_order() -> None:
    a = _f(title="Open port 445/tcp", evidence={"port": "445"})
    b = _f(title="Open port 80/tcp", evidence={"port": "80"})
    c = _f(tool="masscan", title="Open port 445/tcp", evidence={"port": "445"})  # different tool
    out = dedupe_findings([a, b, c])
    assert [x.title for x in out] == ["Open port 445/tcp", "Open port 80/tcp", "Open port 445/tcp"]
    assert {x.tool for x in out} == {"nmap", "masscan"}


def test_key_ignores_timestamp() -> None:
    import time

    a = _f()
    time.sleep(0.001)
    b = _f()
    assert a.discovered_at != b.discovered_at  # timestamps differ
    assert finding_key(a) == finding_key(b)    # but identity is stable


def test_empty() -> None:
    assert dedupe_findings([]) == []
