"""Registry self-registration smoke test."""

from __future__ import annotations

from alpha_ai.core.registry import load_builtin_tools, registry


def test_builtin_tools_registered() -> None:
    load_builtin_tools()
    names = {s.name for s in registry.all()}
    expected = {
        "nmap", "nuclei", "gobuster", "ffuf", "sqlmap",
        "enum4linux", "crackmapexec", "hydra", "searchsploit",
    }
    assert expected <= names

    # searchsploit is local-only and must skip the authorization gate
    assert registry.get("searchsploit").requires_authorization is False
    assert registry.get("hydra").requires_authorization is True
