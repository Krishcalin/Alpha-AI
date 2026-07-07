"""Registry self-registration smoke test."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory
from alpha_ai.core.registry import load_builtin_tools, registry


def test_builtin_tools_registered() -> None:
    load_builtin_tools()
    names = {s.name for s in registry.all()}
    expected = {
        "nmap", "nuclei", "gobuster", "ffuf", "sqlmap",
        "enum4linux", "crackmapexec", "hydra", "searchsploit",
        # Phase 2 — tool breadth
        "masscan", "subfinder", "nikto", "wpscan", "kerbrute",
        # Phase 2 — AD block
        "secretsdump", "certipy", "bloodhound",
        # Phase 2 — Cred block (local-only crackers)
        "john", "hashcat",
        # Phase 2 — Post block (result-file ingest)
        "linpeas", "winpeas",
    }
    assert expected <= names

    # searchsploit is local-only and must skip the authorization gate
    assert registry.get("searchsploit").requires_authorization is False
    assert registry.get("hydra").requires_authorization is True

    # masscan needs root; kerbrute lights up the AD category
    assert registry.get("masscan").requires_root is True
    assert registry.get("kerbrute").category is ToolCategory.AD

    # the whole AD block shares the AD category
    for ad_tool in ("secretsdump", "certipy", "bloodhound"):
        assert registry.get(ad_tool).category is ToolCategory.AD

    # john/hashcat and linpeas/winpeas are local-only — no authorization gate
    for local_tool in ("john", "hashcat", "linpeas", "winpeas"):
        assert registry.get(local_tool).requires_authorization is False
    for cred_tool in ("john", "hashcat"):
        assert registry.get(cred_tool).category is ToolCategory.CRED
    for post_tool in ("linpeas", "winpeas"):
        assert registry.get(post_tool).category is ToolCategory.POST
