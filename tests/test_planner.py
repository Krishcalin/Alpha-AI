"""Tests for the deterministic RulePlanner (Phase 3)."""

from __future__ import annotations

from alpha_ai.agents.planner import Engagement, PlanContext, Planner, RulePlanner, Step
from alpha_ai.core.models import Finding, Severity

ALL_TOOLS = {
    "nmap", "masscan", "nuclei", "nikto", "gobuster", "enum4linux", "crackmapexec",
    "kerbrute", "secretsdump", "bloodhound", "certipy", "hydra",
}


def _port(port, tool="nmap", target="10.0.0.5"):
    return Finding(tool=tool, target=target, title=f"port {port}", severity=Severity.INFO,
                   evidence={"port": port})


def _plan(findings, eng=None, ran=None):
    ctx = PlanContext(
        engagement=eng or Engagement(target="10.0.0.5"),
        findings=findings,
        ran=ran or set(),
        available=ALL_TOOLS,
    )
    return RulePlanner().next_steps(ctx)


def test_ruleplanner_satisfies_protocol() -> None:
    assert isinstance(RulePlanner(), Planner)


def test_http_port_expands_to_web_tools() -> None:
    steps = _plan([_port("80")])
    by_tool = {s.tool: s for s in steps}
    assert {"nuclei", "nikto", "gobuster"} <= set(by_tool)
    assert by_tool["nuclei"].target == "http://10.0.0.5"


def test_nonstandard_http_port_keeps_port_in_url() -> None:
    steps = _plan([_port(8080, tool="masscan")])  # masscan int port
    assert any(s.target == "http://10.0.0.5:8080" for s in steps)


def test_https_port_sets_ssl_on_nikto() -> None:
    steps = _plan([_port("443")])
    nikto = [s for s in steps if s.tool == "nikto"][0]
    assert nikto.target == "https://10.0.0.5"
    assert nikto.kwargs.get("ssl") is True


def test_smb_port_expands_to_enum_tools() -> None:
    steps = _plan([_port("445")])
    tools = {s.tool for s in steps}
    assert {"enum4linux", "crackmapexec"} <= tools


def test_dc_chain_gated_on_credentials() -> None:
    # No creds → at most kerbrute (needs userlist), no secretsdump/bloodhound/certipy.
    bare = _plan([_port("88")], eng=Engagement(target="10.0.0.5", domain="corp.local"))
    assert not any(s.tool in {"secretsdump", "bloodhound", "certipy"} for s in bare)

    # Full creds + userlist → whole chain.
    eng = Engagement(target="10.0.0.5", domain="corp.local", username="svc",
                     password="P@ss", userlist="/tmp/users.txt")
    full = {s.tool for s in _plan([_port("88")], eng=eng)}
    assert {"kerbrute", "secretsdump", "bloodhound", "certipy"} <= full


def test_already_run_steps_are_filtered() -> None:
    first = _plan([_port("445")])
    ran = {s.key() for s in first}
    again = _plan([_port("445")], ran=ran)
    assert again == []


def test_unavailable_tools_dropped() -> None:
    ctx = PlanContext(
        engagement=Engagement(target="10.0.0.5"),
        findings=[_port("80")],
        ran=set(),
        available={"nuclei"},  # nikto/gobuster not registered here
    )
    tools = {s.tool for s in RulePlanner().next_steps(ctx)}
    assert tools == {"nuclei"}


def test_non_portscan_findings_ignored() -> None:
    other = Finding(tool="nikto", target="http://x", title="XSS", severity=Severity.MEDIUM)
    assert _plan([other]) == []
