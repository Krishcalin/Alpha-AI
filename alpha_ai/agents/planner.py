"""Planning seam for the orchestrator.

A ``Planner`` looks at the findings gathered so far and proposes the next tool
invocations (``Step``s). The default ``RulePlanner`` is deterministic — a
declarative table maps service/finding signals to follow-on tools. The
``Planner`` Protocol is the seam: an ``LLMPlanner`` could later implement the
same ``next_steps`` method and drop in unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from alpha_ai.core.models import Finding


@dataclass
class Engagement:
    """Everything the planner needs to fill in follow-on tool arguments.

    Only ``target`` is required; credential/wordlist fields gate the steps that
    need them — a step whose prerequisites are absent is simply not proposed.
    """

    target: str
    domain: str | None = None
    username: str | None = None
    password: str | None = None
    hashes: str | None = None
    userlist: str | None = None
    wordlist: str | None = None


@dataclass(frozen=True)
class Step:
    """One planned tool invocation. Frozen + hashable so it can be de-duplicated."""

    tool: str
    target: str
    params: tuple[tuple[str, Any], ...] = ()
    reason: str = ""

    @classmethod
    def make(cls, tool: str, target: str, reason: str = "", **params: Any) -> "Step":
        return cls(tool=tool, target=target, params=tuple(sorted(params.items())), reason=reason)

    @property
    def kwargs(self) -> dict[str, Any]:
        return dict(self.params)

    def key(self) -> str:
        """Identity for run-once bookkeeping (ignores the human-readable reason)."""
        return f"{self.tool}|{self.target}|{self.params}"


@dataclass
class PlanContext:
    engagement: Engagement
    findings: list[Finding]
    ran: set[str] = field(default_factory=set)      # Step.key()s already executed
    available: set[str] = field(default_factory=set)  # registered tool names


@runtime_checkable
class Planner(Protocol):
    def next_steps(self, ctx: PlanContext) -> list[Step]:
        """Propose the next batch of steps given findings so far."""
        ...


# ── service-port → follow-on tool rules ──────────────────────────────────────
_WEB_HTTP = {80, 8000, 8080}
_WEB_HTTPS = {443, 8443}
_SMB = {139, 445}
_BRUTE_SVC = {21: "ftp", 22: "ssh", 3389: "rdp"}


def _port_of(f: Finding) -> int | None:
    """Normalize a port-scan finding's port to int (nmap=str, masscan=int)."""
    if f.tool not in ("nmap", "masscan"):
        return None
    try:
        return int(str(f.evidence.get("port")))
    except (TypeError, ValueError):
        return None


class RulePlanner:
    """Deterministic planner: expands port/service findings into follow-on steps."""

    def next_steps(self, ctx: PlanContext) -> list[Step]:
        proposed: list[Step] = []
        for f in ctx.findings:
            proposed.extend(self._react(f, ctx.engagement))

        # Filter to available tools, drop already-run and intra-batch duplicates.
        seen: set[str] = set()
        result: list[Step] = []
        for s in proposed:
            if ctx.available and s.tool not in ctx.available:
                continue
            k = s.key()
            if k in ctx.ran or k in seen:
                continue
            seen.add(k)
            result.append(s)
        return result

    # -- per-finding reactions -------------------------------------------------
    def _react(self, f: Finding, eng: Engagement) -> list[Step]:
        port = _port_of(f)
        if port is None:
            return []
        host = f.target
        steps: list[Step] = []

        if port in _WEB_HTTP:
            url = f"http://{host}" if port == 80 else f"http://{host}:{port}"
            steps += [
                Step.make("nuclei", url, reason=f"HTTP service on {port}"),
                Step.make("nikto", url, reason=f"web server scan (port {port})"),
                Step.make("gobuster", url, reason=f"content discovery (port {port})"),
            ]
        elif port in _WEB_HTTPS:
            url = f"https://{host}" if port == 443 else f"https://{host}:{port}"
            steps += [
                Step.make("nuclei", url, reason=f"HTTPS service on {port}"),
                Step.make("nikto", url, ssl=True, reason=f"web server scan (port {port})"),
            ]

        if port in _SMB:
            steps.append(Step.make("enum4linux", host, reason="SMB/NetBIOS open"))
            cme: dict[str, Any] = {"protocol": "smb"}
            if eng.username:
                cme.update(username=eng.username, shares=True, users=True)
                if eng.domain:
                    cme["domain"] = eng.domain
                if eng.password:
                    cme["password"] = eng.password
            steps.append(Step.make("crackmapexec", host, reason="SMB enumeration", **cme))

        if port == 88:  # Kerberos → domain controller
            steps += self._dc_chain(host, eng)

        if port in _BRUTE_SVC and eng.userlist and eng.wordlist:
            svc = _BRUTE_SVC[port]
            steps.append(
                Step.make(
                    "hydra", host, service=svc,
                    username_list=eng.userlist, password_list=eng.wordlist,
                    reason=f"{svc} credential brute-force",
                )
            )
        return steps

    def _dc_chain(self, host: str, eng: Engagement) -> list[Step]:
        """kerbrute → secretsdump → bloodhound → certipy, gated on what creds exist."""
        steps: list[Step] = []
        if not eng.domain:
            return steps

        if eng.userlist:
            steps.append(
                Step.make(
                    "kerbrute", host, domain=eng.domain, mode="userenum",
                    userlist=eng.userlist, reason="Kerberos user enumeration",
                )
            )

        has_creds = eng.username and (eng.password or eng.hashes)
        if not has_creds:
            return steps

        auth: dict[str, Any] = {"domain": eng.domain, "username": eng.username}
        if eng.password:
            auth["password"] = eng.password
        if eng.hashes:
            auth["hashes"] = eng.hashes

        steps.append(Step.make("secretsdump", host, reason="DCSync hash dump", just_dc=True, dc_ip=host, **auth))
        steps.append(Step.make("bloodhound", host, reason="AD attack-path collection", **auth))
        steps.append(Step.make("certipy", host, reason="ADCS ESC discovery", **auth))
        return steps
