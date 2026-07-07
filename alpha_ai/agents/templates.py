"""Named workflow templates — the seed steps each engagement starts from.

Reactions (web/SMB/AD expansion) are the planner's job; a template only decides
where the chain *begins*.
"""

from __future__ import annotations

from alpha_ai.agents.planner import Engagement, Step

TEMPLATE_NAMES = ("external-pentest", "internal-ad", "web-app")


def _looks_like_domain(target: str) -> bool:
    return any(c.isalpha() for c in target) and not target.startswith(("http://", "https://"))


def _web_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"http://{target}"


def seed_steps(template: str, eng: Engagement) -> list[Step]:
    """Return the initial steps for *template* against *eng.target*."""
    t = eng.target

    if template == "external-pentest":
        steps = [Step.make("nmap", t, reason="initial port + service scan", ports="1-1000")]
        if _looks_like_domain(t):
            steps.append(Step.make("subfinder", t, reason="passive subdomain enumeration"))
        return steps

    if template == "internal-ad":
        steps = [Step.make("nmap", t, reason="host + service scan", ports="1-1000")]
        if eng.domain and eng.username:
            cme: dict = {"protocol": "smb", "username": eng.username, "shares": True, "users": True, "domain": eng.domain}
            if eng.password:
                cme["password"] = eng.password
            steps.append(Step.make("crackmapexec", t, reason="authenticated SMB enumeration", **cme))
        return steps

    if template == "web-app":
        url = _web_url(t)
        return [
            Step.make("nmap", t, reason="port scan", ports="1-1000"),
            Step.make("nuclei", url, reason="template-based vulnerability scan"),
            Step.make("nikto", url, reason="web server misconfiguration scan"),
            Step.make("gobuster", url, reason="content discovery"),
        ]

    raise ValueError(f"unknown workflow template: {template!r} (choose from {TEMPLATE_NAMES})")
