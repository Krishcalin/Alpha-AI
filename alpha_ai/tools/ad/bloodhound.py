"""bloodhound-python wrapper — Active Directory attack-path data collection."""

from __future__ import annotations

from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.bloodhound import parse_bloodhound

_runner = CommandRunner()


async def bloodhound_scan(
    target: str,
    domain: str,
    username: str,
    password: str | None = None,
    hashes: str | None = None,
    collection_method: str = "Default",
    nameserver: str | None = None,
    timeout: float = 900.0,
) -> ToolResult:
    """Collect AD data from *target* (a DC) for BloodHound analysis.

    Args:
        target: Domain controller host/IP (-dc). Must be authorized.
        domain: AD domain (e.g. "corp.local").
        username: Domain user.
        password: Password (or use *hashes*).
        hashes: "LMHASH:NTHASH" for pass-the-hash (--hashes).
        collection_method: SharpHound method — Default, All, DCOnly, Session, etc.
        nameserver: DNS server to resolve the domain (-ns); defaults to *target*.
    """
    cmd = [
        "bloodhound-python",
        "-d", domain,
        "-u", username,
        "-dc", target,
        "-c", collection_method,
        "-ns", nameserver or target,
        "--zip",
    ]
    if password is not None:
        cmd += ["-p", password]
    if hashes:
        cmd += ["--hashes", hashes]

    cmd_result = await _runner.run(cmd, timeout=timeout)
    # Progress (INFO: Found N ...) is logged to stderr; combine both streams.
    combined = f"{cmd_result.stdout}\n{cmd_result.stderr}"
    findings = parse_bloodhound(combined, target=target)

    return ToolResult(
        tool="bloodhound",
        target=target,
        args={"domain": domain, "username": username, "collection_method": collection_method},
        command=cmd_result,
        findings=findings,
    )


registry.register(
    ToolSpec(
        name="bloodhound",
        category=ToolCategory.AD,
        description="Collect AD objects/ACLs/sessions for BloodHound attack-path mapping (bloodhound-python).",
        fn=bloodhound_scan,
        parameters={
            "target": {"type": "string", "required": True, "description": "DC host/IP"},
            "domain": {"type": "string", "required": True},
            "username": {"type": "string", "required": True},
            "password": {"type": "string"},
            "hashes": {"type": "string", "description": "LMHASH:NTHASH for pass-the-hash"},
            "collection_method": {"type": "string", "default": "Default"},
            "nameserver": {"type": "string", "description": "DNS server; defaults to target"},
        },
    )
)
