"""FastMCP server exposing Alpha-AI tools to LLM agents.

Run with:  alpha-mcp        (stdio transport — for Claude Desktop / Code)
"""

from __future__ import annotations

from fastmcp import FastMCP

from alpha_ai.core.logging import configure_logging
from alpha_ai.core.registry import load_builtin_tools, registry
from alpha_ai.servers.dispatcher import Dispatcher

configure_logging()
load_builtin_tools()

mcp = FastMCP("alpha-ai")
_dispatch = Dispatcher()


@mcp.tool()
async def list_tools() -> list[dict]:
    """List all security tools registered in Alpha-AI."""
    return [
        {
            "name": s.name,
            "category": s.category.value,
            "description": s.description,
            "parameters": s.parameters,
            "requires_root": s.requires_root,
        }
        for s in registry.all()
    ]


@mcp.tool()
async def nmap_scan(
    target: str,
    ports: str = "1-1000",
    service_detection: bool = True,
    timing: int = 4,
) -> dict:
    """Run nmap port + service scan against an authorized target."""
    result = await _dispatch.run_tool(
        "nmap",
        target=target,
        ports=ports,
        service_detection=service_detection,
        timing=timing,
    )
    return result.model_dump(mode="json")


@mcp.tool()
async def nuclei_scan(
    target: str,
    severity: str | None = None,
    tags: list[str] | None = None,
) -> dict:
    """Run nuclei template-based vulnerability scan against an authorized URL."""
    result = await _dispatch.run_tool(
        "nuclei",
        target=target,
        severity=severity,
        tags=tags,
    )
    return result.model_dump(mode="json")


@mcp.tool()
async def gobuster_scan(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str | None = None,
    threads: int = 30,
) -> dict:
    """Brute-force directories and files on a web target with gobuster."""
    result = await _dispatch.run_tool(
        "gobuster",
        target=target,
        wordlist=wordlist,
        extensions=extensions,
        threads=threads,
    )
    return result.model_dump(mode="json")


@mcp.tool()
async def ffuf_scan(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    match_codes: str = "200,204,301,302,307,401,403",
    threads: int = 40,
) -> dict:
    """Fast web fuzzer (ffuf). The target URL must include the FUZZ keyword."""
    result = await _dispatch.run_tool(
        "ffuf",
        target=target,
        wordlist=wordlist,
        match_codes=match_codes,
        threads=threads,
    )
    return result.model_dump(mode="json")


@mcp.tool()
async def sqlmap_scan(
    target: str,
    data: str | None = None,
    cookie: str | None = None,
    level: int = 1,
    risk: int = 1,
) -> dict:
    """Automated SQL injection detection with sqlmap (batch mode)."""
    result = await _dispatch.run_tool(
        "sqlmap",
        target=target,
        data=data,
        cookie=cookie,
        level=level,
        risk=risk,
    )
    return result.model_dump(mode="json")


@mcp.tool()
async def enum4linux_scan(
    target: str,
    aggressive: bool = False,
    username: str | None = None,
    password: str | None = None,
) -> dict:
    """SMB/Samba enumeration (shares, users, OS) with enum4linux."""
    result = await _dispatch.run_tool(
        "enum4linux",
        target=target,
        aggressive=aggressive,
        username=username,
        password=password,
    )
    return result.model_dump(mode="json")


@mcp.tool()
async def crackmapexec_scan(
    target: str,
    protocol: str = "smb",
    username: str | None = None,
    password: str | None = None,
    hash: str | None = None,
    domain: str | None = None,
    shares: bool = False,
    users: bool = False,
) -> dict:
    """Multi-protocol network/AD pentesting tool (crackmapexec)."""
    result = await _dispatch.run_tool(
        "crackmapexec",
        target=target,
        protocol=protocol,
        username=username,
        password=password,
        hash=hash,
        domain=domain,
        shares=shares,
        users=users,
    )
    return result.model_dump(mode="json")


@mcp.tool()
async def hydra_scan(
    target: str,
    service: str = "ssh",
    username: str | None = None,
    username_list: str | None = None,
    password: str | None = None,
    password_list: str | None = None,
    port: int | None = None,
    threads: int = 16,
    stop_on_first: bool = True,
) -> dict:
    """Brute-force network logins with hydra (SSH/FTP/SMB/RDP/HTTP/MySQL/Postgres/...)."""
    result = await _dispatch.run_tool(
        "hydra",
        target=target,
        service=service,
        username=username,
        username_list=username_list,
        password=password,
        password_list=password_list,
        port=port,
        threads=threads,
        stop_on_first=stop_on_first,
    )
    return result.model_dump(mode="json")


@mcp.tool()
async def searchsploit_search(
    query: str,
    exclude: str | None = None,
    cve: str | None = None,
) -> dict:
    """Search Exploit-DB locally with searchsploit. The query replaces the target."""
    result = await _dispatch.run_tool(
        "searchsploit",
        target=query,
        exclude=exclude,
        cve=cve,
    )
    return result.model_dump(mode="json")


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
