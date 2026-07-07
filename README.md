# Alpha-AI

> Agentic AI offensive-security framework — MCP server + REST API exposing 50+ security tools to LLMs for autonomous penetration testing.

Alpha-AI lets a Claude/GPT/Copilot agent autonomously chain reconnaissance → vulnerability discovery → exploitation → reporting against authorized targets.

## Architecture

```
                      ┌─────────────────────┐
                      │   LLM Agent         │
                      │ (Claude / GPT / …)  │
                      └──────────┬──────────┘
                                 │
                  ┌──────────────┴───────────────┐
                  │                              │
          ┌───────▼────────┐            ┌────────▼────────┐
          │  MCP Server    │            │   REST API      │
          │  (FastMCP)     │            │   (FastAPI)     │
          └───────┬────────┘            └────────┬────────┘
                  │                              │
                  └──────────────┬───────────────┘
                                 │
                       ┌─────────▼─────────┐
                       │  Tool Registry    │
                       └─────────┬─────────┘
                                 │
        ┌────────────┬───────────┼──────────┬────────────┐
        │            │           │          │            │
    ┌───▼──┐     ┌───▼──┐    ┌───▼──┐   ┌───▼──┐    ┌───▼──┐
    │ nmap │     │nuclei│    │ ffuf │   │sqlmap│    │ ...  │
    └──────┘     └──────┘    └──────┘   └──────┘    └──────┘
                                 │
                       ┌─────────▼─────────┐
                       │ Subprocess Runner │
                       │  (timeout, cache, │
                       │   authz, logging) │
                       └───────────────────┘
```

## Components

| Layer | Purpose |
|-------|---------|
| `alpha_ai/core/runner.py` | Async subprocess wrapper — timeout, env isolation, output capture |
| `alpha_ai/core/cache.py` | Result cache keyed by `(tool, args)` to avoid re-running expensive scans |
| `alpha_ai/core/auth.py` | Target authorization — whitelist enforced before any tool runs |
| `alpha_ai/core/models.py` | Pydantic models: `Target`, `Finding`, `ToolResult`, `Severity` |
| `alpha_ai/core/registry.py` | Tool registry — single source of truth for MCP + REST |
| `alpha_ai/tools/` | Tool wrappers (recon, web, network, ad, cred, exploit) |
| `alpha_ai/parsers/` | Tool-specific output parsers → normalized `Finding` objects |
| `alpha_ai/servers/mcp_server.py` | FastMCP server entry — exposes tools as MCP tools |
| `alpha_ai/servers/rest_api.py` | FastAPI app — exposes the same tools as REST endpoints |

## Runtime

Alpha-AI assumes a **Kali Linux container** runtime — all underlying binaries (`nmap`, `nuclei`, `gobuster`, `ffuf`, `sqlmap`, `nikto`, `enum4linux`, `crackmapexec`, `hydra`, `searchsploit`, `impacket-*`, …) are expected to be on `$PATH`.

```bash
# Build the Kali container
docker build -t alpha-ai .

# Run MCP server (stdio transport for Claude Desktop / Code)
docker run -it --rm alpha-ai alpha-mcp

# Run REST API on :8000
docker run -it --rm -p 8000:8000 alpha-ai alpha-api
```

## Tools

| Category | Tool | Status |
|----------|------|:------:|
| Recon | nmap | ✅ |
| Recon | masscan | ✅ |
| Recon | subfinder | ✅ |
| Web | nuclei | ✅ |
| Web | gobuster | ✅ |
| Web | ffuf | ✅ |
| Web | sqlmap | ✅ |
| Web | nikto | ✅ |
| Web | wpscan | ✅ |
| Network | enum4linux | ✅ |
| Network | crackmapexec | ✅ |
| AD | kerbrute | ✅ |
| AD | secretsdump | ✅ |
| AD | certipy | ✅ |
| AD | bloodhound | ✅ |
| Cred | hydra | ✅ |
| Cred | john | ✅ |
| Cred | hashcat | ✅ |
| Exploit | searchsploit | ✅ |
| Post | linpeas | ✅ |
| Post | winpeas | ✅ |

## Autopilot (workflow orchestration)

Beyond calling tools one at a time, Alpha-AI can **chain them automatically**. A deterministic
playbook engine seeds a workflow template, runs the tools, then picks the next tools from what the
findings reveal — e.g. an open SMB port triggers `enum4linux` + `crackmapexec`; an open Kerberos
port with domain credentials triggers `kerbrute → secretsdump → bloodhound → certipy`.

Templates: `external-pentest`, `internal-ad`, `web-app`.

```bash
# REST
curl -X POST localhost:8000/workflows \
  -H 'content-type: application/json' \
  -d '{"target": "10.0.0.10", "template": "internal-ad",
       "domain": "corp.local", "username": "svc", "password": "P@ssw0rd",
       "userlist": "/usr/share/wordlists/users.txt"}'
```

Over MCP, call the `run_workflow` tool with the same fields. The planner is deterministic (no LLM,
no API cost) and sits behind a `Planner` protocol, so an LLM-driven planner can drop in later.
Every step runs at most once; findings are de-duplicated across the whole run.

## Authorization

**Alpha-AI is for authorized security testing only.** Targets must be explicitly listed in `config/targets.yaml` before any tool will run against them. All tool invocations are logged with timestamp, caller, target, command, and result.

## License

MIT
