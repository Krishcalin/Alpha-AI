# CLAUDE.md — Alpha-AI

## Project Overview

Alpha-AI is an agentic offensive-security framework that exposes security tools to LLM agents
(Claude, GPT, Copilot) over **two parallel surfaces**: an MCP server (FastMCP, stdio transport)
and a REST API (FastAPI). Both surfaces share a single tool registry, so each tool wrapper is
written once and exposed everywhere.

Inspired by [HexStrike AI](https://github.com/0x4m4/hexstrike-ai/). Designed to run inside a
**Kali Linux container** — all underlying binaries (nmap, nuclei, gobuster, ffuf, sqlmap,
enum4linux, crackmapexec, hydra, searchsploit, …) are expected on `$PATH`.

**Repository**: https://github.com/Krishcalin/Alpha-AI
**License**: MIT
**Python**: 3.11+
**Status**: MVP — 9 tools wrapped (recon, web, network, cred, exploit), 21 tests passing

---

## Architecture

### Directory layout

```
Alpha-AI/
├── pyproject.toml              # fastmcp, fastapi, uvicorn, pydantic, structlog
├── Dockerfile                  # kalilinux/kali-rolling base + all tool binaries
├── README.md
├── CLAUDE.md                   # this file
├── config/
│   └── targets.example.yaml    # authorization whitelist (literals + CIDR + globs)
├── alpha_ai/
│   ├── __init__.py             # __version__ = "0.1.0"
│   ├── core/
│   │   ├── models.py           # Target, Finding, CommandResult, ToolResult, Severity, ToolCategory
│   │   ├── runner.py           # CommandRunner — async subprocess + timeout + which()
│   │   ├── cache.py            # ResultCache — sha256(tool, target, args) → JSON file
│   │   ├── auth.py             # TargetAuthorizer — literals, CIDRs, globs; UnauthorizedTargetError
│   │   ├── registry.py         # ToolSpec, ToolRegistry, global registry, load_builtin_tools()
│   │   └── logging.py          # structlog setup
│   ├── parsers/                # Per-tool output → list[Finding]
│   │   ├── nmap.py             # XML → open ports
│   │   ├── nuclei.py           # JSONL → CVE-tagged findings
│   │   ├── gobuster.py         # text → discovered paths (sensitive paths flagged MEDIUM)
│   │   ├── ffuf.py             # JSON → matched URLs
│   │   ├── sqlmap.py           # text → injection points (always CRITICAL)
│   │   ├── enum4linux.py       # text → shares, users, OS banner
│   │   ├── crackmapexec.py     # text → [+] success lines (Pwn3d! → CRITICAL)
│   │   ├── hydra.py            # text → valid credentials (always CRITICAL)
│   │   └── searchsploit.py     # JSON → exploit-db entries (severity by type)
│   ├── tools/
│   │   ├── recon/nmap.py
│   │   ├── web/{nuclei,gobuster,ffuf,sqlmap}.py
│   │   ├── network/{enum4linux,crackmapexec}.py
│   │   ├── cred/hydra.py
│   │   └── exploit/searchsploit.py
│   └── servers/
│       ├── dispatcher.py       # Shared: authz → cache → tool fn → cache write
│       ├── mcp_server.py       # FastMCP — stdio entrypoint `alpha-mcp`
│       └── rest_api.py         # FastAPI — uvicorn entrypoint `alpha-api`
└── tests/
    ├── test_runner.py          # subprocess + timeout + missing-binary (Linux only)
    ├── test_auth.py            # whitelist literals/CIDR/glob
    ├── test_parsers.py         # nmap, nuclei
    ├── test_parsers_more.py    # gobuster, ffuf, sqlmap, enum4linux, crackmapexec
    ├── test_parsers_phase3.py  # hydra, searchsploit
    ├── test_registry.py        # all 9 tools self-register; flags asserted
    └── test_dispatcher.py      # authz gate is bypassed for requires_authorization=False tools
```

### Core design principles

1. **Single source of truth** — every tool registers once with `ToolRegistry`. The MCP server
   and REST API both import from the registry; no duplicated tool logic between surfaces.
2. **Authorization is the default** — `TargetAuthorizer` blocks any tool against a host not
   in the whitelist. Local-only tools (e.g. searchsploit) opt out via
   `ToolSpec.requires_authorization=False`.
3. **Cache-first** — `Dispatcher` checks the disk cache (`sha256(tool, target, args)`) before
   running. Use `use_cache=False` to force re-run.
4. **Parsers are pure** — `parse_*` functions take text/JSON and return `list[Finding]` with no
   I/O. They are unit-tested in isolation; tool wrappers don't need integration tests for parse
   logic.
5. **Tool wrappers are thin** — the wrapper builds the argv, calls `_runner.run()`, hands the
   stdout to its parser, and packages the result into a `ToolResult`. No business logic.
6. **Linux/Kali assumed** — no Windows shims, no shell quoting on Windows. Wrappers call
   binaries by name and let `CommandRunner.which()` raise `ToolNotFoundError` if missing.

### Request flow

```
LLM agent
  │
  ├── (MCP) FastMCP @mcp.tool() shim
  │       └── _dispatch.run_tool(name, target, **kwargs)
  │
  └── (REST) FastAPI POST /tools/<name>
          └── _dispatch.run_tool(name, target, **kwargs)
                  │
                  ├── registry.get(name) → ToolSpec
                  ├── if spec.requires_authorization: authorizer.require(target)
                  ├── if use_cache: cache.get(...) → return if hit
                  ├── result = await spec.fn(target=target, **kwargs)
                  │       ├── runner.run(argv) → CommandResult
                  │       └── parse_<tool>(stdout) → list[Finding]
                  ├── cache.put(result)
                  └── return ToolResult
```

### Models (`core/models.py`)

- **`Severity`** — INFO, LOW, MEDIUM, HIGH, CRITICAL
- **`ToolCategory`** — RECON, WEB, NETWORK, AD, CRED, EXPLOIT, POST
- **`Target`** — value + kind (auto/host/ip/cidr/url)
- **`Finding`** — tool, target, title, severity, description, evidence dict, references, CVE list, timestamp
- **`CommandResult`** — argv, returncode, stdout, stderr, duration_sec, timed_out
- **`ToolResult`** — tool, target, args, command, findings, cached, started_at; `success` property = `returncode == 0 and not timed_out`

### Authorization (`core/auth.py`)

Loads `config/targets.yaml`:
```yaml
authorized_targets:
  - 127.0.0.1
  - localhost
  - 10.0.0.0/24      # CIDR
  - "*.lab.internal" # glob
```

`TargetAuthorizer.require(target)` raises `UnauthorizedTargetError` (a `PermissionError`
subclass) if the target is not whitelisted. The REST API maps this to HTTP 403.

---

## Tool inventory

| Category | Tool         | Module                                       | Severity policy                                   |
|----------|--------------|----------------------------------------------|---------------------------------------------------|
| Recon    | nmap         | `tools/recon/nmap.py`                        | INFO per open port                                |
| Web      | nuclei       | `tools/web/nuclei.py`                        | Maps nuclei severity 1:1                          |
| Web      | gobuster     | `tools/web/gobuster.py`                      | Sensitive paths → MEDIUM, 200s → LOW              |
| Web      | ffuf         | `tools/web/ffuf.py`                          | 200s → LOW, others → INFO                         |
| Web      | sqlmap       | `tools/web/sqlmap.py`                        | Always CRITICAL on injection point                |
| Network  | enum4linux   | `tools/network/enum4linux.py`                | Disk shares → MEDIUM, users → LOW, OS → INFO      |
| Network  | crackmapexec | `tools/network/crackmapexec.py`              | `Pwn3d!` → CRITICAL, other `[+]` → HIGH           |
| Cred     | hydra        | `tools/cred/hydra.py`                        | Always CRITICAL on valid credentials              |
| Exploit  | searchsploit | `tools/exploit/searchsploit.py` (local-only) | webapps/remote → HIGH, local/dos → MEDIUM         |

**9 tools, all flow through the same dispatcher.**

---

## Adding a new tool — the pattern

Adding tool #10 takes 5 files. Follow this pattern exactly:

### 1. Parser (`alpha_ai/parsers/<tool>.py`)

```python
from alpha_ai.core.models import Finding, Severity

def parse_<tool>(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    # ... regex / json / xml parsing ...
    return findings
```

Pure function. No I/O. Returns empty list on garbage input. Unit-tested directly.

### 2. Wrapper (`alpha_ai/tools/<category>/<tool>.py`)

```python
from alpha_ai.core.models import ToolCategory, ToolResult
from alpha_ai.core.registry import ToolSpec, registry
from alpha_ai.core.runner import CommandRunner
from alpha_ai.parsers.<tool> import parse_<tool>

_runner = CommandRunner()

async def <tool>_scan(target: str, ...kwargs) -> ToolResult:
    cmd = ["<tool>", ...]
    cmd_result = await _runner.run(cmd, timeout=...)
    findings = parse_<tool>(cmd_result.stdout, target=target)
    return ToolResult(
        tool="<tool>", target=target, args={...},
        command=cmd_result, findings=findings,
    )

registry.register(ToolSpec(
    name="<tool>",
    category=ToolCategory.<CATEGORY>,
    description="...",
    fn=<tool>_scan,
    parameters={...},                     # JSON-schema-ish dict for MCP/REST docs
    requires_authorization=True,          # False only for local-only tools
))
```

### 3. Register in `core/registry.py`

```python
def load_builtin_tools() -> None:
    ...
    from alpha_ai.tools.<category> import <tool> as _<tool>  # noqa: F401
```

### 4. MCP shim in `servers/mcp_server.py`

```python
@mcp.tool()
async def <tool>_scan(target: str, ...) -> dict:
    """One-line description for the LLM."""
    result = await _dispatch.run_tool("<tool>", target=target, ...)
    return result.model_dump(mode="json")
```

### 5. REST route in `servers/rest_api.py`

```python
class <Tool>Request(BaseModel):
    target: str
    use_cache: bool = True
    # ... params

@app.post("/tools/<tool>")
async def run_<tool>(req: <Tool>Request) -> dict:
    return await _invoke("<tool>", req.target, use_cache=req.use_cache, ...)
```

### 6. Tests

- Add a parser test in `tests/test_parsers_<phase>.py` (golden output → expected findings)
- Add the new tool name to `test_registry.py::test_builtin_tools_registered`'s expected set

That's it. The dispatcher, cache, authz, and logging come for free.

---

## Coding conventions

- Python 3.11+ (use `match/case`, `X | Y` unions, PEP 604 syntax)
- Type hints on every public function
- One tool per file, named after the binary (e.g. `gobuster.py` not `dir_brute.py`)
- Parsers live next to each other in `alpha_ai/parsers/` (not nested by category) — easier to grep
- Use `structlog.get_logger(__name__)` — never bare `print()` or `logging.info()`
- Tests mirror the source layout; one test file per parser group
- All config via YAML — no hardcoded paths in tool wrappers (use `DEFAULT_WORDLIST` constants)

### What NOT to do

- **Don't add fallback shell paths** for Windows. The container is Kali; if a binary is
  missing, `CommandRunner.which()` should raise loudly.
- **Don't bypass the dispatcher**. MCP shims and REST routes both call `_dispatch.run_tool()`.
  Authorization and caching are enforced there, not in tool wrappers.
- **Don't put parsing logic in tool wrappers**. The wrapper builds argv and calls the parser.
- **Don't `subprocess.run()` directly**. Always go through `CommandRunner.run()` so timeouts,
  logging, and error handling are uniform.
- **Don't add a tool without a parser test**. Parsers are the only piece of tool code that
  has unit tests (subprocess execution is integration-tested in the container).

---

## Safety & authorization

- All tools default to `requires_authorization=True`
- Targets must be in `config/targets.yaml` before any remote tool will run against them
- `searchsploit` is the only opt-out (local-only DB lookup)
- Every tool invocation is logged via structlog with: tool name, target, argv, returncode, duration
- The cache is keyed on `(tool, target, args)` — re-running with `use_cache=False` re-executes

---

## Running the tool

### Local development (Windows host)

```bash
python -m pip install pydantic pyyaml structlog pytest pytest-asyncio
python -m pytest tests/test_parsers.py tests/test_parsers_more.py tests/test_parsers_phase3.py \
                 tests/test_auth.py tests/test_registry.py tests/test_dispatcher.py -q
```

The runner tests (`test_runner.py`) need a Linux environment because they exec `sleep`.

### Production (Kali container)

```bash
docker build -t alpha-ai .

# MCP server (stdio — for Claude Desktop / Code)
docker run -it --rm \
    -v $(pwd)/config:/opt/alpha-ai/config \
    -v $(pwd)/cache:/opt/alpha-ai/cache \
    alpha-ai alpha-mcp

# REST API on :8000
docker run -it --rm -p 8000:8000 \
    -v $(pwd)/config:/opt/alpha-ai/config \
    -v $(pwd)/cache:/opt/alpha-ai/cache \
    alpha-ai
```

### Claude Desktop / Code MCP config

```json
{
  "mcpServers": {
    "alpha-ai": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "-v", "/abs/path/config:/opt/alpha-ai/config",
               "-v", "/abs/path/cache:/opt/alpha-ai/cache",
               "alpha-ai", "alpha-mcp"]
    }
  }
}
```

### REST API examples

```bash
curl -X POST http://localhost:8000/tools/nmap \
    -H "content-type: application/json" \
    -d '{"target":"127.0.0.1","ports":"22,80,443","timing":4}'

curl -X POST http://localhost:8000/tools/searchsploit \
    -H "content-type: application/json" \
    -d '{"query":"Apache 2.4.49"}'

curl http://localhost:8000/tools     # list all registered tools
curl http://localhost:8000/health
```

---

## Roadmap

### Phase 1 — MVP (COMPLETE)
- [x] Core: runner, models, cache, auth, registry, dispatcher
- [x] MCP server (FastMCP) + REST API (FastAPI) sharing the registry
- [x] 9 tools across recon/web/network/cred/exploit
- [x] 21 unit tests (parsers, auth, registry, dispatcher)
- [x] Dockerfile (Kali base) with all binaries preinstalled
- [x] Authorization model with `requires_authorization` opt-out

### Phase 2 — Tool breadth
- [ ] Recon: masscan, amass, subfinder, dnsrecon
- [ ] Web: nikto, wpscan, wfuzz
- [ ] AD: impacket-secretsdump, kerbrute, certipy, bloodhound-python
- [ ] Cred: john, hashcat (local-only — `requires_authorization=False`)
- [ ] Post: linpeas/winpeas wrappers (require uploaded result file)

### Phase 3 — Orchestration
- [ ] `agents/autopilot.py` — LLM-driven loop that picks the next tool from prior findings
- [ ] Finding deduplication across tool runs (hash by tool + target + evidence)
- [ ] Workflow templates: "external pentest", "internal AD", "web app assessment"

### Phase 4 — Reporting
- [ ] Markdown report generator (group findings by severity → tool → target)
- [ ] HTML report (port the Jinja2 template from Windows-Red-Teaming)
- [ ] MITRE ATT&CK technique mapping per finding
- [ ] Export ATT&CK Navigator JSON layer

### Phase 5 — Hardening
- [ ] Integration tests against vulnerable lab containers (DVWA, Metasploitable, vulhub)
- [ ] Rate limiting and concurrency caps in the dispatcher
- [ ] Per-tool resource quotas (CPU, wall time, max output size)
- [ ] CI/CD pipeline (GitHub Actions): lint, type-check, parser tests, container build
- [ ] OpenAPI schema validation tests

---

## Key dependencies

```
fastmcp>=0.2.0           # MCP server framework
fastapi>=0.110.0         # REST API framework
uvicorn[standard]>=0.29  # ASGI server
pydantic>=2.6            # Models, request/response validation
httpx>=0.27              # HTTP client (for future API-driven tools)
structlog>=24.0          # Structured logging
rich>=13.7               # CLI output (future)
pyyaml>=6.0              # Config loading
python-multipart>=0.0.9  # FastAPI form/file uploads
```

Test-only: `pytest>=8.0`, `pytest-asyncio>=0.23`, `pytest-cov>=4.1`
