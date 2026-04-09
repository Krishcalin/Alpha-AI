"""FastAPI REST server exposing Alpha-AI tools.

Run with:  alpha-api  [--host 0.0.0.0] [--port 8000]
"""

from __future__ import annotations

import argparse

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from alpha_ai.core.auth import UnauthorizedTargetError
from alpha_ai.core.logging import configure_logging
from alpha_ai.core.registry import load_builtin_tools, registry
from alpha_ai.core.runner import ToolNotFoundError
from alpha_ai.servers.dispatcher import Dispatcher

configure_logging()
load_builtin_tools()

app = FastAPI(
    title="Alpha-AI",
    version="0.1.0",
    description="Agentic offensive-security framework — REST surface.",
)
_dispatch = Dispatcher()


class NmapRequest(BaseModel):
    target: str
    ports: str = "1-1000"
    service_detection: bool = True
    timing: int = Field(default=4, ge=0, le=5)
    use_cache: bool = True


class NucleiRequest(BaseModel):
    target: str
    severity: str | None = None
    tags: list[str] | None = None
    templates: str | None = None
    rate_limit: int = 150
    use_cache: bool = True


class GobusterRequest(BaseModel):
    target: str
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    extensions: str | None = None
    threads: int = 30
    status_codes: str = "200,204,301,302,307,401,403"
    use_cache: bool = True


class FfufRequest(BaseModel):
    target: str
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    match_codes: str = "200,204,301,302,307,401,403"
    threads: int = 40
    use_cache: bool = True


class SqlmapRequest(BaseModel):
    target: str
    data: str | None = None
    cookie: str | None = None
    level: int = Field(default=1, ge=1, le=5)
    risk: int = Field(default=1, ge=1, le=3)
    technique: str = "BEUSTQ"
    use_cache: bool = True


class Enum4linuxRequest(BaseModel):
    target: str
    aggressive: bool = False
    username: str | None = None
    password: str | None = None
    use_cache: bool = True


class CrackmapexecRequest(BaseModel):
    target: str
    protocol: str = "smb"
    username: str | None = None
    password: str | None = None
    hash: str | None = None
    domain: str | None = None
    module: str | None = None
    shares: bool = False
    users: bool = False
    use_cache: bool = True


class HydraRequest(BaseModel):
    target: str
    service: str = "ssh"
    username: str | None = None
    username_list: str | None = None
    password: str | None = None
    password_list: str | None = None
    port: int | None = None
    threads: int = 16
    stop_on_first: bool = True
    use_cache: bool = True


class SearchsploitRequest(BaseModel):
    query: str
    exclude: str | None = None
    cve: str | None = None
    use_cache: bool = True


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "tools": len(registry.all())}


@app.get("/tools")
async def list_tools() -> list[dict]:
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


@app.post("/tools/nmap")
async def run_nmap(req: NmapRequest) -> dict:
    return await _invoke(
        "nmap",
        req.target,
        use_cache=req.use_cache,
        ports=req.ports,
        service_detection=req.service_detection,
        timing=req.timing,
    )


@app.post("/tools/nuclei")
async def run_nuclei(req: NucleiRequest) -> dict:
    return await _invoke(
        "nuclei",
        req.target,
        use_cache=req.use_cache,
        severity=req.severity,
        tags=req.tags,
        templates=req.templates,
        rate_limit=req.rate_limit,
    )


@app.post("/tools/gobuster")
async def run_gobuster(req: GobusterRequest) -> dict:
    return await _invoke(
        "gobuster",
        req.target,
        use_cache=req.use_cache,
        wordlist=req.wordlist,
        extensions=req.extensions,
        threads=req.threads,
        status_codes=req.status_codes,
    )


@app.post("/tools/ffuf")
async def run_ffuf(req: FfufRequest) -> dict:
    return await _invoke(
        "ffuf",
        req.target,
        use_cache=req.use_cache,
        wordlist=req.wordlist,
        match_codes=req.match_codes,
        threads=req.threads,
    )


@app.post("/tools/sqlmap")
async def run_sqlmap(req: SqlmapRequest) -> dict:
    return await _invoke(
        "sqlmap",
        req.target,
        use_cache=req.use_cache,
        data=req.data,
        cookie=req.cookie,
        level=req.level,
        risk=req.risk,
        technique=req.technique,
    )


@app.post("/tools/enum4linux")
async def run_enum4linux(req: Enum4linuxRequest) -> dict:
    return await _invoke(
        "enum4linux",
        req.target,
        use_cache=req.use_cache,
        aggressive=req.aggressive,
        username=req.username,
        password=req.password,
    )


@app.post("/tools/crackmapexec")
async def run_crackmapexec(req: CrackmapexecRequest) -> dict:
    return await _invoke(
        "crackmapexec",
        req.target,
        use_cache=req.use_cache,
        protocol=req.protocol,
        username=req.username,
        password=req.password,
        hash=req.hash,
        domain=req.domain,
        module=req.module,
        shares=req.shares,
        users=req.users,
    )


@app.post("/tools/hydra")
async def run_hydra(req: HydraRequest) -> dict:
    return await _invoke(
        "hydra",
        req.target,
        use_cache=req.use_cache,
        service=req.service,
        username=req.username,
        username_list=req.username_list,
        password=req.password,
        password_list=req.password_list,
        port=req.port,
        threads=req.threads,
        stop_on_first=req.stop_on_first,
    )


@app.post("/tools/searchsploit")
async def run_searchsploit(req: SearchsploitRequest) -> dict:
    return await _invoke(
        "searchsploit",
        req.query,
        use_cache=req.use_cache,
        exclude=req.exclude,
        cve=req.cve,
    )


async def _invoke(tool: str, target: str, use_cache: bool, **kwargs) -> dict:
    try:
        result = await _dispatch.run_tool(tool, target=target, use_cache=use_cache, **kwargs)
    except UnauthorizedTargetError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    except ToolNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return result.model_dump(mode="json")


def main() -> None:
    parser = argparse.ArgumentParser(prog="alpha-api")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()
    uvicorn.run(
        "alpha_ai.servers.rest_api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
