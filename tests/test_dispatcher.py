"""Dispatcher behavior tests — authorization gating + skip for local-only tools."""

from __future__ import annotations

from pathlib import Path

import pytest

from alpha_ai.core.auth import TargetAuthorizer, UnauthorizedTargetError
from alpha_ai.core.cache import ResultCache
from alpha_ai.core.models import CommandResult, ToolCategory, ToolResult
from alpha_ai.core.registry import ToolRegistry, ToolSpec
from alpha_ai.servers.dispatcher import Dispatcher
from alpha_ai.servers import dispatcher as dispatcher_mod


@pytest.fixture
def empty_authz(tmp_path: Path) -> TargetAuthorizer:
    cfg = tmp_path / "targets.yaml"
    cfg.write_text("authorized_targets: []\n")
    return TargetAuthorizer(cfg)


@pytest.fixture
def stub_registry(monkeypatch: pytest.MonkeyPatch) -> ToolRegistry:
    """Replace the global registry with an isolated one for this test."""
    reg = ToolRegistry()

    async def _local_fn(target: str, **kwargs) -> ToolResult:
        return ToolResult(
            tool="local_only",
            target=target,
            args=kwargs,
            command=CommandResult(
                command=["echo", target], returncode=0, stdout="", stderr="", duration_sec=0.0
            ),
        )

    async def _remote_fn(target: str, **kwargs) -> ToolResult:
        return ToolResult(
            tool="remote",
            target=target,
            args=kwargs,
            command=CommandResult(
                command=["echo", target], returncode=0, stdout="", stderr="", duration_sec=0.0
            ),
        )

    reg.register(
        ToolSpec(
            name="local_only",
            category=ToolCategory.EXPLOIT,
            description="local",
            fn=_local_fn,
            requires_authorization=False,
        )
    )
    reg.register(
        ToolSpec(
            name="remote",
            category=ToolCategory.RECON,
            description="remote",
            fn=_remote_fn,
            requires_authorization=True,
        )
    )

    monkeypatch.setattr(dispatcher_mod, "registry", reg)
    return reg


@pytest.mark.asyncio
async def test_dispatcher_blocks_unauthorized_remote_target(
    empty_authz: TargetAuthorizer, tmp_path: Path, stub_registry: ToolRegistry
) -> None:
    d = Dispatcher(authorizer=empty_authz, cache=ResultCache(tmp_path / "cache"))
    with pytest.raises(UnauthorizedTargetError):
        await d.run_tool("remote", target="8.8.8.8", use_cache=False)


@pytest.mark.asyncio
async def test_dispatcher_allows_local_only_tool_without_whitelist(
    empty_authz: TargetAuthorizer, tmp_path: Path, stub_registry: ToolRegistry
) -> None:
    d = Dispatcher(authorizer=empty_authz, cache=ResultCache(tmp_path / "cache"))
    # No targets in whitelist, but local_only must still run
    result = await d.run_tool("local_only", target="Apache 2.4.49", use_cache=False)
    assert result.tool == "local_only"
    assert result.target == "Apache 2.4.49"
