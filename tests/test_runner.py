"""CommandRunner sanity tests — uses a guaranteed-present binary."""

from __future__ import annotations

import shutil
import sys

import pytest

from alpha_ai.core.runner import CommandRunner, ToolNotFoundError


@pytest.mark.asyncio
async def test_run_python_version() -> None:
    runner = CommandRunner(default_timeout=10)
    result = await runner.run([sys.executable, "-c", "print('alpha-ai')"])
    assert result.returncode == 0
    assert "alpha-ai" in result.stdout
    assert not result.timed_out


@pytest.mark.asyncio
async def test_run_unknown_binary_raises() -> None:
    runner = CommandRunner()
    with pytest.raises(ToolNotFoundError):
        await runner.run(["definitely-not-a-real-binary-xyz123"])


@pytest.mark.asyncio
async def test_run_timeout() -> None:
    sleeper = shutil.which("sleep")
    if not sleeper:
        pytest.skip("sleep not available")
    runner = CommandRunner()
    result = await runner.run([sleeper, "5"], timeout=0.5)
    assert result.timed_out is True
