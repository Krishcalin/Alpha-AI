"""Async subprocess runner with timeout, output capture, and structured logging."""

from __future__ import annotations

import asyncio
import shutil
import time
from pathlib import Path

import structlog

from alpha_ai.core.models import CommandResult

log = structlog.get_logger(__name__)


class ToolNotFoundError(RuntimeError):
    """Raised when a required binary is not on PATH."""


class CommandRunner:
    """Runs external security tools as subprocesses.

    Assumes a Linux runtime (Kali container) — all binaries on PATH.
    """

    def __init__(self, default_timeout: float = 300.0, cwd: Path | None = None) -> None:
        self.default_timeout = default_timeout
        self.cwd = cwd

    @staticmethod
    def which(binary: str) -> str:
        path = shutil.which(binary)
        if not path:
            raise ToolNotFoundError(f"Binary not found on PATH: {binary}")
        return path

    async def run(
        self,
        command: list[str],
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        """Execute *command* and return a CommandResult.

        Never raises on non-zero exit — caller inspects ``returncode``.
        Raises ToolNotFoundError if command[0] is missing.
        """
        if not command:
            raise ValueError("command must not be empty")

        # Validate the binary exists up-front (clearer error than asyncio's)
        self.which(command[0])

        timeout = timeout or self.default_timeout
        log.info("runner.exec", cmd=command, timeout=timeout)

        start = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=str(self.cwd) if self.cwd else None,
        )

        timed_out = False
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            timed_out = True
            proc.kill()
            stdout_b, stderr_b = await proc.communicate()
            log.warning("runner.timeout", cmd=command, timeout=timeout)

        duration = time.monotonic() - start
        result = CommandResult(
            command=command,
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout_b.decode(errors="replace"),
            stderr=stderr_b.decode(errors="replace"),
            duration_sec=round(duration, 3),
            timed_out=timed_out,
        )
        log.info(
            "runner.done",
            cmd=command[0],
            rc=result.returncode,
            duration=result.duration_sec,
            timed_out=timed_out,
        )
        return result
