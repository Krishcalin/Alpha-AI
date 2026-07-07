"""Shared helper for POST-exploitation result-file ingestion.

linpeas / winpeas are run by the operator ON the compromised host; Alpha-AI only
ingests the captured output file. No subprocess runs, so we synthesize a
CommandResult (sentinel binary "<ingest>") to keep the ToolResult shape uniform.
On a missing/unreadable file we return a failed CommandResult rather than raising,
matching CommandRunner's never-raise-on-failure contract.
"""

from __future__ import annotations

from pathlib import Path

from alpha_ai.core.models import CommandResult

_MAX_STDOUT = 8000  # keep ToolResult light; PEASS output can be multiple MB


def read_result_file(tool: str, path: str) -> tuple[str, CommandResult]:
    """Read an uploaded PEASS output file.

    Returns (full_text, CommandResult). Parse against *full_text*; the
    CommandResult.stdout carries only a truncated preview.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as e:
        return "", CommandResult(
            command=["<ingest>", tool, path],
            returncode=1,
            stdout="",
            stderr=f"result file not readable: {e}",
            duration_sec=0.0,
        )

    if len(raw) > _MAX_STDOUT:
        preview = raw[:_MAX_STDOUT] + f"\n...[truncated {len(raw) - _MAX_STDOUT} chars]..."
    else:
        preview = raw

    return raw, CommandResult(
        command=["<ingest>", tool, path],
        returncode=0,
        stdout=preview,
        stderr="",
        duration_sec=0.0,
    )
