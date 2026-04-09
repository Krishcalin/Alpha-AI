"""Shared pydantic models for Alpha-AI tools, findings, and results."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolCategory(str, Enum):
    RECON = "recon"
    WEB = "web"
    NETWORK = "network"
    AD = "ad"
    CRED = "cred"
    EXPLOIT = "exploit"
    POST = "post"


class Target(BaseModel):
    """A scan target — host, IP, CIDR, or URL."""

    value: str
    kind: str = "auto"  # auto | host | ip | cidr | url

    def __str__(self) -> str:
        return self.value


class Finding(BaseModel):
    """A normalized finding produced by a tool parser."""

    tool: str
    target: str
    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CommandResult(BaseModel):
    """Raw output of a subprocess invocation."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_sec: float
    timed_out: bool = False


class ToolResult(BaseModel):
    """Structured output of a tool wrapper — raw command + parsed findings."""

    tool: str
    target: str
    args: dict[str, Any] = Field(default_factory=dict)
    command: CommandResult
    findings: list[Finding] = Field(default_factory=list)
    cached: bool = False
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def success(self) -> bool:
        return self.command.returncode == 0 and not self.command.timed_out
