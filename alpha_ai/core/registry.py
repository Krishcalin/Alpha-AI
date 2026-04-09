"""Tool registry — single source of truth for MCP and REST exposures.

Each registered tool is a callable that accepts a target + kwargs and returns
a ToolResult. The registry exposes metadata (name, category, description,
parameter schema) so the MCP server and REST API can both build their
endpoints from it without duplication.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable

from alpha_ai.core.models import ToolCategory, ToolResult

ToolFn = Callable[..., Awaitable[ToolResult]]


@dataclass
class ToolSpec:
    name: str
    category: ToolCategory
    description: str
    fn: ToolFn
    parameters: dict = field(default_factory=dict)
    requires_root: bool = False
    requires_authorization: bool = True  # set False for local-only tools (e.g. searchsploit)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool already registered: {spec.name}")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        return self._tools[name]

    def all(self) -> list[ToolSpec]:
        return list(self._tools.values())

    def by_category(self, category: ToolCategory) -> list[ToolSpec]:
        return [t for t in self._tools.values() if t.category == category]


# Global registry instance — tool modules import this and call register()
registry = ToolRegistry()


def load_builtin_tools() -> None:
    """Import all built-in tool modules so they self-register."""
    from alpha_ai.tools.recon import nmap as _nmap  # noqa: F401
    from alpha_ai.tools.web import nuclei as _nuclei  # noqa: F401
    from alpha_ai.tools.web import gobuster as _gobuster  # noqa: F401
    from alpha_ai.tools.web import ffuf as _ffuf  # noqa: F401
    from alpha_ai.tools.web import sqlmap as _sqlmap  # noqa: F401
    from alpha_ai.tools.network import enum4linux as _enum4linux  # noqa: F401
    from alpha_ai.tools.network import crackmapexec as _crackmapexec  # noqa: F401
    from alpha_ai.tools.cred import hydra as _hydra  # noqa: F401
    from alpha_ai.tools.exploit import searchsploit as _searchsploit  # noqa: F401
