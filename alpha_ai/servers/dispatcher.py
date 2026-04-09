"""Shared dispatch logic used by both the MCP server and REST API.

Centralizes: authorization, cache lookup, tool invocation, cache write.
"""

from __future__ import annotations

from alpha_ai.core.auth import TargetAuthorizer
from alpha_ai.core.cache import ResultCache
from alpha_ai.core.models import ToolResult
from alpha_ai.core.registry import registry


class Dispatcher:
    def __init__(
        self,
        authorizer: TargetAuthorizer | None = None,
        cache: ResultCache | None = None,
    ) -> None:
        self.authorizer = authorizer or TargetAuthorizer()
        self.cache = cache or ResultCache()

    async def run_tool(
        self,
        tool_name: str,
        target: str,
        use_cache: bool = True,
        **kwargs,
    ) -> ToolResult:
        spec = registry.get(tool_name)
        if spec.requires_authorization:
            self.authorizer.require(target)

        args = dict(kwargs)
        if use_cache:
            cached = self.cache.get(tool_name, target, args)
            if cached is not None:
                return cached

        result = await spec.fn(target=target, **kwargs)
        self.cache.put(result)
        return result
