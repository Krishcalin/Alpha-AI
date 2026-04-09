"""Disk-backed result cache keyed by (tool, args) hash."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from alpha_ai.core.models import ToolResult


class ResultCache:
    """Simple JSON file cache. Avoids re-running expensive scans during a session."""

    def __init__(self, cache_dir: Path | str = "cache") -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _key(tool: str, target: str, args: dict) -> str:
        payload = json.dumps({"tool": tool, "target": target, "args": args}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:32]

    def _path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def get(self, tool: str, target: str, args: dict) -> ToolResult | None:
        path = self._path(self._key(tool, target, args))
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            result = ToolResult.model_validate(data)
            result.cached = True
            return result
        except (json.JSONDecodeError, ValueError):
            return None

    def put(self, result: ToolResult) -> None:
        key = self._key(result.tool, result.target, result.args)
        self._path(key).write_text(result.model_dump_json(indent=2))
