"""Target authorization — refuse to run tools against non-whitelisted targets."""

from __future__ import annotations

import fnmatch
import ipaddress
from pathlib import Path

import structlog
import yaml

log = structlog.get_logger(__name__)


class UnauthorizedTargetError(PermissionError):
    """Raised when a tool is asked to run against a non-whitelisted target."""


class TargetAuthorizer:
    """Loads an allowlist from YAML and checks targets against it.

    Supports literal hosts, CIDR ranges, and glob patterns.
    """

    def __init__(self, config_path: Path | str = "config/targets.yaml") -> None:
        self.config_path = Path(config_path)
        self.literals: set[str] = set()
        self.networks: list[ipaddress._BaseNetwork] = []
        self.globs: list[str] = []
        self._load()

    def _load(self) -> None:
        if not self.config_path.exists():
            log.warning("auth.no_config", path=str(self.config_path))
            return
        data = yaml.safe_load(self.config_path.read_text()) or {}
        for entry in data.get("authorized_targets", []):
            entry = str(entry).strip()
            if not entry:
                continue
            if "*" in entry or "?" in entry:
                self.globs.append(entry)
                continue
            try:
                self.networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                self.literals.add(entry.lower())

    def is_authorized(self, target: str) -> bool:
        t = target.strip().lower()
        if t in self.literals:
            return True
        for pattern in self.globs:
            if fnmatch.fnmatch(t, pattern.lower()):
                return True
        try:
            ip = ipaddress.ip_address(t)
            for net in self.networks:
                if ip in net:
                    return True
        except ValueError:
            pass
        return False

    def require(self, target: str) -> None:
        if not self.is_authorized(target):
            log.error("auth.denied", target=target)
            raise UnauthorizedTargetError(
                f"Target {target!r} is not in the authorized whitelist "
                f"({self.config_path}). Add it before running tools against it."
            )
