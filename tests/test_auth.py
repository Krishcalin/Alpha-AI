"""Authorization whitelist tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from alpha_ai.core.auth import TargetAuthorizer, UnauthorizedTargetError


@pytest.fixture
def auth(tmp_path: Path) -> TargetAuthorizer:
    cfg = tmp_path / "targets.yaml"
    cfg.write_text(
        "authorized_targets:\n"
        "  - 127.0.0.1\n"
        "  - localhost\n"
        "  - 10.0.0.0/24\n"
        "  - '*.lab.internal'\n"
    )
    return TargetAuthorizer(cfg)


def test_literal_authorized(auth: TargetAuthorizer) -> None:
    assert auth.is_authorized("127.0.0.1")
    assert auth.is_authorized("localhost")


def test_cidr_authorized(auth: TargetAuthorizer) -> None:
    assert auth.is_authorized("10.0.0.5")
    assert not auth.is_authorized("10.0.1.5")


def test_glob_authorized(auth: TargetAuthorizer) -> None:
    assert auth.is_authorized("box1.lab.internal")
    assert not auth.is_authorized("evil.example.com")


def test_require_raises(auth: TargetAuthorizer) -> None:
    with pytest.raises(UnauthorizedTargetError):
        auth.require("8.8.8.8")
