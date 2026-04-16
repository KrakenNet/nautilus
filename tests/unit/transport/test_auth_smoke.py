"""Smoke tests for :mod:`nautilus.transport.auth` (VERIFY 2.19 coverage gate).

Covers:
    * :func:`verify_api_key` happy / wrong / empty-keys / constant-time paths.
    * :func:`require_api_key` as a FastAPI dependency via TestClient.
    * :func:`proxy_trust_dependency` reading ``X-Forwarded-User``.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import HTTPException

from nautilus.transport.auth import (
    proxy_trust_dependency,
    require_api_key,
    verify_api_key,
)

pytestmark = pytest.mark.unit


class _StateCarrier:
    """Minimal object mimicking ``app`` with a ``state`` namespace."""

    def __init__(self, *, api_keys: list[str]) -> None:
        self.state = type("State", (), {"api_keys": api_keys})()


def test_verify_api_key_accepts_match() -> None:
    """Correct key returns cleanly (no exception)."""
    verify_api_key("secret", ["secret"])


def test_verify_api_key_rejects_wrong_key() -> None:
    """Wrong key → 401."""
    with pytest.raises(HTTPException) as exc:
        verify_api_key("nope", ["secret"])
    assert exc.value.status_code == 401


def test_verify_api_key_fail_closed_on_empty_keys() -> None:
    """Empty allow-list → 401 (never silently admit)."""
    with pytest.raises(HTTPException) as exc:
        verify_api_key("anything", [])
    assert exc.value.status_code == 401


def test_verify_api_key_rejects_empty_header_against_nonempty_list() -> None:
    """Empty header vs non-empty allow-list → 401."""
    with pytest.raises(HTTPException) as exc:
        verify_api_key("", ["secret"])
    assert exc.value.status_code == 401


def test_verify_api_key_matches_second_key_in_list() -> None:
    """Constant-time path iterates every key — the second entry still matches."""
    # Matches the second key; exercises the loop body on a non-first match.
    verify_api_key("second", ["first", "second", "third"])


async def test_require_api_key_rejects_missing_via_direct_call() -> None:
    """Direct call without header value raises 401 via verify_api_key."""
    from starlette.requests import Request as StarletteRequest

    scope: Any = {
        "type": "http",
        "headers": [],
        "method": "GET",
        "path": "/",
        "app": _StateCarrier(api_keys=["s3cret"]),
    }
    req = StarletteRequest(scope)
    with pytest.raises(HTTPException) as exc:
        await require_api_key(req, header_value="wrong")
    assert exc.value.status_code == 401


async def test_require_api_key_accepts_via_direct_call() -> None:
    from starlette.requests import Request as StarletteRequest

    scope: Any = {
        "type": "http",
        "headers": [],
        "method": "GET",
        "path": "/",
        "app": _StateCarrier(api_keys=["s3cret"]),
    }
    req = StarletteRequest(scope)
    principal = await require_api_key(req, header_value="s3cret")
    assert principal == "s3cret"


async def test_proxy_trust_dependency_reads_header() -> None:
    from starlette.requests import Request as StarletteRequest

    scope: Any = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-forwarded-user", b"alice")],
    }
    req = StarletteRequest(scope)
    user = await proxy_trust_dependency(req)
    assert user == "alice"


async def test_proxy_trust_dependency_rejects_missing_header() -> None:
    from starlette.requests import Request as StarletteRequest

    scope: Any = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
    }
    req = StarletteRequest(scope)
    with pytest.raises(HTTPException) as exc:
        await proxy_trust_dependency(req)
    assert exc.value.status_code == 401
