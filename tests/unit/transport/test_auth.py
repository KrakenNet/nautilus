"""Unit tests for :mod:`nautilus.transport.auth` — Task 3.11.

Covers FR-26, AC-12.2, AC-12.3:
    (a) ``verify_api_key("good", ["good","other"])`` passes.
    (b) ``verify_api_key("bad", ["good"])`` raises HTTP 401.
    (c) ``secrets.compare_digest`` is used (patched + asserted called).
    (d) ``proxy_trust`` mode reads ``X-Forwarded-User`` header value as identity.
    (e) Both modes return the resolved identity string.
"""

from __future__ import annotations

import secrets as _real_secrets
from typing import Any

import pytest
from fastapi import HTTPException

from nautilus.transport import auth as auth_mod
from nautilus.transport.auth import (
    proxy_trust_dependency,
    require_api_key,
    verify_api_key,
)

pytestmark = pytest.mark.unit


class _StateCarrier:
    """Minimal ``app``-like object exposing a ``state.api_keys`` attribute."""

    def __init__(self, *, api_keys: list[str]) -> None:
        self.state = type("State", (), {"api_keys": api_keys})()


def _build_request(headers: list[tuple[bytes, bytes]], app: Any = None) -> Any:
    """Construct a minimal Starlette Request with the given headers / app."""
    from starlette.requests import Request as StarletteRequest

    scope: Any = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": headers,
    }
    if app is not None:
        scope["app"] = app
    return StarletteRequest(scope)


# --- (a) verify_api_key accepts a matching key in a multi-key allow-list ------


def test_a_verify_api_key_good_against_multi_key_list_passes() -> None:
    """``verify_api_key("good", ["good","other"])`` returns without raising."""
    # Must not raise; returns None by contract.
    result = verify_api_key("good", ["good", "other"])
    assert result is None


# --- (b) verify_api_key rejects mismatched key with HTTP 401 ------------------


def test_b_verify_api_key_bad_raises_http_401() -> None:
    """``verify_api_key("bad", ["good"])`` raises HTTPException(401)."""
    with pytest.raises(HTTPException) as exc:
        verify_api_key("bad", ["good"])
    assert exc.value.status_code == 401


# --- (c) secrets.compare_digest is used (patch + assert call) -----------------


def test_c_verify_api_key_uses_secrets_compare_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pins the constant-time-compare invariant (D-11).

    We install a spy that wraps the real :func:`secrets.compare_digest`
    on the ``auth`` module's imported ``secrets`` reference, then confirm
    the spy is invoked for each allow-list entry we scan.
    """
    calls: list[tuple[bytes, bytes]] = []
    # Capture the original BEFORE patching — ``auth_mod.secrets`` is the
    # same module object as the test-level ``_real_secrets``, so patching
    # one replaces ``compare_digest`` for both references and would cause
    # the spy to recurse into itself.
    original_compare_digest = _real_secrets.compare_digest

    def _spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return original_compare_digest(a, b)

    monkeypatch.setattr(auth_mod.secrets, "compare_digest", _spy)

    # A matching call: compare_digest should be invoked at least once.
    verify_api_key("good", ["good", "other"])
    assert len(calls) >= 1, "compare_digest must be called for a match check"
    # Arguments are the utf-8 encoded header and the utf-8 encoded key.
    assert calls[0] == (b"good", b"good")

    # A non-matching call across both keys: compare_digest must be invoked
    # for every key before we fail closed (constant-time per-entry scan).
    calls.clear()
    with pytest.raises(HTTPException):
        verify_api_key("zzz", ["good", "other"])
    assert len(calls) == 2, "compare_digest must be called once per allow-list entry"


# --- (d) proxy_trust reads X-Forwarded-User as the identity -------------------


async def test_d_proxy_trust_reads_x_forwarded_user_as_identity() -> None:
    """``proxy_trust_dependency`` returns the header value verbatim."""
    req = _build_request([(b"x-forwarded-user", b"alice")])
    identity = await proxy_trust_dependency(req)
    assert identity == "alice"


# --- (e) both modes return the resolved identity string -----------------------


@pytest.mark.parametrize(
    ("mode", "identity"),
    [
        ("api_key", "s3cret"),
        ("proxy_trust", "bob"),
    ],
)
async def test_e_both_modes_return_resolved_identity_string(
    mode: str,
    identity: str,
) -> None:
    """Both ``api_key`` and ``proxy_trust`` paths return a string identity."""
    if mode == "api_key":
        req = _build_request(headers=[], app=_StateCarrier(api_keys=[identity]))
        resolved = await require_api_key(req, header_value=identity)
    else:
        req = _build_request(headers=[(b"x-forwarded-user", identity.encode("utf-8"))])
        resolved = await proxy_trust_dependency(req)
    assert isinstance(resolved, str)
    assert resolved == identity
