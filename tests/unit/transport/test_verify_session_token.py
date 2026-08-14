"""``verify_session_token`` is exercised, not just exported (AUDIT.md:989).

The dependency is public (it is in ``nautilus.transport.auth.__all__``) and
documented, but no route registers it and its body had 0% coverage:
replacing ``return service.verify(token_value)`` with ``return None`` left
the whole suite green. A downstream integrator who wires it themselves
inherits a path no test in this repo covers.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from starlette.requests import Request

from nautilus.attestation.key_ring import KeyRing
from nautilus.attestation.session_token import SessionTokenService
from nautilus.transport.auth import verify_session_token

_HEADER = b"x-nautilus-session-token"
_INSTANCE = "broker-1"


def _request(app: FastAPI, token: str | None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if token is not None:
        headers.append((_HEADER, token.encode()))
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers, "app": app})


def _app(**state: Any) -> FastAPI:
    app = FastAPI()
    for key, value in state.items():
        setattr(app.state, key, value)
    return app


def _service(key_ring: KeyRing, ttl_seconds: int = 3600) -> SessionTokenService:
    return SessionTokenService(
        key_ring=key_ring, broker_instance_id=_INSTANCE, ttl_seconds=ttl_seconds
    )


def _token(service: SessionTokenService, **overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "session_id": "s1",
        "agent_id": "a1",
        "purpose": "threat-analysis",
        "clearance": "unclassified",
    }
    kwargs.update(overrides)
    return service.issue(**kwargs)


class TestKeyRingPath:
    """No broker on app.state — the dependency mints its own service."""

    @pytest.mark.asyncio
    async def test_a_valid_token_yields_its_claims(self) -> None:
        ring = KeyRing()
        token = _token(_service(ring))
        app = _app(key_ring=ring, broker_instance_id=_INSTANCE)

        claims = await verify_session_token(_request(app, token))
        assert claims is not None
        assert (claims.session_id, claims.agent_id) == ("s1", "a1")

    @pytest.mark.asyncio
    async def test_a_missing_header_is_not_an_error(self) -> None:
        app = _app(key_ring=KeyRing(), broker_instance_id=_INSTANCE)
        assert await verify_session_token(_request(app, None)) is None

    @pytest.mark.asyncio
    async def test_a_tampered_token_is_rejected(self) -> None:
        ring = KeyRing()
        token = _token(_service(ring))
        header, payload, signature = token.split(".")
        forged = f"{header}.{payload}.{signature[:-4]}AAAA"
        app = _app(key_ring=ring, broker_instance_id=_INSTANCE)

        with pytest.raises(HTTPException) as exc:
            await verify_session_token(_request(app, forged))
        assert exc.value.status_code == 401
        assert "bad_signature" in str(exc.value.detail)

    @pytest.mark.asyncio
    async def test_an_expired_token_is_rejected(self) -> None:
        ring = KeyRing()
        token = _token(_service(ring), expires_at=int(time.time()) - 60)
        app = _app(key_ring=ring, broker_instance_id=_INSTANCE)

        with pytest.raises(HTTPException) as exc:
            await verify_session_token(_request(app, token))
        assert exc.value.status_code == 401
        assert "expired" in str(exc.value.detail)

    @pytest.mark.asyncio
    async def test_a_token_from_another_broker_is_rejected(self) -> None:
        ring = KeyRing()
        other = SessionTokenService(key_ring=ring, broker_instance_id="broker-2")
        app = _app(key_ring=ring, broker_instance_id=_INSTANCE)

        with pytest.raises(HTTPException) as exc:
            await verify_session_token(_request(app, _token(other)))
        assert exc.value.status_code == 401
        assert "broker_instance_mismatch" in str(exc.value.detail)

    @pytest.mark.asyncio
    async def test_without_a_key_ring_the_dependency_is_a_no_op(self) -> None:
        # Documented behaviour: state-less apps keep working.
        app = _app()
        assert await verify_session_token(_request(app, "anything")) is None


class TestBrokerPath:
    """A real broker service on app.state is preferred, so failures audit."""

    @pytest.mark.asyncio
    async def test_the_brokers_verifier_is_used_when_present(self) -> None:
        ring = KeyRing()
        service = _service(ring)
        token = _token(service)
        seen: list[str] = []

        def _verify(value: str) -> Any:
            seen.append(value)
            return service.verify(value)

        broker = SimpleNamespace(session_tokens=service, verify_session_token=_verify)
        app = _app(broker=broker, key_ring=ring, broker_instance_id=_INSTANCE)

        claims = await verify_session_token(_request(app, token))
        assert seen == [token]
        assert claims is not None and claims.session_id == "s1"

    @pytest.mark.asyncio
    async def test_a_broker_rejection_becomes_a_401(self) -> None:
        ring = KeyRing()
        service = _service(ring)
        broker = SimpleNamespace(
            session_tokens=service,
            verify_session_token=service.verify,
        )
        app = _app(broker=broker, key_ring=ring, broker_instance_id=_INSTANCE)

        with pytest.raises(HTTPException) as exc:
            await verify_session_token(_request(app, "not-a-jwt"))
        assert exc.value.status_code == 401
