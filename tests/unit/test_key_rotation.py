"""Unit coverage for #25 — live signing-key rotation + lazy token re-sign.

Three layers:

- **Broker**: ``rotate_signing_key`` / ``revoke_signing_key`` mutate the
  shared ring, emit ``signing_key_rotated`` / ``signing_key_revoked``
  audit entries with reviewer + kid linkage, and raise ``RuntimeError``
  when session tokens are disabled. After rotation, a request presenting
  an old-kid token is lazily re-signed under the new primary (grace
  window); revoking the old kid ends the window — its tokens stop
  verifying immediately.
- **Transport**: auth-gated ``POST /v1/keys/rotate`` and
  ``POST /v1/keys/{kid}/revoke`` drive the broker methods; 400 on missing
  reviewer/reason, 404 unknown kid, 409 when tokens are disabled.
- **CLI**: ``key rotate --url`` / ``key revoke --url`` POST to the live
  endpoints (MockTransport-injected); network failure exits 2.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from nautilus import Broker
from nautilus.attestation.session_token import SessionTokenError
from nautilus.cli import key as cli_key
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint
from nautilus.transport.fastapi_app import create_app

pytestmark = pytest.mark.unit

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nautilus.yaml"


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


# ---------------------------------------------------------------------------
# Broker-level helpers (mirrors tests/unit/test_session_token_plumbing.py)
# ---------------------------------------------------------------------------


class _FakeAdapter:
    source_type: str = "fake"

    def __init__(self, source_id: str) -> None:
        self._source_id = source_id

    async def connect(self, config: SourceConfig) -> None:
        del config

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        return AdapterResult(source_id=self._source_id, rows=[{"id": 1}], duration_ms=0)

    async def close(self) -> None:
        pass

    async def get_schema(self) -> Any:
        from nautilus.adapters.schema import AdapterSchema

        return AdapterSchema.unknown(self._source_id, self.source_type)


def _build_broker(tmp_path: Path, *, tokens_enabled: bool = True) -> Broker:
    src = FIXTURE_PATH.read_text(encoding="utf-8")
    src = src.replace("./audit.jsonl", str(tmp_path / "audit.jsonl").replace("\\", "/"))
    if tokens_enabled:
        src += "\nsession_tokens:\n  enabled: true\n"
    cfg = tmp_path / "nautilus.yaml"
    cfg.write_text(src, encoding="utf-8")
    broker = Broker.from_config(cfg)
    fakes = {sid: _FakeAdapter(sid) for sid in ("nvd_db", "internal_vulns")}
    broker._adapters = dict(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = set(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    return broker


def _ctx() -> dict[str, Any]:
    return {
        "clearance": "unclassified",
        "purpose": "threat-analysis",
        "session_id": "s1",
        "embedding": [0.1, 0.2, 0.3],
    }


def _audit_events(tmp_path: Path) -> list[dict[str, Any]]:
    from nautilus.audit.logger import NAUTILUS_METADATA_KEY

    audit = tmp_path / "audit.jsonl"
    if not audit.exists():
        return []
    entries: list[dict[str, Any]] = []
    for line in audit.read_text().splitlines():
        if not line.strip():
            continue
        record: dict[str, Any] = json.loads(line)
        metadata: dict[str, Any] = record.get("metadata") or {}
        raw = metadata.get(NAUTILUS_METADATA_KEY)
        if isinstance(raw, str):
            entries.append(json.loads(raw))
    return entries


# ---------------------------------------------------------------------------
# Broker: rotate / revoke
# ---------------------------------------------------------------------------


def test_rotate_and_revoke_raise_when_tokens_disabled(tmp_path: Path) -> None:
    broker = _build_broker(tmp_path, tokens_enabled=False)
    try:
        with pytest.raises(RuntimeError, match="disabled"):
            broker.rotate_signing_key(reviewer="alice@example.com")
        with pytest.raises(RuntimeError, match="disabled"):
            broker.revoke_signing_key("kid-x", reason="r", reviewer="alice@example.com")
    finally:
        broker.close()


def test_rotate_mints_new_primary_and_audits(tmp_path: Path) -> None:
    broker = _build_broker(tmp_path)
    try:
        ring = broker.key_ring
        assert ring is not None
        old_kid = ring.primary().kid
        new_kid = broker.rotate_signing_key(reviewer="alice@example.com")
        assert new_kid != old_kid
        assert ring.primary().kid == new_kid
        old_entry = ring.verifier_for(old_kid)
        assert old_entry is not None and old_entry.status == "rotating-out"

        rotated = [
            e for e in _audit_events(tmp_path) if e.get("event_type") == "signing_key_rotated"
        ]
        assert len(rotated) == 1
        trace = rotated[0]["rule_trace"]
        assert f"previous_kid={old_kid}" in trace
        assert f"new_kid={new_kid}" in trace
        assert "reviewer=alice@example.com" in trace
    finally:
        broker.close()


def test_revoke_unknown_kid_raises_keyerror(tmp_path: Path) -> None:
    broker = _build_broker(tmp_path)
    try:
        with pytest.raises(KeyError):
            broker.revoke_signing_key("nope", reason="r", reviewer="alice@example.com")
    finally:
        broker.close()


def test_revoke_current_primary_refused(tmp_path: Path) -> None:
    """Revoking the primary would auto-generate an unaudited ghost key (C1)."""
    broker = _build_broker(tmp_path)
    try:
        ring = broker.key_ring
        assert ring is not None
        with pytest.raises(ValueError, match="rotate first"):
            broker.revoke_signing_key(ring.primary().kid, reason="r", reviewer="alice@example.com")
    finally:
        broker.close()


def test_revoked_key_drops_private_material(tmp_path: Path) -> None:
    """KeyEntry contract: revoked keys must not retain signing material."""
    broker = _build_broker(tmp_path)
    try:
        ring = broker.key_ring
        assert ring is not None
        old_kid = ring.primary().kid
        broker.rotate_signing_key(reviewer="alice@example.com")
        broker.revoke_signing_key(old_kid, reason="r", reviewer="alice@example.com")
        entry = ring.verifier_for(old_kid)
        assert entry is not None
        assert entry.status == "revoked"
        assert entry.private_key_pem is None
    finally:
        broker.close()


def test_revoke_audits_with_reason(tmp_path: Path) -> None:
    broker = _build_broker(tmp_path)
    try:
        old_kid = broker.rotate_signing_key(reviewer="alice@example.com")
        # Rotate again so old_kid is no longer primary, then revoke it.
        broker.rotate_signing_key(reviewer="alice@example.com")
        broker.revoke_signing_key(old_kid, reason="compromise", reviewer="alice@example.com")
        revoked = [
            e for e in _audit_events(tmp_path) if e.get("event_type") == "signing_key_revoked"
        ]
        assert len(revoked) == 1
        trace = revoked[0]["rule_trace"]
        assert f"kid={old_kid}" in trace
        assert "reason=compromise" in trace
    finally:
        broker.close()


# ---------------------------------------------------------------------------
# Broker: lazy re-sign (grace window) + revocation ends grace
# ---------------------------------------------------------------------------


def test_lazy_resign_after_rotation(tmp_path: Path) -> None:
    broker = _build_broker(tmp_path)
    try:
        first = broker.request("agent-1", "show vulnerabilities", _ctx())
        old_token = first.session_token
        assert old_token is not None

        new_kid = broker.rotate_signing_key(reviewer="alice@example.com")

        # Grace window: old token verifies AND the response carries a fresh
        # primary-signed token with the same session claims.
        ctx2 = _ctx()
        ctx2["session_token"] = old_token
        second = broker.request("agent-1", "show vulnerabilities", ctx2)
        assert second.session_token is not None
        assert second.session_token != old_token
        claims = broker.verify_session_token(second.session_token)
        assert claims.kid == new_kid
        assert claims.session_id == "s1"

        # Re-keying must NOT extend the session lifetime (C2): the
        # re-signed token carries the ORIGINAL expiry.
        import jwt as pyjwt

        refreshed_exp = broker.verify_session_token(second.session_token).expires_at
        original_exp = pyjwt.decode(old_token, options={"verify_signature": False})["expires_at"]
        assert refreshed_exp == original_exp

        # Presenting the refreshed token does NOT re-issue again.
        ctx3 = _ctx()
        ctx3["session_token"] = second.session_token
        third = broker.request("agent-1", "show vulnerabilities", ctx3)
        assert third.session_token == second.session_token

        resigned = [
            e
            for e in _audit_events(tmp_path)
            if e.get("event_type") == "session_token_issued"
            and any(t.startswith("resigned-from-kid=") for t in e.get("rule_trace", []))
        ]
        assert len(resigned) == 1
    finally:
        broker.close()


def test_revocation_ends_grace_window(tmp_path: Path) -> None:
    broker = _build_broker(tmp_path)
    try:
        ring = broker.key_ring
        assert ring is not None
        old_kid = ring.primary().kid
        first = broker.request("agent-1", "show vulnerabilities", _ctx())
        old_token = first.session_token
        assert old_token is not None

        broker.rotate_signing_key(reviewer="alice@example.com")
        broker.revoke_signing_key(old_kid, reason="post-grace", reviewer="alice@example.com")

        ctx2 = _ctx()
        ctx2["session_token"] = old_token
        with pytest.raises(SessionTokenError) as excinfo:
            broker.request("agent-1", "show vulnerabilities", ctx2)
        assert excinfo.value.reason_code == "unknown_kid"
    finally:
        broker.close()


# ---------------------------------------------------------------------------
# Transport: POST /v1/keys/rotate + /v1/keys/{kid}/revoke
# ---------------------------------------------------------------------------


def _mock_broker() -> MagicMock:
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()
    broker._config = SimpleNamespace(
        api=SimpleNamespace(auth=SimpleNamespace(mode="api_key"), keys=["topsecret"]),
    )
    broker.rotate_signing_key = MagicMock(return_value="kid-new")
    broker.revoke_signing_key = MagicMock(return_value=None)
    return broker


async def test_rotate_endpoint_requires_auth() -> None:
    app = create_app(None, existing_broker=_mock_broker())
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/v1/keys/rotate", json={"reviewer": "alice"})
            assert response.status_code in (401, 403)


async def test_rotate_endpoint_rotates_via_broker() -> None:
    broker = _mock_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/v1/keys/rotate",
                json={"reviewer": "alice"},
                headers={"X-API-Key": "topsecret"},
            )
            assert response.status_code == 200
            assert response.json()["new_primary_kid"] == "kid-new"
            broker.rotate_signing_key.assert_called_once_with(reviewer="alice")

            missing = await client.post(
                "/v1/keys/rotate", json={}, headers={"X-API-Key": "topsecret"}
            )
            assert missing.status_code == 400


async def test_rotate_endpoint_409_when_disabled() -> None:
    broker = _mock_broker()
    broker.rotate_signing_key.side_effect = RuntimeError("session tokens are disabled")
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/v1/keys/rotate",
                json={"reviewer": "alice"},
                headers={"X-API-Key": "topsecret"},
            )
            assert response.status_code == 409


async def test_revoke_endpoint_paths() -> None:
    kid_ok = "11111111-2222-4333-8444-555555555555"
    kid_missing = "99999999-2222-4333-8444-555555555555"
    broker = _mock_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {"X-API-Key": "topsecret"}
            response = await client.post(
                f"/v1/keys/{kid_ok}/revoke",
                json={"reviewer": "alice", "reason": "compromise"},
                headers=headers,
            )
            assert response.status_code == 200
            broker.revoke_signing_key.assert_called_once_with(
                kid_ok, reason="compromise", reviewer="alice"
            )

            missing = await client.post(f"/v1/keys/{kid_ok}/revoke", json={}, headers=headers)
            assert missing.status_code == 400

            # Non-UUID kid rejected before reaching the broker (I1).
            bad_kid = await client.post(
                "/v1/keys/kid%0Ainjected/revoke",
                json={"reviewer": "alice", "reason": "r"},
                headers=headers,
            )
            assert bad_kid.status_code == 400

            # Control characters in reviewer rejected (I1).
            bad_reviewer = await client.post(
                f"/v1/keys/{kid_ok}/revoke",
                json={"reviewer": "alice\nbob", "reason": "r"},
                headers=headers,
            )
            assert bad_reviewer.status_code == 400

            # Revoking the current primary → broker raises ValueError → 409.
            broker.revoke_signing_key.side_effect = ValueError("is the current primary")
            primary_revoke = await client.post(
                f"/v1/keys/{kid_ok}/revoke",
                json={"reviewer": "alice", "reason": "r"},
                headers=headers,
            )
            assert primary_revoke.status_code == 409

            broker.revoke_signing_key.side_effect = KeyError("kid-404")
            not_found = await client.post(
                f"/v1/keys/{kid_missing}/revoke",
                json={"reviewer": "alice", "reason": "r"},
                headers=headers,
            )
            assert not_found.status_code == 404


# ---------------------------------------------------------------------------
# CLI: --url live mode
# ---------------------------------------------------------------------------


def _rotate_args(**overrides: Any) -> argparse.Namespace:
    base: dict[str, Any] = {
        "cmd": "key",
        "key_subcommand": "rotate",
        "remove_old": False,
        "yes": True,
        "json": False,
        "url": "http://broker.example",
        "api_key": "topsecret",
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_cli_rotate_url_posts_to_live_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice@example.com")
    captured: dict[str, Any] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["api_key"] = request.headers.get("X-API-Key")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"new_primary_kid": "kid-new", "reviewer": "alice"})

    rc = cli_key._cmd_rotate(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        _rotate_args(), transport=httpx.MockTransport(_handler)
    )
    assert rc == 0
    assert captured["path"] == "/v1/keys/rotate"
    assert captured["api_key"] == "topsecret"
    assert captured["body"] == {"reviewer": "alice@example.com"}


def test_cli_rotate_url_network_failure_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice@example.com")

    def _handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    rc = cli_key._cmd_rotate(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        _rotate_args(), transport=httpx.MockTransport(_handler)
    )
    assert rc == 2


def test_cli_rotate_url_server_error_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice@example.com")

    def _handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(409, json={"detail": "session tokens are disabled"})

    rc = cli_key._cmd_rotate(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        _rotate_args(), transport=httpx.MockTransport(_handler)
    )
    assert rc == 2


def test_cli_revoke_url_posts_to_live_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice@example.com")
    captured: dict[str, Any] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"revoked_kid": "kid-1", "reviewer": "alice", "reason": "r"}
        )

    args = argparse.Namespace(
        cmd="key",
        key_subcommand="revoke",
        kid="kid-1",
        reason="compromise",
        yes=True,
        json=False,
        url="http://broker.example",
        api_key="topsecret",
    )
    rc = cli_key._cmd_revoke(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        args, transport=httpx.MockTransport(_handler)
    )
    assert rc == 0
    assert captured["path"] == "/v1/keys/kid-1/revoke"
    assert captured["body"] == {"reviewer": "alice@example.com", "reason": "compromise"}


def test_cli_rotate_local_mode_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """No --url → existing local in-memory ring behaviour (back-compat)."""
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice@example.com")
    rc = cli_key._cmd_rotate(_rotate_args(url=None, api_key=None))  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert rc == 0
