"""Integration coverage for #25 — rotate mid-flight (issue acceptance).

"Integration test: rotate mid-flight, assert pre-rotation tokens still
verify during grace, post-grace fail." Grace ends by explicit revocation
of the rotated-out kid (the operator action exposed via
``POST /v1/keys/{kid}/revoke`` / ``nautilus key revoke --url``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from nautilus import Broker
from nautilus.attestation.session_token import SessionTokenError
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

pytestmark = pytest.mark.integration

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nautilus.yaml"


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


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


def _build_broker(tmp_path: Path) -> Broker:
    src = FIXTURE_PATH.read_text(encoding="utf-8")
    src = src.replace("./audit.jsonl", str(tmp_path / "audit.jsonl").replace("\\", "/"))
    src += "\nsession_tokens:\n  enabled: true\n"
    cfg = tmp_path / "nautilus.yaml"
    cfg.write_text(src, encoding="utf-8")
    broker = Broker.from_config(cfg)
    fakes = {sid: _FakeAdapter(sid) for sid in ("nvd_db", "internal_vulns")}
    broker._adapters = dict(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = set(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    return broker


def _ctx(token: str | None = None) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "clearance": "secret",
        "purpose": "threat-analysis",
        "session_id": "sess-rot",
        "embedding": [0.1, 0.2, 0.3],
    }
    if token is not None:
        ctx["session_token"] = token
    return ctx


async def test_rotate_mid_flight_grace_then_fail(tmp_path: Path) -> None:
    broker = _build_broker(tmp_path)
    try:
        ring = broker.key_ring
        assert ring is not None
        old_kid = ring.primary().kid

        # Mid-flight session: token minted under the old key.
        first = await broker.arequest("agent-1", "show vulnerabilities", _ctx())
        old_token = first.session_token
        assert old_token is not None

        # Operator rotates the LIVE ring.
        new_kid = broker.rotate_signing_key(reviewer="ops@example.com")
        assert new_kid != old_kid

        # Grace: pre-rotation token still verifies; response carries the
        # lazily re-signed replacement under the new primary.
        second = await broker.arequest("agent-1", "show vulnerabilities", _ctx(old_token))
        refreshed = second.session_token
        assert refreshed is not None and refreshed != old_token
        assert broker.verify_session_token(refreshed).kid == new_kid

        # Post-grace: operator revokes the old kid → pre-rotation token
        # fails closed, refreshed token keeps working.
        broker.revoke_signing_key(old_kid, reason="grace ended", reviewer="ops@example.com")
        with pytest.raises(SessionTokenError) as excinfo:
            await broker.arequest("agent-1", "show vulnerabilities", _ctx(old_token))
        assert excinfo.value.reason_code == "unknown_kid"

        third = await broker.arequest("agent-1", "show vulnerabilities", _ctx(refreshed))
        assert third.session_token == refreshed
    finally:
        await broker.aclose()
