"""Integration coverage for #18 session-provenance tokens.

Issue #18 acceptance: "Integration test in ``tests/integration/`` covering:
issuance, valid presentation, tampered token, expired token, cross-agent
handoff." Exercises the full broker pipeline (from_config → arequest →
audit JSONL) with in-process fake adapters standing in for live sources.
"""

from __future__ import annotations

import json
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


def _build_broker(tmp_path: Path, *, ttl_seconds: int = 3600) -> Broker:
    src = FIXTURE_PATH.read_text(encoding="utf-8")
    src = src.replace("./audit.jsonl", str(tmp_path / "audit.jsonl").replace("\\", "/"))
    src += f"\nsession_tokens:\n  enabled: true\n  ttl_seconds: {ttl_seconds}\n"
    src += (
        "\nagents:\n"
        "  agent-a:\n    id: agent-a\n    clearance: secret\n"
        "  agent-b:\n    id: agent-b\n    clearance: secret\n"
    )
    cfg = tmp_path / "nautilus.yaml"
    cfg.write_text(src, encoding="utf-8")
    broker = Broker.from_config(cfg)
    fakes = {sid: _FakeAdapter(sid) for sid in ("nvd_db", "internal_vulns")}
    broker._adapters = dict(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = set(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    return broker


def _ctx(session_id: str = "sess-1") -> dict[str, Any]:
    return {
        "clearance": "secret",
        "purpose": "threat-analysis",
        "session_id": session_id,
        "embedding": [0.1, 0.2, 0.3],
    }


def _events(tmp_path: Path) -> list[dict[str, Any]]:
    """Unwrap Nautilus entries from the fathom AuditRecord envelope."""
    from nautilus.audit.logger import NAUTILUS_METADATA_KEY

    audit = tmp_path / "audit.jsonl"
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


async def test_full_token_lifecycle(tmp_path: Path) -> None:
    """Issuance → valid presentation → tampered rejection, one broker."""
    broker = _build_broker(tmp_path)
    try:
        # 1. Issuance — first request returns a signed token + audit event.
        first = await broker.arequest("agent-a", "show vulnerabilities", _ctx())
        token = first.session_token
        assert token is not None
        assert token.count(".") == 2  # compact JWS
        assert any(e.get("event_type") == "session_token_issued" for e in _events(tmp_path))

        # 2. Valid presentation — token accepted, session pinned, no re-mint.
        ctx2 = _ctx("attacker-fresh-session")
        ctx2["session_token"] = token
        second = await broker.arequest("agent-a", "show vulnerabilities", ctx2)
        assert second.session_token == token
        request_events = [e for e in _events(tmp_path) if e.get("event_type") == "request"]
        assert request_events[-1]["session_id"] == "sess-1"

        # 3. Tampered token — fail closed with audited reason.
        header, payload, sig = token.split(".")
        ctx3 = _ctx()
        ctx3["session_token"] = f"{header}.{payload}.{'A' * len(sig)}"
        with pytest.raises(SessionTokenError) as excinfo:
            await broker.arequest("agent-a", "show vulnerabilities", ctx3)
        assert excinfo.value.reason_code == "bad_signature"
        failed = [
            e
            for e in _events(tmp_path)
            if e.get("event_type") == "session_token_verification_failed"
        ]
        assert failed and failed[-1]["error_records"][0]["error_type"] == "bad_signature"
    finally:
        await broker.aclose()


async def test_expired_token_rejected(tmp_path: Path) -> None:
    broker = _build_broker(tmp_path, ttl_seconds=-1)
    try:
        first = await broker.arequest("agent-a", "show vulnerabilities", _ctx())
        assert first.session_token is not None
        ctx2 = _ctx()
        ctx2["session_token"] = first.session_token
        with pytest.raises(SessionTokenError) as excinfo:
            await broker.arequest("agent-a", "show vulnerabilities", ctx2)
        assert excinfo.value.reason_code == "expired"
    finally:
        await broker.aclose()


async def test_cross_agent_handoff_with_token(tmp_path: Path) -> None:
    """agent-a's token authorizes the handoff; agent-b's does not."""
    broker = _build_broker(tmp_path)
    try:
        first = await broker.arequest("agent-a", "show vulnerabilities", _ctx())
        token_a = first.session_token
        assert token_a is not None

        allowed = await broker.declare_handoff(
            source_agent_id="agent-a",
            receiving_agent_id="agent-b",
            session_id="sess-1",
            data_classifications=["unclassified"],
            session_token=token_a,
        )
        assert allowed.action == "allow"
        assert any(t.startswith("session-token:verified") for t in allowed.rule_trace)

        # agent-b presenting agent-a's token as its own source token → deny.
        denied = await broker.declare_handoff(
            source_agent_id="agent-b",
            receiving_agent_id="agent-a",
            session_id="sess-1",
            data_classifications=["unclassified"],
            session_token=token_a,
        )
        assert denied.action == "deny"
        assert denied.denial_records[0].rule_name == "session-token-agent-mismatch"

        # Missing token → deny.
        missing = await broker.declare_handoff(
            source_agent_id="agent-a",
            receiving_agent_id="agent-b",
            session_id="sess-1",
            data_classifications=["unclassified"],
        )
        assert missing.action == "deny"
        assert missing.denial_records[0].rule_name == "session-token-required"
    finally:
        await broker.aclose()
