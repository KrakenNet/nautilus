"""Unit coverage for #18 remainder — session-token plumbing + audit events.

Locks the broker-side token lifecycle (AC-18.a/b/d/f):

- Default OFF — stock fixture YAML (no ``session_tokens:`` section) leaves
  ``BrokerResponse.session_token`` ``None`` and emits zero token audit
  events (NFR-5).
- First request in a session mints a token: returned on the response,
  injected into the adapter ``context`` (AC-18.b), and audited as
  ``session_token_issued`` (AC-18.f).
- A presented valid token PINS the session — a caller declaring a fresh
  ``session_id`` while presenting an old token cannot reset its exposure
  ledger (issue #18 core property).
- Tampered / expired tokens fail closed: :class:`SessionTokenError` raised
  before the pipeline runs, ``session_token_verification_failed`` audited
  with the reason code (AC-18.d).
- ``declare_handoff`` requires the originating agent's token when tokens
  are enabled: missing / mismatched tokens deny; a valid token records a
  ``session-token:verified`` reference in the handoff rule trace.
- HTTP-family adapters forward the token as ``X-Nautilus-Session-Token``
  (:func:`session_token_headers`, exercised end-to-end via the REST
  adapter's MockTransport).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from nautilus import Broker
from nautilus.adapters.base import (
    SESSION_TOKEN_HEADER,
    session_token_headers,
)
from nautilus.adapters.rest import RestAdapter
from nautilus.attestation.session_token import SessionTokenError
from nautilus.config.models import EndpointSpec, NoneAuth, SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nautilus.yaml"


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dummy DSNs so config interpolation succeeds (fakes replace adapters)."""
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _write_yaml(
    tmp_path: Path,
    *,
    tokens_enabled: bool = True,
    ttl_seconds: int = 3600,
    with_agents: bool = False,
) -> Path:
    """Clone the fixture YAML with audit-path + session-token overrides."""
    src = FIXTURE_PATH.read_text(encoding="utf-8")
    audit_target = tmp_path / "audit.jsonl"
    src = src.replace("./audit.jsonl", str(audit_target).replace("\\", "/"))
    if tokens_enabled:
        src += f"\nsession_tokens:\n  enabled: true\n  ttl_seconds: {ttl_seconds}\n"
    if with_agents:
        src += (
            "\nagents:\n"
            "  agent-source:\n    id: agent-source\n    clearance: secret\n"
            "  agent-receiver:\n    id: agent-receiver\n    clearance: secret\n"
        )
    dst = tmp_path / "nautilus.yaml"
    dst.write_text(src, encoding="utf-8")
    return dst


class _CapturingAdapter:
    """Minimal Adapter impl that records the ``context`` it receives."""

    source_type: str = "fake"

    def __init__(self, source_id: str) -> None:
        self._source_id = source_id
        self.contexts: list[dict[str, Any]] = []

    async def connect(self, config: SourceConfig) -> None:
        del config

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope
        self.contexts.append(dict(context))
        return AdapterResult(source_id=self._source_id, rows=[{"id": 1}], duration_ms=0)

    async def close(self) -> None:
        pass

    async def get_schema(self) -> Any:
        from nautilus.adapters.schema import AdapterSchema

        return AdapterSchema.unknown(self._source_id, self.source_type)


def _install_fakes(broker: Broker) -> dict[str, _CapturingAdapter]:
    fakes = {sid: _CapturingAdapter(sid) for sid in ("nvd_db", "internal_vulns")}
    broker._adapters = dict(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = set(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    return fakes


def _ctx(session_id: str = "s1") -> dict[str, Any]:
    return {
        "clearance": "unclassified",
        "purpose": "threat-analysis",
        "session_id": session_id,
        "embedding": [0.1, 0.2, 0.3],
    }


def _audit_events(tmp_path: Path) -> list[dict[str, Any]]:
    """Unwrap Nautilus entries from the fathom AuditRecord envelope."""
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
# Default-off (NFR-5)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tokens_disabled_by_default(tmp_path: Path) -> None:
    broker = Broker.from_config(_write_yaml(tmp_path, tokens_enabled=False))
    try:
        assert broker.session_tokens is None
        assert broker.key_ring is None
        _install_fakes(broker)
        response = broker.request("agent-1", "show vulnerabilities", _ctx())
        assert response.session_token is None
        events = {e.get("event_type") for e in _audit_events(tmp_path)}
        assert "session_token_issued" not in events
    finally:
        broker.close()


@pytest.mark.unit
def test_issue_session_token_raises_when_disabled(tmp_path: Path) -> None:
    broker = Broker.from_config(_write_yaml(tmp_path, tokens_enabled=False))
    try:
        with pytest.raises(RuntimeError, match="disabled"):
            broker.issue_session_token(session_id="s", agent_id="a", purpose="p", clearance="c")
        with pytest.raises(RuntimeError, match="disabled"):
            broker.verify_session_token("whatever")
    finally:
        broker.close()


# ---------------------------------------------------------------------------
# Issuance (AC-18.a + AC-18.b + AC-18.f)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_first_request_issues_token_and_audits(tmp_path: Path) -> None:
    broker = Broker.from_config(_write_yaml(tmp_path))
    try:
        fakes = _install_fakes(broker)
        response = broker.request("agent-1", "show vulnerabilities", _ctx())
        assert isinstance(response.session_token, str) and response.session_token

        # Token claims bind the declared session + agent.
        claims = broker.verify_session_token(response.session_token)
        assert claims.session_id == "s1"
        assert claims.agent_id == "agent-1"

        # AC-18.b — adapters saw the token in context.
        seen = [c for fake in fakes.values() for c in fake.contexts]
        assert seen, "expected at least one adapter execution"
        assert all(c.get("session_token") == response.session_token for c in seen)

        # AC-18.f — exactly one session_token_issued event, request-correlated.
        issued = [
            e for e in _audit_events(tmp_path) if e.get("event_type") == "session_token_issued"
        ]
        assert len(issued) == 1
        assert issued[0]["agent_id"] == "agent-1"
        assert issued[0]["session_id"] == "s1"
        assert issued[0]["request_id"] == response.request_id
    finally:
        broker.close()


@pytest.mark.unit
def test_missing_session_id_gets_broker_generated_one(tmp_path: Path) -> None:
    broker = Broker.from_config(_write_yaml(tmp_path))
    try:
        _install_fakes(broker)
        ctx = _ctx()
        del ctx["session_id"]
        response = broker.request("agent-1", "show vulnerabilities", ctx)
        assert response.session_token is not None
        claims = broker.verify_session_token(response.session_token)
        assert claims.session_id  # non-empty broker-generated id
    finally:
        broker.close()


# ---------------------------------------------------------------------------
# Presentation pins the session (issue #18 core property)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_presented_token_pins_session_id(tmp_path: Path) -> None:
    """A fresh caller-declared session_id must NOT reset the exposure ledger."""
    broker = Broker.from_config(_write_yaml(tmp_path))
    try:
        _install_fakes(broker)
        first = broker.request("agent-1", "show vulnerabilities", _ctx("s1"))
        token = first.session_token
        assert token is not None

        # Second request declares a brand-new session_id but presents the
        # old token — the token wins.
        ctx2 = _ctx("fresh-session-evasion")
        ctx2["session_token"] = token
        second = broker.request("agent-1", "show vulnerabilities", ctx2)
        assert second.session_token == token  # echoed, not re-minted

        request_events = [e for e in _audit_events(tmp_path) if e.get("event_type") == "request"]
        assert len(request_events) == 2
        assert request_events[1]["session_id"] == "s1", (
            "token claims must override the caller-declared session_id"
        )
        # No second issuance.
        issued = [
            e for e in _audit_events(tmp_path) if e.get("event_type") == "session_token_issued"
        ]
        assert len(issued) == 1
    finally:
        broker.close()


# ---------------------------------------------------------------------------
# Fail-closed (AC-18.d + AC-18.f)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_tampered_token_fails_closed_with_audit(tmp_path: Path) -> None:
    broker = Broker.from_config(_write_yaml(tmp_path))
    try:
        fakes = _install_fakes(broker)
        first = broker.request("agent-1", "show vulnerabilities", _ctx())
        token = first.session_token
        assert token is not None

        header, payload, sig = token.split(".")
        tampered = f"{header}.{payload}.{'A' * len(sig)}"
        ctx2 = _ctx()
        ctx2["session_token"] = tampered
        with pytest.raises(SessionTokenError) as excinfo:
            broker.request("agent-1", "show vulnerabilities", ctx2)
        assert excinfo.value.reason_code == "bad_signature"

        failed = [
            e
            for e in _audit_events(tmp_path)
            if e.get("event_type") == "session_token_verification_failed"
        ]
        assert len(failed) == 1
        assert failed[0]["error_records"][0]["error_type"] == "bad_signature"

        # Fail-closed: the tampered request never reached an adapter.
        executions = sum(len(f.contexts) for f in fakes.values())
        first_run_executions = len(first.sources_queried)
        assert executions == first_run_executions
    finally:
        broker.close()


@pytest.mark.unit
@pytest.mark.parametrize("junk", [0, False, "", [], {}], ids=type)
def test_falsy_or_nonstring_token_fails_closed(tmp_path: Path, junk: Any) -> None:
    """A present-but-junk token must NOT silently re-mint a fresh session.

    Security-review finding: ``if presented:`` would treat falsy values
    (0 / False / "" / []) as "no token" and mint a new session — letting a
    caller suppress verification and reset its exposure ledger. Only an
    ABSENT key means "no token"; everything else fails closed.
    """
    broker = Broker.from_config(_write_yaml(tmp_path))
    try:
        _install_fakes(broker)
        ctx = _ctx()
        ctx["session_token"] = junk
        with pytest.raises(SessionTokenError) as excinfo:
            broker.request("agent-1", "show vulnerabilities", ctx)
        assert excinfo.value.reason_code == "missing"
        issued = [
            e for e in _audit_events(tmp_path) if e.get("event_type") == "session_token_issued"
        ]
        assert issued == [], "junk token must never trigger a fresh mint"
    finally:
        broker.close()


@pytest.mark.unit
def test_expired_token_fails_closed(tmp_path: Path) -> None:
    broker = Broker.from_config(_write_yaml(tmp_path, ttl_seconds=-1))
    try:
        _install_fakes(broker)
        first = broker.request("agent-1", "show vulnerabilities", _ctx())
        token = first.session_token
        assert token is not None

        ctx2 = _ctx()
        ctx2["session_token"] = token
        with pytest.raises(SessionTokenError) as excinfo:
            broker.request("agent-1", "show vulnerabilities", ctx2)
        assert excinfo.value.reason_code == "expired"
    finally:
        broker.close()


# ---------------------------------------------------------------------------
# Handoff token gate (#18 AC: handoff requires originating agent's token)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_handoff_without_token_denied_when_tokens_enabled(tmp_path: Path) -> None:
    broker = Broker.from_config(_write_yaml(tmp_path, with_agents=True))
    try:
        decision = asyncio.run(
            broker.declare_handoff(
                source_agent_id="agent-source",
                receiving_agent_id="agent-receiver",
                session_id="sess-h",
                data_classifications=["unclassified"],
            )
        )
        assert decision.action == "deny"
        assert decision.denial_records[0].rule_name == "session-token-required"
    finally:
        broker.close()


@pytest.mark.unit
def test_handoff_with_valid_token_allows_and_records_reference(tmp_path: Path) -> None:
    broker = Broker.from_config(_write_yaml(tmp_path, with_agents=True))
    try:
        token = broker.issue_session_token(
            session_id="sess-h",
            agent_id="agent-source",
            purpose="threat-analysis",
            clearance="secret",
        )
        decision = asyncio.run(
            broker.declare_handoff(
                source_agent_id="agent-source",
                receiving_agent_id="agent-receiver",
                session_id="sess-h",
                data_classifications=["unclassified"],
                session_token=token,
            )
        )
        assert decision.action == "allow"
        assert any(t.startswith("session-token:verified") for t in decision.rule_trace)

        # The handoff audit entry carries the token reference via rule_trace.
        handoffs = [e for e in _audit_events(tmp_path) if e.get("event_type") == "handoff_declared"]
        assert len(handoffs) == 1
        assert any(t.startswith("session-token:verified") for t in handoffs[0]["rule_trace"])
    finally:
        broker.close()


@pytest.mark.unit
def test_handoff_with_other_agents_token_denied(tmp_path: Path) -> None:
    broker = Broker.from_config(_write_yaml(tmp_path, with_agents=True))
    try:
        token = broker.issue_session_token(
            session_id="sess-h",
            agent_id="agent-receiver",  # wrong agent presents as source
            purpose="threat-analysis",
            clearance="secret",
        )
        decision = asyncio.run(
            broker.declare_handoff(
                source_agent_id="agent-source",
                receiving_agent_id="agent-receiver",
                session_id="sess-h",
                data_classifications=["unclassified"],
                session_token=token,
            )
        )
        assert decision.action == "deny"
        assert decision.denial_records[0].rule_name == "session-token-agent-mismatch"
    finally:
        broker.close()


@pytest.mark.unit
def test_handoff_ignores_token_when_disabled(tmp_path: Path) -> None:
    """Backwards compat: tokens off → handoff path unchanged (NFR-5)."""
    broker = Broker.from_config(_write_yaml(tmp_path, tokens_enabled=False, with_agents=True))
    try:
        decision = asyncio.run(
            broker.declare_handoff(
                source_agent_id="agent-source",
                receiving_agent_id="agent-receiver",
                session_id="sess-h",
                data_classifications=["unclassified"],
            )
        )
        assert decision.action == "allow"
    finally:
        broker.close()


# ---------------------------------------------------------------------------
# Adapter header forwarding (AC-18.b)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_session_token_headers_helper() -> None:
    assert session_token_headers({}) is None
    assert session_token_headers({"session_token": ""}) is None
    assert session_token_headers({"session_token": 42}) is None
    assert session_token_headers({"session_token": "tok"}) == {SESSION_TOKEN_HEADER: "tok"}


@pytest.mark.unit
async def test_rest_adapter_forwards_session_token_header() -> None:
    captured: dict[str, Any] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json=[{"id": 1}])

    client = httpx.AsyncClient(
        base_url="http://api.example.com", transport=httpx.MockTransport(_handler)
    )
    adapter = RestAdapter(client=client)
    await adapter.connect(
        SourceConfig(
            id="rest_src",
            type="rest",
            description="rest source",
            classification="secret",
            data_types=["widget"],
            allowed_purposes=["research"],
            connection="http://api.example.com",
            endpoints=[EndpointSpec(path="/widgets", method="GET")],
            auth=NoneAuth(),
        )
    )
    intent = IntentAnalysis(raw_intent="fetch widgets", data_types_needed=["widget"], entities=[])
    await adapter.execute(intent, [], {"session_token": "tok-123"})
    assert captured["headers"].get(SESSION_TOKEN_HEADER.lower()) == "tok-123"

    captured.clear()
    await adapter.execute(intent, [], {})
    assert SESSION_TOKEN_HEADER.lower() not in captured["headers"]
    await adapter.close()
