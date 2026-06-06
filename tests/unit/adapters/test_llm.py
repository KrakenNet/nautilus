"""Unit tests for :class:`nautilus.adapters.llm.LLMAdapter` (#43)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from nautilus.adapters.base import Adapter, AdapterError, ScopeEnforcementError
from nautilus.adapters.llm import (
    LLMAdapter,
    _assemble_prompt,  # pyright: ignore[reportPrivateUsage]
    _reject_unroutable_literal,  # pyright: ignore[reportPrivateUsage]
)
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint

pytestmark = pytest.mark.unit


def _source(
    connection: str = "http://127.0.0.1:9/v1", model: str | None = "test-model"
) -> SourceConfig:
    return SourceConfig(
        id="llm_src",
        type="llm",
        description="LLM source (test)",
        classification="unclassified",
        data_types=["vulnerability"],
        allowed_purposes=["threat-analysis"],
        connection=connection,
        model=model,
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="summarize recent vulnerabilities",
        data_types_needed=["vulnerability"],
        entities=["CVE-2024-1234"],
    )


def _scope() -> list[ScopeConstraint]:
    return [ScopeConstraint(source_id="llm_src", operator="=", field="severity", value="critical")]


def _openai_client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url="http://127.0.0.1:9/v1", transport=httpx.MockTransport(handler)
    )


def _completion_handler(captured: list[dict[str, Any]]) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "GENERATED ANSWER"}}]})

    return handler


# ---------------------------------------------------------------------------
# Protocol + capability surface
# ---------------------------------------------------------------------------


def test_llm_adapter_satisfies_adapter_protocol() -> None:
    assert isinstance(LLMAdapter(), Adapter)


def test_llm_adapter_declares_non_deterministic_capability() -> None:
    assert "non_deterministic" in LLMAdapter.capabilities


async def test_connect_requires_model() -> None:
    adapter = LLMAdapter()
    with pytest.raises(AdapterError, match="model"):
        await adapter.connect(_source(model=None))


async def test_connect_rejects_mtls_auth() -> None:
    """mTLS would be silently dropped by _auth_for_config — fail closed instead."""
    from nautilus.config.models import MtlsAuth

    source = _source()
    source = source.model_copy(
        update={"auth": MtlsAuth(cert_path="/tmp/c.pem", key_path="/tmp/k.pem")}
    )
    with pytest.raises(AdapterError, match="mTLS"):
        await LLMAdapter().connect(source)


async def test_execute_before_connect_raises() -> None:
    with pytest.raises(AdapterError, match="before connect"):
        await LLMAdapter().execute(_intent(), [], {})


async def test_close_is_idempotent() -> None:
    adapter = LLMAdapter(client=_openai_client(_completion_handler([])))
    await adapter.connect(_source())
    await adapter.close()
    await adapter.close()


async def test_get_schema_is_static_capability_only() -> None:
    adapter = LLMAdapter(client=_openai_client(_completion_handler([])))
    await adapter.connect(_source())
    schema = await adapter.get_schema()
    assert schema.adapter_id == "llm_src"
    assert schema.source_type == "llm"


# ---------------------------------------------------------------------------
# Endpoint guards
# ---------------------------------------------------------------------------


def test_loopback_and_private_hosts_allowed() -> None:
    _reject_unroutable_literal("http://127.0.0.1:8000/v1")
    _reject_unroutable_literal("http://10.0.0.5:8000/v1")
    _reject_unroutable_literal("https://llm.internal.example/v1")


def test_link_local_metadata_host_rejected() -> None:
    with pytest.raises(ScopeEnforcementError, match="link-local"):
        _reject_unroutable_literal("http://169.254.169.254/v1")


def test_empty_host_rejected() -> None:
    with pytest.raises(ScopeEnforcementError, match="non-empty host"):
        _reject_unroutable_literal("not-a-url")


# ---------------------------------------------------------------------------
# Prompt assembly — scope-limited by construction
# ---------------------------------------------------------------------------


def test_prompt_contains_intent_and_scope_only() -> None:
    prompt = _assemble_prompt(_intent(), _scope())
    assert "summarize recent vulnerabilities" in prompt
    assert "vulnerability" in prompt
    assert "CVE-2024-1234" in prompt
    assert "severity = 'critical'" in prompt


def test_prompt_invalid_operator_fails_closed() -> None:
    bad = ScopeConstraint.model_construct(
        source_id="llm_src", operator="DROP", field="severity", value="x"
    )
    with pytest.raises(ScopeEnforcementError, match="allowlist"):
        _assemble_prompt(_intent(), [bad])


def test_prompt_invalid_field_fails_closed() -> None:
    bad = ScopeConstraint.model_construct(
        source_id="llm_src", operator="=", field='x"; DROP TABLE', value="x"
    )
    with pytest.raises(ScopeEnforcementError, match="field identifier"):
        _assemble_prompt(_intent(), [bad])


# ---------------------------------------------------------------------------
# execute()
# ---------------------------------------------------------------------------


async def test_execute_returns_provenance_marked_rows() -> None:
    captured: list[dict[str, Any]] = []
    adapter = LLMAdapter(client=_openai_client(_completion_handler(captured)))
    await adapter.connect(_source())
    result = await adapter.execute(_intent(), _scope(), {})
    assert result.source_id == "llm_src"
    assert result.rows == [
        {"content": "GENERATED ANSWER", "provenance": "llm_generated", "model": "test-model"}
    ]
    assert captured[0]["model"] == "test-model"
    assert captured[0]["temperature"] == 0
    await adapter.close()


async def test_context_secrets_never_enter_the_request() -> None:
    """#43 acceptance: only scope-permitted fields enter the prompt.

    The request context (session tokens, clearance) must not appear
    anywhere in the outgoing HTTP body.
    """
    captured: list[dict[str, Any]] = []
    adapter = LLMAdapter(client=_openai_client(_completion_handler(captured)))
    await adapter.connect(_source())
    context = {
        "session_token": "SECRET-TOKEN-DO-NOT-LEAK",
        "clearance": "ts-sci-SECRET-MARKING",
        "session_id": "s1",
    }
    await adapter.execute(_intent(), _scope(), context)
    body = json.dumps(captured[0])
    assert "SECRET-TOKEN-DO-NOT-LEAK" not in body
    assert "ts-sci-SECRET-MARKING" not in body
    # The scoped prompt did go out.
    assert "severity = 'critical'" in body
    await adapter.close()


async def test_scope_violation_blocks_before_network() -> None:
    captured: list[dict[str, Any]] = []
    adapter = LLMAdapter(client=_openai_client(_completion_handler(captured)))
    await adapter.connect(_source())
    bad = ScopeConstraint.model_construct(
        source_id="llm_src", operator="DROP", field="severity", value="x"
    )
    with pytest.raises(ScopeEnforcementError):
        await adapter.execute(_intent(), [bad], {})
    assert captured == [], "no HTTP call may happen after a scope violation"
    await adapter.close()


async def test_http_error_raises_adapter_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    adapter = LLMAdapter(client=_openai_client(handler))
    await adapter.connect(_source())
    with pytest.raises(AdapterError, match="call failed"):
        await adapter.execute(_intent(), [], {})
    await adapter.close()


async def test_unexpected_response_shape_raises_adapter_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"not": "openai"})

    adapter = LLMAdapter(client=_openai_client(handler))
    await adapter.connect(_source())
    with pytest.raises(AdapterError, match="response shape"):
        await adapter.execute(_intent(), [], {})
    await adapter.close()


# ---------------------------------------------------------------------------
# Broker integration — routed request, denial rules, hash_skipped attestation
# ---------------------------------------------------------------------------

_BROKER_CONFIG = """\
sources:
  - id: llm_src
    type: llm
    description: "LLM source (test)"
    classification: unclassified
    data_types: [vulnerability]
    allowed_purposes: [threat-analysis]
    connection: "http://127.0.0.1:9/v1"
    model: test-model

rules:
  user_rules_dirs: []

analysis:
  keyword_map:
    vulnerability: [vulnerability, vuln]

audit:
  path: {audit_path}

attestation:
  enabled: true
  sink:
    type: file
    path: {sink_path}
"""


def _write_broker_config(tmp_path: Path) -> tuple[Path, Path]:
    config = tmp_path / "nautilus.yaml"
    sink_path = tmp_path / "attest.jsonl"
    config.write_text(
        _BROKER_CONFIG.format(audit_path=str(tmp_path / "audit.jsonl"), sink_path=str(sink_path)),
        encoding="utf-8",
    )
    return config, sink_path


def _install_llm_adapter(broker: Any, captured: list[dict[str, Any]]) -> LLMAdapter:
    adapter = LLMAdapter(client=_openai_client(_completion_handler(captured)))
    broker._adapters = {"llm_src": adapter}  # noqa: SLF001
    return adapter


async def test_brokered_request_routes_to_llm_and_signs_hash_skipped(tmp_path: Path) -> None:
    """#43 acceptance: routed request, attestation carries hash_skipped=True,
    audit chain records the exchange."""
    from nautilus.core.broker import Broker

    config, sink_path = _write_broker_config(tmp_path)
    broker = Broker.from_config(config)
    captured: list[dict[str, Any]] = []
    adapter = _install_llm_adapter(broker, captured)
    await adapter.connect(_source())
    broker._connected_adapters = {"llm_src"}  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001

    try:
        resp = await broker.arequest(
            "agent-alpha",
            "vulnerability summary",
            {"clearance": "unclassified", "purpose": "threat-analysis", "session_id": "s1"},
        )
        assert "llm_src" in resp.sources_queried
        assert resp.data["llm_src"][0]["provenance"] == "llm_generated"
        assert resp.attestation_token is not None

        # Attestation sink payload signs hash_skipped=True, no response_hash
        # (AC-19.g — non-deterministic source).
        payloads = [
            json.loads(line)
            for line in sink_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert payloads, "attestation sink must record the exchange"
        claims = payloads[-1]["nautilus_payload"]
        assert claims["hash_skipped"] is True
        assert "response_hash" not in claims
        assert payloads[-1]["token"], "sink envelope must carry the signed JWT"

        # Audit chain records the exchange.
        audit_lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        assert audit_lines, "audit log must record the exchange"
    finally:
        await broker.aclose()


async def test_brokered_request_denial_rules_apply(tmp_path: Path) -> None:
    """#43 acceptance: denial rules apply — purpose mismatch denies the LLM
    source and no LLM call is made."""
    from nautilus.core.broker import Broker

    config, _sink_path = _write_broker_config(tmp_path)
    broker = Broker.from_config(config)
    captured: list[dict[str, Any]] = []
    adapter = _install_llm_adapter(broker, captured)
    await adapter.connect(_source())
    broker._connected_adapters = {"llm_src"}  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001

    try:
        resp = await broker.arequest(
            "agent-alpha",
            "vulnerability summary",
            {"clearance": "unclassified", "purpose": "research", "session_id": "s1"},
        )
        assert "llm_src" in resp.sources_denied
        assert "llm_src" not in resp.sources_queried
        assert captured == [], "denied source must never be queried"
    finally:
        await broker.aclose()


# ---------------------------------------------------------------------------
# Air-gap interaction (serve --air-gapped)
# ---------------------------------------------------------------------------


def test_air_gap_drops_non_loopback_llm_source(capsys: pytest.CaptureFixture[str]) -> None:
    from nautilus.cli.serve import _enforce_air_gap  # pyright: ignore[reportPrivateUsage]

    raw: dict[str, Any] = {
        "sources": [
            {"id": "remote_llm", "type": "llm", "connection": "https://api.example.com/v1"},
            {"id": "local_llm", "type": "llm", "connection": "http://127.0.0.1:8000/v1"},
            {"id": "localhost_llm", "type": "llm", "connection": "http://localhost:8000/v1"},
            {"id": "fqdn_llm", "type": "llm", "connection": "http://localhost.:8000/v1"},
            {"id": "v6_llm", "type": "llm", "connection": "http://[::1]:8000/v1"},
            {"id": "pg", "type": "postgres", "connection": "postgres://remote/db"},
        ]
    }
    result = _enforce_air_gap(raw)
    kept_ids = [s["id"] for s in result["sources"]]
    assert kept_ids == ["local_llm", "localhost_llm", "fqdn_llm", "v6_llm", "pg"]
    assert "remote_llm" in capsys.readouterr().err
