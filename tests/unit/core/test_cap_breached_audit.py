"""Unit tests for the ``cap_breached`` audit emitter (Task 20, US-2, AC-2.12).

Covers the enrichment Task 20 layers on top of Task 18's inline stub
:meth:`nautilus.core.broker.Broker._emit_cap_breached_audit`:

1. **Payload enrichment** — the breach-specific fields
   (``source_id``, ``axis``, ``observed``, ``limit``, ``enforcement``,
   ``actor``) are stashed on the emitted :class:`AuditEntry` in a
   reversible shape so ``AuditEntry.model_validate_json`` round-trips
   them without loss.
2. **Actor threading** — the request principal (``state.actor_agent_id``)
   is recorded as the ``actor`` on the breach line, distinct from the
   broker-as-emitter ``agent_id="<broker>"``.
3. **Multiple breaches per request** — a request that breaches on two
   sources emits two audit entries (one per breach event).
4. **``cost_cap_context`` attestation enrichment** — when the request
   carries non-empty per-source effective caps, the v2 attestation
   payload's ``cost_cap_context`` block includes ``effective_caps_per_source``
   alongside the existing ``cap_breached`` flag. When neither signal is
   present, the block is omitted (NFR-ATT-V2-FROZEN).

All scenarios are strictly unit-scoped: no broker fixture load, no
testcontainers, no asyncio pipeline — we poke
:meth:`Broker._emit_cap_breached_audit` directly or exercise
:func:`build_payload` with duck-typed response shims. The audit logger
is redirected to an in-memory sink so assertions read only this test's
writes.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fathom.models import AuditRecord

from nautilus.audit.logger import (
    NAUTILUS_METADATA_KEY,
    AuditLogger,
    decode_nautilus_entry,
)
from nautilus.core.attestation_payload import build_payload
from nautilus.core.broker import Broker, _RequestState  # pyright: ignore[reportPrivateUsage]
from nautilus.core.models import AuditEntry, IntentAnalysis

# ---------------------------------------------------------------------------
# Harness: direct-emission via a minimal broker shim.
# ---------------------------------------------------------------------------


class _CapturingSink:
    """In-memory audit sink — stashes every :class:`AuditRecord` for assertions.

    Mirrors the shape :class:`fathom.audit.FileSink` exposes so
    :class:`AuditLogger.emit` accepts it via duck typing (``write`` is
    the only attribute consumed).
    """

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def write(self, record: AuditRecord) -> None:
        self.records.append(record)


def _make_state(*, agent_id: str = "agent-alpha") -> _RequestState:
    """Build a minimal :class:`_RequestState` for direct emitter invocations.

    Populates only the fields the emitter reads (``request_id``,
    ``session_id``, ``intent``, ``actor_agent_id``); everything else
    stays on its dataclass default.
    """
    return _RequestState(
        request_id="req-cap-test",
        session_id="sess-cap-test",
        started=0.0,
        intent="unit-test intent",
        intent_analysis=IntentAnalysis(
            raw_intent="unit-test intent", data_types_needed=[], entities=[]
        ),
        actor_agent_id=agent_id,
    )


def _broker_with_capturing_sink() -> tuple[Broker, _CapturingSink]:
    """Build a :class:`Broker` whose audit logger writes into a capture sink.

    Uses the repo's ``tests/fixtures/nautilus.yaml`` fixture but swaps
    the audit logger so assertions read only this test's emissions.
    """
    fixture_path = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"
    broker = Broker.from_config(fixture_path)
    sink = _CapturingSink()
    broker._audit_logger = AuditLogger(sink=sink)  # type: ignore[attr-defined]  # noqa: SLF001
    return broker, sink


@pytest.fixture(autouse=True)
def _set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    """Stub DSNs the fixture ``nautilus.yaml`` interpolates via ``${ENV}``.

    The fixture wires adapters against env-templated Postgres DSNs; for
    unit tests we swap the adapters/sink before any dispatch so the DSN
    is never actually opened.
    """
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


def _extract_entry(record: AuditRecord) -> AuditEntry:
    """Decode the :class:`AuditEntry` JSON embedded in an :class:`AuditRecord`."""
    return decode_nautilus_entry(record)


def _parse_breach_line(line: str) -> dict[str, str]:
    """Split a ``cap_breached:`` rule_trace line into a ``{key: value}`` dict.

    Accepts the exact shape
    :meth:`Broker._emit_cap_breached_audit` emits:
    ``cap_breached:source_id=...,axis=...,observed=...,limit=...,``
    ``enforcement=...,actor=...``.
    """
    assert line.startswith("cap_breached:"), f"unexpected rule_trace line: {line!r}"
    payload = line.removeprefix("cap_breached:")
    result: dict[str, str] = {}
    for kv in payload.split(","):
        key, _, value = kv.partition("=")
        result[key] = value
    return result


# ---------------------------------------------------------------------------
# Scenario (a) — one hard breach emits one entry with enriched payload.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_hard_cap_breached_audit_entry_has_enriched_payload() -> None:
    """AC-2.12 — ``_emit_cap_breached_audit`` writes one entry with
    ``source_id``, ``axis``, ``observed``, ``limit``, ``enforcement``,
    ``actor`` recoverable from the persisted payload."""
    broker, sink = _broker_with_capturing_sink()
    state = _make_state(agent_id="agent-alpha")
    try:
        broker._emit_cap_breached_audit(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            state=state,
            source_id="nvd_db",
            axis="max_tokens",
            observed=1500,
            limit=1000,
            enforcement="hard",
        )
    finally:
        broker.close()

    assert len(sink.records) == 1, (
        f"one hard breach must emit exactly one audit record; got {len(sink.records)}"
    )
    entry = _extract_entry(sink.records[0])
    assert entry.event_type == "cap_breached"
    assert entry.agent_id == "<broker>", (
        f"broker-as-emitter marker must be '<broker>'; got {entry.agent_id!r}"
    )
    assert entry.sources_errored == ["nvd_db"]

    # Structured rule_trace line carries the full breach payload.
    assert len(entry.rule_trace) == 1, (
        f"rule_trace must carry exactly one breach line; got {entry.rule_trace!r}"
    )
    parsed = _parse_breach_line(entry.rule_trace[0])
    assert parsed["source_id"] == "nvd_db"
    assert parsed["axis"] == "max_tokens"
    assert parsed["observed"] == "1500"
    assert parsed["limit"] == "1000"
    assert parsed["enforcement"] == "hard"
    assert parsed["actor"] == "agent-alpha"


# ---------------------------------------------------------------------------
# Scenario (b) — two sources each breach different axes → two entries.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_two_breaches_in_one_request_emit_two_audit_entries() -> None:
    """One request can emit multiple ``cap_breached`` audits — one per breach event."""
    broker, sink = _broker_with_capturing_sink()
    state = _make_state(agent_id="agent-beta")
    try:
        broker._emit_cap_breached_audit(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            state=state,
            source_id="nvd_db",
            axis="max_tokens",
            observed=2000,
            limit=1000,
            enforcement="hard",
        )
        broker._emit_cap_breached_audit(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            state=state,
            source_id="internal_vulns",
            axis="max_duration_seconds",
            observed=5.0,
            limit=2,
            enforcement="soft",
        )
    finally:
        broker.close()

    assert len(sink.records) == 2, (
        f"two breaches must emit two audit records; got {len(sink.records)}"
    )
    entries = [_extract_entry(r) for r in sink.records]
    # Both records carry the same request_id but distinct per-breach payloads.
    assert all(e.event_type == "cap_breached" for e in entries)
    assert {e.rule_trace[0] for e in entries} == {
        "cap_breached:source_id=nvd_db,axis=max_tokens,observed=2000,limit=1000,"
        "enforcement=hard,actor=agent-beta",
        "cap_breached:source_id=internal_vulns,axis=max_duration_seconds,"
        "observed=5.0,limit=2,enforcement=soft,actor=agent-beta",
    }


# ---------------------------------------------------------------------------
# Scenario (c) — payload round-trips through the JSONL decoder.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_cap_breached_audit_round_trips_through_decode() -> None:
    """Round-trip: emitted record → :func:`decode_nautilus_entry` reconstructs the full payload."""
    broker, sink = _broker_with_capturing_sink()
    state = _make_state(agent_id="agent-roundtrip")
    try:
        broker._emit_cap_breached_audit(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            state=state,
            source_id="svc-llm",
            axis="max_tool_calls",
            observed=42,
            limit=10,
            enforcement="hard",
        )
    finally:
        broker.close()

    record = sink.records[0]
    # The metadata key contract is what :class:`FileSink` writes to disk
    # as a JSONL line; round-trip here mirrors reading that line back.
    raw = record.metadata[NAUTILUS_METADATA_KEY]
    assert isinstance(raw, str)
    # Full model_validate_json round-trip must succeed.
    rehydrated = AuditEntry.model_validate_json(raw)
    assert rehydrated.event_type == "cap_breached"
    assert len(rehydrated.rule_trace) == 1
    parsed = _parse_breach_line(rehydrated.rule_trace[0])
    assert parsed == {
        "source_id": "svc-llm",
        "axis": "max_tool_calls",
        "observed": "42",
        "limit": "10",
        "enforcement": "hard",
        "actor": "agent-roundtrip",
    }
    # Raw JSON contains the event_type marker as a top-level field — the
    # structural shape the JSONL consumer greps for.
    decoded: dict[str, Any] = json.loads(raw)
    assert decoded["event_type"] == "cap_breached"


# ---------------------------------------------------------------------------
# Scenario (d) — ``cost_cap_context`` reflects per-source effective caps.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_cost_cap_context_includes_effective_caps_per_source() -> None:
    """Even with ``cap_breached=False``, non-empty ``effective_caps_per_source``
    triggers the v2 ``cost_cap_context`` enrichment (AC-2.12)."""
    response = SimpleNamespace(
        cap_breached=False,
        effective_caps_per_source={
            "nvd_db": {
                "max_tokens": 1000,
                "max_duration_seconds": 30,
                "max_tool_calls": None,
                "enforcement": "hard",
            }
        },
    )
    payload, version = build_payload(
        "req-1",
        "agent-a",
        ["nvd_db"],
        [],
        [],
        response=response,
    )
    # Scope is empty → v1 branch. The ``cost_cap_context`` key is a
    # conditional-on-presence extension that can ride on either version;
    # the spec's "three conditional v2 extensions" is about what they
    # *opt into*, not a prerequisite that the scope be v2.
    assert version == "v1"
    assert "cost_cap_context" in payload, (
        "effective_caps_per_source presence must opt the payload into "
        f"cost_cap_context; got {payload!r}"
    )
    block: dict[str, Any] = payload["cost_cap_context"]
    assert block["cap_breached"] is False
    assert block["effective_caps_per_source"] == {
        "nvd_db": {
            "max_tokens": 1000,
            "max_duration_seconds": 30,
            "max_tool_calls": None,
            "enforcement": "hard",
        }
    }


@pytest.mark.unit
def test_cost_cap_context_omitted_without_caps_or_breach() -> None:
    """NFR-ATT-V2-FROZEN — a response with no caps AND no breach leaves
    the payload bit-for-bit identical to the no-response path."""
    # Baseline: legacy call path (no response kwarg).
    baseline, _ = build_payload("req-1", "agent-a", ["s"], [], [])
    # With a response that carries neither signal, the cost_cap_context
    # extension must NOT fire.
    response = SimpleNamespace(cap_breached=False, effective_caps_per_source={})
    enriched, _ = build_payload("req-1", "agent-a", ["s"], [], [], response=response)
    assert "cost_cap_context" not in enriched
    assert enriched == baseline, (
        "legacy shape must be preserved when neither cap_breached nor "
        f"effective_caps_per_source fires; got {enriched!r}"
    )


@pytest.mark.unit
def test_cost_cap_context_back_compat_when_only_cap_breached() -> None:
    """Task 9 shape still works: ``cap_breached=True`` alone → block with just that key."""
    response = SimpleNamespace(cap_breached=True, effective_caps_per_source={})
    payload, _ = build_payload("req-1", "agent-a", ["s"], [], [], response=response)
    assert payload["cost_cap_context"] == {"cap_breached": True}
