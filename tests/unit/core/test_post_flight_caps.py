"""Unit tests for :meth:`Broker._check_post_flight_caps` (spec Task 19, US-2).

Exercises the post-flight cost-cap check that runs inside
:meth:`Broker._gather_adapter_results`. Five scenarios cover the AC-2.6
requirements:

1. ``max_tool_calls`` hard breach — observed > limit, ``enforcement="hard"``
   → breach detected, hard skip marker, audit entry with ``enforcement="hard"``.
2. ``max_tool_calls`` soft breach — same limits, ``enforcement="soft"`` →
   breach detected, NO skip marker (caller keeps the data), audit entry
   with ``enforcement="soft"``.
3. ``max_tokens`` post-flight breach — pre-flight never fired (no
   ``estimate_cost`` on adapter) → post-flight detects the breach.
4. Pre-flight / post-flight dedup — ``cap_breaches_seen`` pre-seeded with
   ``(source_id, "max_tokens")`` → post-flight DOES NOT emit a second audit
   for the same axis even though the ground-truth observation would trip it.
5. Missing ``usage`` — ``result.meta`` has no ``usage`` key → no-op
   (no breach, no audit).

Directly invokes the private method on a real :class:`Broker` wired from
the fixture YAML; adapter results are synthesized as light shims with a
``.meta`` attribute so the check reads observed usage without requiring
Task 39's :class:`LLMAdapter`.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from nautilus import Broker
from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.config.models import CostCapConfig
from nautilus.core.broker import _new_request_state  # pyright: ignore[reportPrivateUsage]
from nautilus.core.models import AuditEntry

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"


@pytest.fixture(autouse=True)
def _set_test_env(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Provide dummy DSNs + root audit writes under ``tmp_path``."""
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")
    monkeypatch.chdir(tmp_path)


def _mk_result(source_id: str, meta: dict[str, Any] | None) -> Any:
    """Adapter-result shim with ``.meta`` — duck-types the fields the check reads."""
    return SimpleNamespace(source_id=source_id, meta=meta, rows=[], duration_ms=0, error=None)


def _read_audit_entries(audit_file: Path) -> list[AuditEntry]:
    entries: list[AuditEntry] = []
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record: dict[str, Any] = json.loads(line)
        entry_json = record["metadata"][NAUTILUS_METADATA_KEY]
        entries.append(AuditEntry.model_validate_json(entry_json))
    return entries


# ---------------------------------------------------------------------------
# Scenario 1 — max_tool_calls hard breach.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_post_flight_caps_max_tool_calls_hard(tmp_path: Path) -> None:
    """Hard breach on ``max_tool_calls`` → skip marker + audit entry."""
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        state = _new_request_state({"session_id": "sess-1"}, "t1")
        result = _mk_result("nvd_db", {"usage": {"tool_calls": 8, "tokens": 10}})
        caps = CostCapConfig(max_tool_calls=5, enforcement="hard")

        breach, markers = broker._check_post_flight_caps(  # type: ignore[attr-defined]  # noqa: SLF001
            result, caps, state, "nvd_db"
        )

        assert breach is True
        assert markers == ["cap_breached:max_tool_calls:nvd_db"]
        assert state.cap_breached is True
        assert ("nvd_db", "max_tool_calls") in state.cap_breaches_seen

        audit_file = tmp_path / "audit.jsonl"
        entries = _read_audit_entries(audit_file)
        cap_entries = [e for e in entries if e.event_type == "cap_breached"]
        assert len(cap_entries) == 1
        assert cap_entries[0].error_records, "cap_breached audit must carry ErrorRecord"
        msg = cap_entries[0].error_records[0].message
        assert "axis=max_tool_calls" in msg
        assert "enforcement=hard" in msg
    finally:
        import asyncio as _asyncio

        _asyncio.run(broker.aclose())


# ---------------------------------------------------------------------------
# Scenario 2 — max_tool_calls soft breach (data kept, cap_breached flipped).
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_post_flight_caps_max_tool_calls_soft(tmp_path: Path) -> None:
    """Soft breach → NO skip marker; data kept; cap_breached flipped; audit emitted."""
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        state = _new_request_state({"session_id": "sess-2"}, "t2")
        result = _mk_result("nvd_db", {"usage": {"tool_calls": 9}})
        caps = CostCapConfig(max_tool_calls=5, enforcement="soft")

        breach, markers = broker._check_post_flight_caps(  # type: ignore[attr-defined]  # noqa: SLF001
            result, caps, state, "nvd_db"
        )

        assert breach is True
        assert markers == []  # soft — caller keeps the partial data
        assert state.cap_breached is True

        audit_file = tmp_path / "audit.jsonl"
        entries = _read_audit_entries(audit_file)
        cap_entries = [e for e in entries if e.event_type == "cap_breached"]
        assert len(cap_entries) == 1
        msg = cap_entries[0].error_records[0].message
        assert "axis=max_tool_calls" in msg
        assert "enforcement=soft" in msg
    finally:
        import asyncio as _asyncio

        _asyncio.run(broker.aclose())


# ---------------------------------------------------------------------------
# Scenario 3 — max_tokens post-flight breach (pre-flight estimate missing).
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_post_flight_caps_max_tokens_when_preflight_absent(tmp_path: Path) -> None:
    """Post-flight ``max_tokens`` ground truth trips a breach pre-flight couldn't see."""
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        state = _new_request_state({"session_id": "sess-3"}, "t3")
        # cap_breaches_seen starts empty — pre-flight never fired.
        assert state.cap_breaches_seen == set()
        result = _mk_result("nvd_db", {"usage": {"tokens": 150}})
        caps = CostCapConfig(max_tokens=100, enforcement="hard")

        breach, markers = broker._check_post_flight_caps(  # type: ignore[attr-defined]  # noqa: SLF001
            result, caps, state, "nvd_db"
        )

        assert breach is True
        assert markers == ["cap_breached:max_tokens:nvd_db"]
        assert state.cap_breached is True
        assert ("nvd_db", "max_tokens") in state.cap_breaches_seen

        audit_file = tmp_path / "audit.jsonl"
        entries = _read_audit_entries(audit_file)
        cap_entries = [e for e in entries if e.event_type == "cap_breached"]
        assert len(cap_entries) == 1
        msg = cap_entries[0].error_records[0].message
        assert "axis=max_tokens" in msg
        assert "observed=150" in msg
        assert "limit=100" in msg
    finally:
        import asyncio as _asyncio

        _asyncio.run(broker.aclose())


# ---------------------------------------------------------------------------
# Scenario 4 — dedup: pre-flight already emitted → post-flight skips audit.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_post_flight_caps_dedup_with_preflight(tmp_path: Path) -> None:
    """Pre-flight already emitted ``(src1, max_tokens)`` → post-flight skips the audit.

    The breach IS still detected (skip marker + cap_breached flipped) so the
    caller still discards the partial data on hard enforcement; only the
    audit entry is suppressed so the JSONL stream isn't duplicated.
    """
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        state = _new_request_state({"session_id": "sess-4"}, "t4")
        # Simulate pre-flight hit: ``_enforce_cost_caps`` already recorded
        # this (source_id, axis) pair when it emitted its own audit.
        state.cap_breaches_seen.add(("nvd_db", "max_tokens"))
        result = _mk_result("nvd_db", {"usage": {"tokens": 200}})
        caps = CostCapConfig(max_tokens=100, enforcement="hard")

        breach, markers = broker._check_post_flight_caps(  # type: ignore[attr-defined]  # noqa: SLF001
            result, caps, state, "nvd_db"
        )

        assert breach is True
        assert markers == ["cap_breached:max_tokens:nvd_db"]

        audit_file = tmp_path / "audit.jsonl"
        if audit_file.exists():
            entries = _read_audit_entries(audit_file)
            cap_entries = [e for e in entries if e.event_type == "cap_breached"]
            assert len(cap_entries) == 0, (
                f"post-flight must not emit audit when pre-flight already did; "
                f"got {len(cap_entries)}"
            )
        # else: no audit file yet == zero emissions; this is the expected path.
    finally:
        import asyncio as _asyncio

        _asyncio.run(broker.aclose())


# ---------------------------------------------------------------------------
# Scenario 5 — missing ``usage`` entirely → no-op.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_post_flight_caps_missing_usage_is_noop(tmp_path: Path) -> None:
    """``result.meta`` without ``usage`` key → no breach, no audit, no state mutation."""
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        state = _new_request_state({"session_id": "sess-5"}, "t5")
        # No meta at all.
        result_none = _mk_result("nvd_db", None)
        caps = CostCapConfig(max_tool_calls=1, max_tokens=1, enforcement="hard")

        breach1, markers1 = broker._check_post_flight_caps(  # type: ignore[attr-defined]  # noqa: SLF001
            result_none, caps, state, "nvd_db"
        )
        assert (breach1, markers1) == (False, [])

        # Meta present but no ``usage`` key.
        result_empty = _mk_result("nvd_db", {"provider": "fake"})
        breach2, markers2 = broker._check_post_flight_caps(  # type: ignore[attr-defined]  # noqa: SLF001
            result_empty, caps, state, "nvd_db"
        )
        assert (breach2, markers2) == (False, [])

        assert state.cap_breached is False
        assert state.cap_breaches_seen == set()

        audit_file = tmp_path / "audit.jsonl"
        if audit_file.exists():
            entries = _read_audit_entries(audit_file)
            cap_entries = [e for e in entries if e.event_type == "cap_breached"]
            assert cap_entries == []
    finally:
        import asyncio as _asyncio

        _asyncio.run(broker.aclose())
