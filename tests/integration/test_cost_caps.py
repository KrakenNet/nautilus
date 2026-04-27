"""Cost-cap enforcement integration tests (Task 18, US-2, FR-18/19/24-28).

AC coverage: AC-2.4 / AC-2.5 / AC-2.7 / AC-2.8 / AC-2.9 / AC-2.10.

Exercises :meth:`Broker._enforce_cost_caps` between :meth:`Broker._route`
and :meth:`Broker._build_adapter_jobs`. Scenarios cover the three
acceptance axes for the Phase-2 enforcement seam:

1. **Soft breach (``enforcement="soft"``)** — a per-source ``max_tokens``
   override trips the pre-flight LLM stub branch, but soft enforcement
   means the source still runs; the audit entry records the breach
   with ``event_type="cap_breached"`` so operators see the signal
   without losing the response payload (AC-2.10).
2. **Duration cap (non-LLM adapters)** — a global ``max_duration_seconds``
   of ``0`` (any positive elapsed time counts as a breach) + two fake
   postgres/pgvector adapters. The check fires before any adapter
   dispatch, so both decisions are skipped with the
   ``cap_breached:max_duration_seconds`` marker and
   ``BrokerResponse.cap_breached is True`` (AC-2.7, AC-2.9).
3. **Pre-flight LLM stub (``AttributeError`` → soft-breach)** —
   ``max_tokens=100`` on a source whose ``type`` is monkey-patched to
   ``"llm"`` (Task 39 adds the literal; for Task 18 the branch is
   functionally stubbed). The installed adapter lacks ``estimate_cost``,
   so the pre-flight branch swallows ``AttributeError``, logs a
   warning, and passes through as a soft breach. The audit entry is
   still emitted so downstream tooling (Task 20) can enumerate cap
   events even while the estimator hook is unwired (AC-2.5 degraded).

All scenarios use the in-process broker (Phase-1 ``InMemorySessionStore``
+ fixture ``nautilus.yaml``) with :class:`_FakeAdapter` doubles installed
via the same ``_install_fakes`` pattern used by
``tests/unit/test_broker.py`` — no Docker, no testcontainers, no external
services. The audit file is rooted under ``tmp_path`` so assertions read
only this test's writes.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from nautilus import Broker
from nautilus.adapters.base import Adapter
from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.config.models import CostCapConfig, SourceConfig
from nautilus.core.models import AdapterResult, AuditEntry, IntentAnalysis, ScopeConstraint

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nautilus.yaml"


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _FakeAdapter:
    """Minimal :class:`Adapter` Protocol impl — mirrors ``tests/unit/test_broker.py``.

    Intentionally LACKS ``estimate_cost`` so the Task 18 pre-flight LLM
    branch hits its ``AttributeError`` stub path. Task 39 adds the method
    on the real :class:`LLMAdapter`; at that point Task 40 re-verifies
    this file with the pre-flight LLM scenarios fully enabled.
    """

    source_type: str = "fake"

    def __init__(
        self,
        source_id: str,
        *,
        rows: list[dict[str, Any]] | None = None,
        sleep_for: float = 0.0,
    ) -> None:
        self._source_id = source_id
        self._rows = rows if rows is not None else [{"id": 1}]
        self._sleep_for = sleep_for

    async def connect(self, config: SourceConfig) -> None:
        del config

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        if self._sleep_for > 0:
            await asyncio.sleep(self._sleep_for)
        return AdapterResult(
            source_id=self._source_id,
            rows=list(self._rows),
            duration_ms=0,
        )

    async def close(self) -> None:
        return None


def _install_fakes(broker: Broker, fakes: dict[str, _FakeAdapter]) -> None:
    """Swap adapters for fakes + pre-mark them as connected (no Postgres)."""
    broker._adapters = dict(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = set(fakes.keys())  # type: ignore[attr-defined]  # noqa: SLF001
    # Sanity: the fakes must still satisfy the runtime-checkable Adapter
    # Protocol so ``_prepare_adapter`` sees them as usable.
    for adapter in fakes.values():
        assert isinstance(adapter, Adapter)


def _ctx() -> dict[str, Any]:
    """Baseline context that routes to both fixture sources."""
    return {
        "clearance": "unclassified",
        "purpose": "threat-analysis",
        "session_id": "sess-cost-caps",
        "embedding": [0.1, 0.2, 0.3],
    }


def _read_audit_entries(audit_file: Path) -> list[AuditEntry]:
    entries: list[AuditEntry] = []
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record: dict[str, Any] = json.loads(line)
        entry_json = record["metadata"][NAUTILUS_METADATA_KEY]
        entries.append(AuditEntry.model_validate_json(entry_json))
    return entries


@pytest.fixture(autouse=True)
def _set_test_env(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Provide dummy DSNs + root audit writes under ``tmp_path``."""
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")
    monkeypatch.chdir(tmp_path)


# ---------------------------------------------------------------------------
# Scenario 1: soft breach — per-source override trips the LLM stub branch
# but ``enforcement="soft"`` lets the source through.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_soft_breach_passes_through_with_audit(tmp_path: Path) -> None:
    """AC-2.10 — ``enforcement="soft"`` logs the breach but does NOT skip the source.

    Per-source ``cost_caps`` on ``nvd_db`` sets ``max_tokens=100`` with
    ``enforcement="soft"``. The ``source.type`` is monkey-patched to
    ``"llm"`` so the pre-flight LLM branch fires; the fake adapter
    lacks ``estimate_cost`` → :class:`AttributeError` → soft-breach.
    Because ``enforcement=="soft"``, the source still runs and surfaces
    under ``sources_queried``; the ``cap_breached`` audit entry records
    the observation without filtering out the decision.
    """
    broker = Broker.from_config(FIXTURE_PATH)
    # Monkey-patch: promote nvd_db to the (future) llm source type + attach
    # a soft per-source cost cap. Pydantic's BaseModel allows attribute
    # mutation so Task 39 doesn't have to land first.
    nvd = next(s for s in broker.sources if s.id == "nvd_db")
    nvd.type = "llm"  # type: ignore[assignment]  # Task 39 extends the literal
    nvd.cost_caps = CostCapConfig(max_tokens=100, enforcement="soft")

    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db", rows=[{"id": 1, "cve": "CVE-SOFT"}]),
                "internal_vulns": _FakeAdapter("internal_vulns", rows=[{"id": 2}]),
            },
        )
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())

        # Soft breach is pass-through — both sources queried, no cap_breached markers.
        assert set(resp.sources_queried) == {"nvd_db", "internal_vulns"}, (
            f"soft breach must NOT skip the source; got sources_queried={resp.sources_queried!r}"
        )
        cap_skips = [s for s in resp.sources_skipped if s.startswith("cap_breached:")]
        assert not cap_skips, f"soft breach must NOT add cap_breached markers; got {cap_skips!r}"

        # Audit emits ``cap_breached`` with enforcement="soft".
        audit_file = tmp_path / "audit.jsonl"
        assert audit_file.exists(), f"audit file missing at {audit_file}"
        entries = _read_audit_entries(audit_file)
        cap_entries = [e for e in entries if e.event_type == "cap_breached"]
        assert len(cap_entries) == 1, (
            f"soft breach must emit exactly one cap_breached audit; got {len(cap_entries)}"
        )
    finally:
        await broker.aclose()


# ---------------------------------------------------------------------------
# Scenario 2: duration cap fires before any adapter dispatch; all decisions skipped.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_duration_cap_skips_remaining_decisions(tmp_path: Path) -> None:
    """AC-2.7 / AC-2.9 — ``max_duration_seconds`` breach skips all remaining decisions.

    Global ``max_duration_seconds=0`` with ``enforcement="hard"``. By the
    time ``_enforce_cost_caps`` runs (after intent analysis + routing),
    non-zero wall time has elapsed, so the check trips for every
    decision. Each surfaces under ``sources_skipped`` with the
    ``cap_breached:max_duration_seconds`` marker, ``cap_breached=True``
    on the response, and exactly one ``cap_breached`` audit entry
    records the breach (axis=``max_duration_seconds`` / enforcement=``hard``).
    """
    broker = Broker.from_config(FIXTURE_PATH)
    # Inject a global duration cap of 0 — any positive elapsed time
    # constitutes a breach. `_enforce_cost_caps` sits after ``_route()``
    # so at least a few microseconds have passed.
    broker._config.cost_caps = CostCapConfig(  # type: ignore[attr-defined]  # noqa: SLF001
        max_duration_seconds=0, enforcement="hard"
    )

    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db", rows=[{"id": 1}]),
                "internal_vulns": _FakeAdapter("internal_vulns", rows=[{"id": 2}]),
            },
        )
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())

        # Hard breach — no sources run, every decision becomes a cap_breached skip.
        assert not resp.sources_queried, (
            f"hard duration cap: no sources should run; got {resp.sources_queried!r}"
        )
        duration_skips = [
            s for s in resp.sources_skipped if s.startswith("cap_breached:max_duration_seconds")
        ]
        assert duration_skips, (
            f"sources_skipped must include cap_breached:max_duration_seconds marker(s); "
            f"got {resp.sources_skipped!r}"
        )
        assert resp.cap_breached is True, (
            f"BrokerResponse.cap_breached must be True on hard breach; got {resp.cap_breached!r}"
        )

        audit_file = tmp_path / "audit.jsonl"
        entries = _read_audit_entries(audit_file)
        cap_entries = [e for e in entries if e.event_type == "cap_breached"]
        assert len(cap_entries) >= 1, (
            f"duration breach must emit at least one cap_breached audit; got {len(cap_entries)}"
        )
    finally:
        await broker.aclose()


# ---------------------------------------------------------------------------
# Scenario 3: pre-flight LLM stub — AttributeError → soft-breach, pass through.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_preflight_llm_stub_passes_through_until_task_39(tmp_path: Path) -> None:
    """Pre-flight LLM branch is stubbed until :class:`LLMAdapter.estimate_cost` ships.

    ``max_tokens=100`` + ``enforcement="hard"`` on a source whose ``type``
    is monkey-patched to ``"llm"``. The installed fake adapter does not
    implement ``estimate_cost``; the broker catches the
    :class:`AttributeError`, emits a ``cap_breached`` audit with
    ``enforcement="soft"`` (the stub marker), logs a warning, and passes
    the decision through. Task 40 re-verifies this scenario with the
    real estimator wired.
    """
    broker = Broker.from_config(FIXTURE_PATH)
    nvd = next(s for s in broker.sources if s.id == "nvd_db")
    nvd.type = "llm"  # type: ignore[assignment]  # Task 39 extends the literal
    nvd.cost_caps = CostCapConfig(max_tokens=100, enforcement="hard")

    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db", rows=[{"id": 1}]),
                "internal_vulns": _FakeAdapter("internal_vulns", rows=[{"id": 2}]),
            },
        )
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())

        # Stub path: source still runs (pass-through).
        assert "nvd_db" in resp.sources_queried, (
            f"stub pre-flight LLM branch must pass through (Task 39 promotes this to a "
            f"functional skip); got sources_queried={resp.sources_queried!r}, "
            f"sources_skipped={resp.sources_skipped!r}"
        )

        audit_file = tmp_path / "audit.jsonl"
        entries = _read_audit_entries(audit_file)
        cap_entries = [e for e in entries if e.event_type == "cap_breached"]
        assert len(cap_entries) == 1, (
            f"stub must emit exactly one cap_breached audit; got {len(cap_entries)}"
        )
    finally:
        await broker.aclose()
