"""Source-state end-to-end integration tests (Task 16, US-3, AC-3.10).

Exercises the full US-3 operator enable/disable flow against a real
``pgvector/pgvector:pg17`` Postgres container via the session-scoped
``pg_container`` fixture (see :mod:`tests.conftest`). The scenario walks
AC-3.10's five checkpoints in order:

1. Baseline ``broker.arequest()`` — both sources queried, ``sources_queried``
   carries both ids, ``sources_skipped`` has no ``source_disabled:`` prefix.
2. Mid-flight disable of both sources via
   :meth:`SourceStateStore.set_enabled` (simulates a running-broker operator
   action; the transport/CLI routes wrap the same call).
3. Subsequent ``broker.arequest()`` — both disabled sources appear in
   ``sources_skipped`` with the ``source_disabled:`` prefix; no adapter
   connection is attempted (FR-29 / AC-3.7).
4. Broker restart (``aclose`` + fresh :meth:`Broker.from_config`) — the
   second broker re-reads state from Postgres and a new request still
   routes zero sources. Proves the DDL row survives process lifecycle.
5. Re-enable both sources via :meth:`SourceStateStore.set_enabled` on the
   second broker; a final ``broker.arequest()`` queries both sources again.

The audit assertion pins four ``source_state_changed`` entries in strict
chronological order (AC-3.10, AC-3.8, FR-40, FR-59): two disables before
the restart, two re-enables after. Each entry is parsed out of the JSONL
audit file via the same envelope helper the other integration tests use
(``metadata[NAUTILUS_METADATA_KEY]``).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.core.broker import Broker
from nautilus.core.models import AuditEntry
from nautilus.core.source_state import SourceStateStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_pg_source_state_config(tmp_path: Path) -> Path:
    """Emit a ``nautilus.yaml`` wiring both sources + a Postgres session store.

    The :meth:`Broker._build_source_state_store` factory only constructs a
    :class:`SourceStateStore` when ``session_store.backend == "postgres"``
    (AC-3.3 — memory backends degrade loudly and US-3 routing skips the
    whole store). The test needs the primary path so AC-3.10's "state
    still applies after restart" checkpoint exercises the real row.
    """
    config: dict[str, Any] = {
        "sources": [
            {
                "id": "nvd_db",
                "type": "postgres",
                "description": "National Vulnerability Database mirror (test fixture)",
                "classification": "unclassified",
                "data_types": ["cve", "vulnerability", "patch"],
                "allowed_purposes": ["threat-analysis", "incident-response"],
                "connection": "${TEST_PG_DSN}",
                "table": "vulns",
            },
            {
                "id": "internal_vulns",
                "type": "pgvector",
                "description": "Internal vulnerability embeddings (test fixture)",
                "classification": "unclassified",
                "data_types": ["vulnerability", "scan_result"],
                "allowed_purposes": ["threat-analysis"],
                "connection": "${TEST_PGV_DSN}",
                "table": "vuln_embeddings",
                "embedding_column": "embedding",
                "metadata_column": "metadata",
                "distance_operator": "<=>",
                "top_k": 10,
            },
        ],
        "rules": {"user_rules_dirs": []},
        "analysis": {
            "keyword_map": {
                "vulnerability": ["vulnerability", "vuln", "weakness"],
                "patch": ["patch", "fix", "update"],
                "asset": ["asset", "system", "host", "server"],
            }
        },
        "audit": {"path": "./audit.jsonl"},
        "attestation": {"enabled": True},
        "session_store": {"backend": "postgres", "on_failure": "fail_closed"},
    }
    config_path = tmp_path / "nautilus.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return config_path


def _read_audit_entries(audit_file: Path) -> list[AuditEntry]:
    """Parse every :class:`AuditEntry` from the JSONL file in write order."""
    entries: list[AuditEntry] = []
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record: dict[str, Any] = json.loads(line)
        entry_json = record["metadata"][NAUTILUS_METADATA_KEY]
        entries.append(AuditEntry.model_validate_json(entry_json))
    return entries


_CONTEXT: dict[str, Any] = {
    "clearance": "unclassified",
    "purpose": "threat-analysis",
    "session_id": "sess-src-state",
    "embedding": [0.1, 0.2, 0.3],
}


# ---------------------------------------------------------------------------
# AC-3.10 — full disable / restart / re-enable scenario against real Postgres.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_source_state_disable_restart_reenable_emits_four_audits_in_order(
    pg_container: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full US-3 flow — disable, restart, re-enable, four audits in order.

    Broker #1 issues a baseline request (both sources queried), disables
    both sources mid-flight, then re-requests (both skipped with
    ``source_disabled:`` prefix). It closes, a fresh Broker #2 boots, a
    third request still routes zero sources (persistence across process
    restart), and finally the second broker re-enables both sources; the
    fourth request queries both sources again.

    AC-3.10 final pin: the audit JSONL carries exactly four
    ``source_state_changed`` entries, in the order
    ``(nvd_db, False) → (internal_vulns, False) → (nvd_db, True) →
    (internal_vulns, True)``, with strictly non-decreasing timestamps.
    """
    del pg_container  # side-effect: container booted, env vars exported
    monkeypatch.chdir(tmp_path)

    config_path = _write_pg_source_state_config(tmp_path)

    # --- Broker #1 ---------------------------------------------------------
    broker_one = Broker.from_config(config_path)
    assert isinstance(broker_one._source_state_store, SourceStateStore), (  # pyright: ignore[reportPrivateUsage]
        "Broker.from_config did not wire a SourceStateStore; US-3 routing "
        "gate cannot be exercised without the primary Postgres path"
    )

    async def _phase_one() -> tuple[Any, Any]:
        """Baseline + disable both + re-request; all in one event loop."""
        await broker_one.setup()

        # (1) Baseline — both sources queried, none skipped as ``source_disabled:``.
        # Intent mentions ``vulnerability`` so the Phase-1 keyword_map
        # matches both fixture sources (data_types include ``vulnerability``).
        baseline = await broker_one.arequest(
            "agent-alpha", "Find vulnerabilities for CVE-2026-0010", _CONTEXT
        )

        # (2) Operator disables both sources mid-flight — mirrors the
        # transport POST and the CLI subcommand, which both call
        # ``SourceStateStore.set_enabled`` under the hood (FR-50 / AC-3.4).
        store = broker_one._source_state_store  # pyright: ignore[reportPrivateUsage]
        assert store is not None
        await store.set_enabled(
            "nvd_db", enabled=False, reason="rotating credentials", actor="tester"
        )
        await store.set_enabled(
            "internal_vulns", enabled=False, reason="maintenance window", actor="tester"
        )

        # (3) Subsequent request — both disabled ids surface under
        # ``sources_skipped`` with the ``source_disabled:`` prefix; no
        # adapter queried (AC-3.7).
        disabled = await broker_one.arequest(
            "agent-alpha", "Find vulnerabilities for CVE-2026-0011", _CONTEXT
        )

        await broker_one.aclose()
        return baseline, disabled

    baseline_resp, disabled_resp = asyncio.run(_phase_one())

    # --- Baseline assertions ----------------------------------------------
    assert set(baseline_resp.sources_queried) == {"nvd_db", "internal_vulns"}, (
        f"baseline must query both sources; got {baseline_resp.sources_queried!r}"
    )
    baseline_disabled_prefixes = [
        s for s in baseline_resp.sources_skipped if s.startswith("source_disabled:")
    ]
    assert not baseline_disabled_prefixes, (
        "baseline request (before any disable) must NOT carry a "
        f"source_disabled: skip; got {baseline_resp.sources_skipped!r}"
    )

    # --- Post-disable assertions ------------------------------------------
    assert not disabled_resp.sources_queried, (
        f"all sources disabled → sources_queried must be empty; "
        f"got {disabled_resp.sources_queried!r}"
    )
    assert set(disabled_resp.sources_skipped) >= {
        "source_disabled:nvd_db",
        "source_disabled:internal_vulns",
    }, (
        f"both ids must appear with the source_disabled: prefix; "
        f"got {disabled_resp.sources_skipped!r}"
    )

    # --- Broker #2 ---------------------------------------------------------
    broker_two = Broker.from_config(config_path)
    assert isinstance(broker_two._source_state_store, SourceStateStore)  # pyright: ignore[reportPrivateUsage]

    async def _phase_two() -> tuple[Any, Any]:
        """Restart: state still applies; re-enable both; state restored."""
        await broker_two.setup()

        # (4a) Persistence checkpoint — broker #2 never called
        # ``set_enabled``; the two rows written by broker #1 must be loaded
        # by ``SourceStateStore.load_all`` at the top of ``arequest``, so
        # both sources are still skipped. Proves AC-3.10 "broker restarts
        # and state still applies".
        restarted = await broker_two.arequest(
            "agent-alpha", "Find vulnerabilities for CVE-2026-0012", _CONTEXT
        )

        # (4b) Operator re-enables both sources via the SAME API path the
        # CLI/transport use. Reason is ``None`` on re-enable per the
        # contract in the docstring of :meth:`SourceStateStore.set_enabled`.
        store_two = broker_two._source_state_store  # pyright: ignore[reportPrivateUsage]
        assert store_two is not None
        await store_two.set_enabled("nvd_db", enabled=True, reason=None, actor="tester")
        await store_two.set_enabled("internal_vulns", enabled=True, reason=None, actor="tester")

        # (5) Final request — both sources routed again.
        restored = await broker_two.arequest(
            "agent-alpha", "Find vulnerabilities for CVE-2026-0013", _CONTEXT
        )

        await broker_two.aclose()
        return restarted, restored

    restarted_resp, restored_resp = asyncio.run(_phase_two())

    # --- Restart assertions (state persisted across process) --------------
    assert not restarted_resp.sources_queried, (
        "post-restart request: state must persist across broker restart; "
        f"sources_queried={restarted_resp.sources_queried!r}"
    )
    assert set(restarted_resp.sources_skipped) >= {
        "source_disabled:nvd_db",
        "source_disabled:internal_vulns",
    }, (
        "post-restart request: disabled ids must still surface under "
        f"sources_skipped; got {restarted_resp.sources_skipped!r}"
    )

    # --- Re-enable assertions ---------------------------------------------
    assert set(restored_resp.sources_queried) == {"nvd_db", "internal_vulns"}, (
        "post-reenable request: both sources must route again; "
        f"got sources_queried={restored_resp.sources_queried!r}"
    )
    restored_disabled_prefixes = [
        s for s in restored_resp.sources_skipped if s.startswith("source_disabled:")
    ]
    assert not restored_disabled_prefixes, (
        "post-reenable request must NOT carry any source_disabled: prefix; "
        f"got {restored_resp.sources_skipped!r}"
    )

    # ------------------------------------------------------------------
    # AC-3.10 final pin — exactly four ``source_state_changed`` audits,
    # in chronological order, one per :meth:`set_enabled` call.
    # ------------------------------------------------------------------
    audit_file = tmp_path / "audit.jsonl"
    assert audit_file.exists(), f"audit file missing at {audit_file}"

    entries = _read_audit_entries(audit_file)
    state_events = [e for e in entries if e.event_type == "source_state_changed"]

    assert len(state_events) == 4, (
        f"AC-3.10 requires exactly four source_state_changed audit entries; "
        f"got {len(state_events)}: {[(e.sources_queried, e.agent_id) for e in state_events]!r}"
    )

    # Order-and-shape pin — each ``set_enabled`` call stamps the source id
    # onto ``sources_queried`` and the actor onto ``agent_id`` (see
    # :meth:`SourceStateStore._emit_state_changed_audit`).
    expected_order: list[str] = [
        "nvd_db",  # disable #1
        "internal_vulns",  # disable #2
        "nvd_db",  # re-enable #1
        "internal_vulns",  # re-enable #2
    ]
    observed_order = [e.sources_queried[0] for e in state_events]
    assert observed_order == expected_order, (
        f"source_state_changed audits out of order; expected {expected_order!r}, "
        f"got {observed_order!r}"
    )

    # Timestamps strictly non-decreasing — proves chronological write order.
    timestamps = [e.timestamp for e in state_events]
    assert timestamps == sorted(timestamps), (
        f"source_state_changed timestamps not in chronological order: {timestamps!r}"
    )

    # Actor round-trips to ``agent_id`` on every emit (FR-40).
    assert all(e.agent_id == "tester" for e in state_events), (
        f"actor='tester' must round-trip to audit agent_id; got "
        f"{[e.agent_id for e in state_events]!r}"
    )
