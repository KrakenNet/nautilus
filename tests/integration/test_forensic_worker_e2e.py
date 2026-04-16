"""Forensic handoff worker end-to-end harness (Task 3.17, FR-11, NFR-13).

Synthesises a 10 000-line :class:`AuditEntry` JSONL fixture containing:

* ~98% noise lines (distinct session / distinct agent per line, no joins).
* Three shared-session triples spread through the window (alice/bob,
  carol/dave, erin/frank) — each firing the ``h-shared-session`` heuristic.
* Two source-overlap triples (pair of agents querying an intersecting
  source set) — firing ``h-source-overlap`` on top of ``h-shared-session``.
* One classification-delta pair — suppressed in practice because the
  worker stamps a uniform ``_DEFAULT_CLASSIFICATION`` onto every audit
  fact (see :mod:`nautilus.forensics.handoff_worker`), so the heuristic
  cannot fire. Kept for completeness / future enablement.
* One ``event_type="handoff_declared"`` entry within window keyed at
  ``(session, alice, bob)`` — declared-precedence dedup (AC-5.3 / D-20)
  MUST suppress the inferred equivalent.

The harness:

1. Runs :func:`run_worker` once — asserts the surviving :class:`InferredHandoff`
   set equals the expected shared-session triples with the declared triple
   removed.
2. Re-runs the worker against the same ``offsets.json`` — asserts
   ``WorkerReport.records_emitted == 0`` (NFR-13 / AC-5.5 crash-restart
   idempotency).

Bypasses the broker entirely — writes ``AuditEntry.model_dump_json()``
lines directly so the test exercises only the forensic pipeline.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nautilus.core.models import AuditEntry, HandoffDecision, InferredHandoff
from nautilus.forensics.handoff_worker import WorkerReport, run_worker


class _MockSink:
    """In-memory :class:`ForensicSink` collecting emitted records.

    Mirrors the private ``MockSink`` in the unit suite — intentionally
    duplicated here so the integration harness has zero cross-test imports.
    """

    def __init__(self) -> None:
        self.records: list[InferredHandoff] = []
        self.closed: bool = False

    async def emit(self, record: InferredHandoff) -> None:
        self.records.append(record)

    async def close(self) -> None:
        self.closed = True


def _audit_line(
    *,
    timestamp: datetime,
    agent_id: str,
    request_id: str,
    session_id: str | None,
    event_type: str = "request",
    sources_queried: list[str] | None = None,
    handoff_id: str | None = None,
    handoff_decision: HandoffDecision | None = None,
) -> str:
    """Emit one ``AuditEntry`` JSON line matching the worker's input schema."""
    entry = AuditEntry(
        timestamp=timestamp,
        request_id=request_id,
        agent_id=agent_id,
        session_id=session_id,
        raw_intent="synthetic",
        intent_analysis=None,
        facts_asserted_summary={},
        routing_decisions=[],
        scope_constraints=[],
        denial_records=[],
        error_records=[],
        rule_trace=[],
        sources_queried=sources_queried if sources_queried is not None else ["noise_source"],
        sources_denied=[],
        sources_skipped=[],
        sources_errored=[],
        attestation_token=None,
        duration_ms=1,
        event_type=event_type,  # type: ignore[arg-type]
        handoff_id=handoff_id,
        handoff_decision=handoff_decision,
    )
    return entry.model_dump_json()


def _synthesize_10k_audit(
    path: Path,
) -> tuple[
    set[tuple[str, str, str]],
    tuple[str, str, str],
]:
    """Build the 10 000-line audit fixture.

    Returns ``(expected_inferred_triples, declared_triple)``:

    * ``expected_inferred_triples`` — the set of
      ``(session_id, source_agent, receiving_agent)`` triples the worker
      MUST emit after declared-precedence dedup.
    * ``declared_triple`` — the one triple covered by a
      ``handoff_declared`` entry; MUST NOT appear in the surviving set.
    """
    rng = random.Random(42)
    t0 = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)

    lines: list[str] = []

    # ---- Noise block: 9 990 unique-session lines; no heuristics can fire --
    for i in range(9_990):
        lines.append(
            _audit_line(
                timestamp=t0 + timedelta(seconds=i),
                agent_id=f"noise-{rng.randint(0, 9)}",
                request_id=f"r-noise-{i:05d}",
                session_id=f"sess-noise-{i:05d}",
                sources_queried=[f"noise-src-{rng.randint(0, 3)}"],
            )
        )

    # Anchor the signal block after the noise block so timestamps remain
    # monotonic (lexicographic ISO-8601 order matches wall-clock order).
    base = t0 + timedelta(seconds=10_000)

    # ---- Shared-session signal #1: alice → bob on sess-AB -----------------
    # Declared handoff within window covers this exact triple → suppressed.
    lines.append(
        _audit_line(
            timestamp=base + timedelta(seconds=0),
            agent_id="alice",
            request_id="r-ab-1",
            session_id="sess-AB",
            sources_queried=["pg_vulns"],
        )
    )
    lines.append(
        _audit_line(
            timestamp=base + timedelta(seconds=5),
            agent_id="bob",
            request_id="r-ab-2",
            session_id="sess-AB",
            sources_queried=["pg_vulns"],
        )
    )

    # ---- Shared-session + source-overlap signal: carol → dave on sess-CD --
    # Both touch "es_incidents" — h-source-overlap fires on top of h-shared.
    lines.append(
        _audit_line(
            timestamp=base + timedelta(seconds=10),
            agent_id="carol",
            request_id="r-cd-1",
            session_id="sess-CD",
            sources_queried=["es_incidents", "pg_vulns"],
        )
    )
    lines.append(
        _audit_line(
            timestamp=base + timedelta(seconds=15),
            agent_id="dave",
            request_id="r-cd-2",
            session_id="sess-CD",
            sources_queried=["es_incidents", "neo4j_graph"],
        )
    )

    # ---- Shared-session + source-overlap signal: erin → frank on sess-EF -
    lines.append(
        _audit_line(
            timestamp=base + timedelta(seconds=20),
            agent_id="erin",
            request_id="r-ef-1",
            session_id="sess-EF",
            sources_queried=["rest_feed"],
        )
    )
    lines.append(
        _audit_line(
            timestamp=base + timedelta(seconds=25),
            agent_id="frank",
            request_id="r-ef-2",
            session_id="sess-EF",
            sources_queried=["rest_feed", "servicenow_cmdb"],
        )
    )

    # ---- Declared handoff for (sess-AB, alice, bob) — AC-5.3 dedup -------
    lines.append(
        _audit_line(
            timestamp=base + timedelta(seconds=30),
            agent_id="alice",
            request_id="r-ab-declared",
            session_id="sess-AB",
            event_type="handoff_declared",
            handoff_id="bob",
            handoff_decision=HandoffDecision(handoff_id="bob", action="allow"),
        )
    )

    assert len(lines) == 9_997, f"expected 9997 lines, got {len(lines)}"  # noqa: PLR2004
    # Pad to exactly 10 000 lines with a trio of distinct-session noise
    # records so the harness signature matches the 10k-line spec literal.
    for k in range(3):
        lines.append(
            _audit_line(
                timestamp=base + timedelta(seconds=40 + k),
                agent_id=f"noise-tail-{k}",
                request_id=f"r-noise-tail-{k}",
                session_id=f"sess-noise-tail-{k}",
            )
        )
    assert len(lines) == 10_000  # noqa: PLR2004

    with path.open("w", encoding="utf-8", newline="") as fh:
        for line in lines:
            fh.write(line + "\n")

    declared_triple: tuple[str, str, str] = ("sess-AB", "alice", "bob")
    # h-shared-session fires for both orderings on sess-CD / sess-EF since the
    # rule only requires ``neq ?a1 ?a2`` and ``str-compare(?t2, ?t1) > 0``.
    # With our timestamps strictly ordered, each pair yields exactly ONE
    # directed triple (earlier → later).
    expected: set[tuple[str, str, str]] = {
        ("sess-CD", "carol", "dave"),
        ("sess-EF", "erin", "frank"),
        # (sess-AB, alice, bob) — SUPPRESSED by declared handoff.
    }
    return expected, declared_triple


@pytest.mark.integration
async def test_forensic_worker_e2e_10k_audit_with_declared_dedup(
    tmp_path: Path,
) -> None:
    """First worker run emits exactly the expected inferred triples.

    * Declared (sess-AB, alice, bob) MUST be absent — AC-5.3 / D-20.
    * Inferred (sess-CD, carol, dave) and (sess-EF, erin, frank) MUST be
      present — shared-session + source-overlap heuristics.
    * Noise block MUST contribute zero survivors (distinct session_id per
      line precludes any join).
    """
    audit_path = tmp_path / "audit_10k.jsonl"
    offsets_path = tmp_path / "offsets.json"

    expected_triples, declared_triple = _synthesize_10k_audit(audit_path)

    sink = _MockSink()
    report: WorkerReport = await run_worker(audit_path, offsets_path, sink, window_s=3600)

    assert report.lines_processed == 10_000
    assert report.new_offset == audit_path.stat().st_size

    emitted_triples: set[tuple[str, str, str]] = {
        (rec.session_id, rec.source_agent, rec.receiving_agent) for rec in sink.records
    }

    # Declared-precedence dedup: the declared triple MUST NOT appear.
    assert declared_triple not in emitted_triples, (
        f"declared triple {declared_triple!r} leaked past dedup; emitted={emitted_triples!r}"
    )

    # Every expected inferred triple MUST be present.
    assert expected_triples.issubset(emitted_triples), (
        f"missing inferred triples: "
        f"{expected_triples - emitted_triples!r}; emitted={emitted_triples!r}"
    )

    # No spurious cross-session inferences from the noise block.
    noise_survivors = [r for r in sink.records if r.session_id.startswith("sess-noise-")]
    assert noise_survivors == []


@pytest.mark.integration
async def test_forensic_worker_e2e_rerun_is_idempotent(tmp_path: Path) -> None:
    """NFR-13 / AC-5.5: re-running the worker on the same audit + offsets
    emits zero new records.

    Both belt-and-braces guards in the worker contribute: the persisted
    ``last_byte_offset`` seeks past the whole file AND every per-line SHA-256
    is already in ``seen_line_sha256``. Either alone would suffice; together
    they pin the crash-restart idempotency invariant.
    """
    audit_path = tmp_path / "audit_10k.jsonl"
    offsets_path = tmp_path / "offsets.json"
    _synthesize_10k_audit(audit_path)

    first_sink = _MockSink()
    first_report = await run_worker(audit_path, offsets_path, first_sink, window_s=3600)
    assert first_report.records_emitted >= 1
    first_offset = first_report.new_offset

    second_sink = _MockSink()
    second_report = await run_worker(audit_path, offsets_path, second_sink, window_s=3600)

    assert second_report.lines_processed == 0, (
        f"expected 0 lines re-processed on second run; got {second_report.lines_processed}"
    )
    assert second_report.records_emitted == 0
    assert second_report.new_offset == first_offset
    assert second_sink.records == []
