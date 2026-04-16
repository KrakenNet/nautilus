"""Canonical unit tests for :mod:`nautilus.forensics.handoff_worker` (Task 3.6).

Five cases pin the worker contract end-to-end on synthetic audit JSONL:

(a) Empty audit file => ``WorkerReport.records_emitted == 0`` (AC-5.1).
(b) 100-line synthetic audit with two shared-session events from distinct
    agents => exactly one :class:`InferredHandoff` survivor for the
    inferred triple (FR-11, AC-5.1).
(c) Re-run on the same audit + persisted offsets => 0 new records
    (NFR-13 / AC-5.5 — idempotent crash-restart).
(d) A ``handoff_declared`` entry within the audit window suppresses the
    inferred equivalent triple (AC-5.3 / D-20 declared-precedence dedup).
(e) Audit rotation (persisted offset > file size) => offset reset to 0
    with a ``WARNING`` log (AC-5.4 rotation guard).

Uses an in-memory :class:`MockSink` implementing the
:class:`nautilus.forensics.sinks.ForensicSink` Protocol; the JSONLSink and
HttpForensicSink paths are already pinned by ``test_sinks.py`` and the
Phase-2 smoke suite.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nautilus.core.models import AuditEntry, HandoffDecision, InferredHandoff
from nautilus.forensics.handoff_worker import WorkerReport, run_worker
from nautilus.forensics.offsets import ProcessedOffsets

# ---------------------------------------------------------------------------
# Helpers — synthetic audit line builder + in-memory sink
# ---------------------------------------------------------------------------


class MockSink:
    """In-memory :class:`ForensicSink` that collects emitted records.

    Satisfies the ``@runtime_checkable`` :class:`ForensicSink` Protocol so
    the worker can treat it as a drop-in for JSONL/HTTP sinks. ``close`` is
    idempotent by construction (no held resources).
    """

    def __init__(self) -> None:
        self.records: list[InferredHandoff] = []
        self.closed = False

    async def emit(self, record: InferredHandoff) -> None:
        self.records.append(record)

    async def close(self) -> None:
        self.closed = True


def _audit_line(
    *,
    timestamp: datetime,
    agent_id: str,
    request_id: str,
    session_id: str | None = "sess-1",
    event_type: str = "request",
    sources_queried: list[str] | None = None,
    handoff_id: str | None = None,
    handoff_decision: HandoffDecision | None = None,
) -> str:
    """Build one AuditEntry JSONL line for the synthetic audit fixture.

    Field shape mirrors the Phase-1 on-disk line at
    ``tests/fixtures/audit/phase1_audit_line.jsonl`` so tests exercise the
    real AuditEntry schema, not a lowest-common-denominator stub.
    """
    entry = AuditEntry(
        timestamp=timestamp,
        request_id=request_id,
        agent_id=agent_id,
        session_id=session_id,
        raw_intent="test intent",
        intent_analysis=None,
        facts_asserted_summary={},
        routing_decisions=[],
        scope_constraints=[],
        denial_records=[],
        error_records=[],
        rule_trace=[],
        sources_queried=sources_queried if sources_queried is not None else ["pg_vulns"],
        sources_denied=[],
        sources_skipped=[],
        sources_errored=[],
        attestation_token=None,
        duration_ms=5,
        event_type=event_type,  # type: ignore[arg-type]
        handoff_id=handoff_id,
        handoff_decision=handoff_decision,
    )
    return entry.model_dump_json()


def _write_audit(path: Path, lines: list[str]) -> None:
    """Write the given JSON lines as an audit JSONL file (LF-terminated)."""
    with path.open("w", encoding="utf-8", newline="") as fh:
        for line in lines:
            fh.write(line + "\n")


def _make_100_line_audit(target: Path) -> tuple[datetime, datetime]:
    """Build a 100-line synthetic audit with ONE shared-session pair.

    Lines 0..97 (98 lines): noise — distinct session per line, single agent.
    Line 98: ``alice`` on ``sess-shared`` querying ``pg_vulns``.
    Line 99: ``bob`` on ``sess-shared`` querying ``pg_vulns``.

    The two shared-session lines at the end are the ONLY pair that should
    trigger the ``inferred_handoff`` rule — noise lines carry distinct
    session_ids so the h-shared-session heuristic cannot join across them.
    """
    t0 = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    lines: list[str] = []
    for i in range(98):
        # Distinct session per noise line — no joins across the noise block.
        lines.append(
            _audit_line(
                timestamp=t0 + timedelta(seconds=i),
                agent_id=f"noise-{i % 5}",
                request_id=f"r-noise-{i:03d}",
                session_id=f"sess-noise-{i:03d}",
                sources_queried=["noise_source"],
            )
        )
    t_alice = t0 + timedelta(seconds=200)
    t_bob = t0 + timedelta(seconds=210)
    lines.append(
        _audit_line(
            timestamp=t_alice,
            agent_id="alice",
            request_id="r-alice",
            session_id="sess-shared",
            sources_queried=["pg_vulns"],
        )
    )
    lines.append(
        _audit_line(
            timestamp=t_bob,
            agent_id="bob",
            request_id="r-bob",
            session_id="sess-shared",
            sources_queried=["pg_vulns"],
        )
    )
    assert len(lines) == 100
    _write_audit(target, lines)
    return t_alice, t_bob


# ---------------------------------------------------------------------------
# (a) Empty audit file => 0 records
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_empty_audit_emits_zero_records(tmp_path: Path) -> None:
    """An empty audit file => ``lines_processed == records_emitted == 0``."""
    audit = tmp_path / "audit.jsonl"
    audit.write_text("", encoding="utf-8")
    offsets = tmp_path / "offsets.json"

    sink = MockSink()
    report = await run_worker(audit, offsets, sink, window_s=3600)

    assert isinstance(report, WorkerReport)
    assert report.lines_processed == 0
    assert report.records_emitted == 0
    assert report.new_offset == 0
    assert sink.records == []
    # The worker does not close the sink — the caller owns lifecycle.
    assert sink.closed is False


# ---------------------------------------------------------------------------
# (b) 100-line audit with one shared-session pair => 1 InferredHandoff
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_100_line_audit_with_shared_session_emits_one_inferred(
    tmp_path: Path,
) -> None:
    """Exactly one ``(sess-shared, alice/bob)`` :class:`InferredHandoff` survives.

    With 98 unique-session noise lines surrounding a single shared-session
    pair, only that pair can join under the h-shared-session heuristic.
    The aggregator collapses per-signal contributions into one record per
    ``(session, source, receiver)`` triple — so the surviving output is
    exactly one record for ``sess-shared``.
    """
    audit = tmp_path / "audit.jsonl"
    offsets = tmp_path / "offsets.json"
    _make_100_line_audit(audit)

    sink = MockSink()
    report = await run_worker(audit, offsets, sink, window_s=3600)

    assert report.lines_processed == 100
    # Exactly one record for the shared-session pair.
    shared = [r for r in sink.records if r.session_id == "sess-shared"]
    assert len(shared) == 1
    rec = shared[0]
    assert {rec.source_agent, rec.receiving_agent} == {"alice", "bob"}
    assert rec.source_agent != rec.receiving_agent
    assert 0.0 < rec.confidence <= 1.0
    assert "shared-session" in rec.signals or rec.signals  # signals are non-empty
    # No spurious cross-session inferences from the noise block.
    noise = [r for r in sink.records if r.session_id != "sess-shared"]
    assert noise == []


# ---------------------------------------------------------------------------
# (c) Re-run on same audit + offsets => 0 new records (NFR-13 / AC-5.5)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_second_run_emits_zero_new_records(tmp_path: Path) -> None:
    """Two consecutive runs over the same audit: second run emits nothing.

    The first run advances ``last_byte_offset`` to EOF and records each
    line's SHA-256; the second run seeks to that offset (nothing new
    to read) AND every line it would re-read is already in the seen set.
    Both belt-and-braces guards must hold — either alone is enough, but
    the contract is "zero new emissions on replay" (NFR-13).
    """
    audit = tmp_path / "audit.jsonl"
    offsets = tmp_path / "offsets.json"
    _make_100_line_audit(audit)

    first_sink = MockSink()
    first = await run_worker(audit, offsets, first_sink, window_s=3600)
    assert first.records_emitted >= 1
    first_offset = first.new_offset
    assert first_offset == audit.stat().st_size

    # Second invocation on the same audit + persisted offsets.
    second_sink = MockSink()
    second = await run_worker(audit, offsets, second_sink, window_s=3600)

    assert second.lines_processed == 0
    assert second.records_emitted == 0
    assert second.new_offset == first_offset
    assert second_sink.records == []


# ---------------------------------------------------------------------------
# (d) Declared handoff in same audit => inferred triple dropped (AC-5.3)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_declared_handoff_within_window_suppresses_inferred(
    tmp_path: Path,
) -> None:
    """AC-5.3 / D-20: a declared handoff dominates the inferred equivalent.

    Key shape (see ``_declared_key`` in ``handoff_worker.py``):
    ``(session_id, entry.agent_id, decision.handoff_id)``. A declared
    entry authored by ``alice`` with ``handoff_id="bob"`` maps to the
    inferred triple ``(sess-shared, alice, bob)``. That triple MUST NOT
    appear in the surviving emits even though the rule pack would
    otherwise fire on the alice→bob shared-session pair.
    """
    audit = tmp_path / "audit.jsonl"
    offsets = tmp_path / "offsets.json"

    t0 = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=10)
    t2 = t0 + timedelta(seconds=20)

    _write_audit(
        audit,
        [
            _audit_line(
                timestamp=t0,
                agent_id="alice",
                request_id="r-1",
                session_id="sess-shared",
                sources_queried=["pg_vulns"],
            ),
            _audit_line(
                timestamp=t1,
                agent_id="bob",
                request_id="r-2",
                session_id="sess-shared",
                sources_queried=["pg_vulns"],
            ),
            _audit_line(
                timestamp=t2,
                agent_id="alice",
                request_id="r-3",
                session_id="sess-shared",
                event_type="handoff_declared",
                handoff_id="bob",
                handoff_decision=HandoffDecision(handoff_id="bob", action="allow"),
            ),
        ],
    )

    sink = MockSink()
    report = await run_worker(audit, offsets, sink, window_s=3600)

    assert report.lines_processed == 3
    # The (sess-shared, alice, bob) triple is suppressed.
    triples = {(r.session_id, r.source_agent, r.receiving_agent) for r in sink.records}
    assert ("sess-shared", "alice", "bob") not in triples


# ---------------------------------------------------------------------------
# (e) Audit rotation: offset > file size => reset to 0 + WARN (AC-5.4)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_rotation_resets_offset_to_zero_and_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Persisted offset > file size => reset to 0 + WARN; lines re-processed.

    Simulates log rotation: the on-disk ``last_byte_offset`` greatly
    exceeds the current audit file size, so the worker cannot honour
    that offset without skipping past the whole file. The intended
    recovery path is to reset the offset to 0, emit one WARN, and
    process from the top of the (post-rotation) file.
    """
    audit = tmp_path / "audit.jsonl"
    offsets_path = tmp_path / "offsets.json"

    # Pre-persist an offset far beyond any audit we'd build in this test.
    ProcessedOffsets(last_byte_offset=10**9).save(offsets_path)

    t0 = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=10)
    _write_audit(
        audit,
        [
            _audit_line(
                timestamp=t0,
                agent_id="alice",
                request_id="r-1",
                session_id="sess-shared",
                sources_queried=["pg_vulns"],
            ),
            _audit_line(
                timestamp=t1,
                agent_id="bob",
                request_id="r-2",
                session_id="sess-shared",
                sources_queried=["pg_vulns"],
            ),
        ],
    )

    sink = MockSink()
    with caplog.at_level("WARNING"):
        report = await run_worker(audit, offsets_path, sink, window_s=3600)

    # Reset is the recovery path — both lines are freshly processed.
    assert report.lines_processed == 2
    warn_records = [
        r for r in caplog.records if "handoff_worker" in r.message and "truncated" in r.message
    ]
    assert len(warn_records) == 1

    # Post-run offset reflects the post-rotation file size (reset happened).
    reloaded = ProcessedOffsets.load(offsets_path)
    assert reloaded.last_byte_offset == report.new_offset
    assert report.new_offset == audit.stat().st_size
