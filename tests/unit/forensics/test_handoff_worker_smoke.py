"""Smoke coverage for :mod:`nautilus.forensics.handoff_worker` (VERIFY 2.24 bridge).

Exercises the offline forensic handoff worker end-to-end on synthetic audit
JSONL so the `[VERIFY] 2.24` gate clears the 80% branch-coverage floor. No
real network is touched; :class:`httpx.MockTransport` stands in for the
HttpForensicSink receiver on the CLI dispatch test.

Locked behavior (design §3.7, FR-11, FR-33, AC-5.1/3/4/5):

- Module exports :func:`run_worker` + :class:`WorkerReport`.
- :class:`WorkerReport` is a valid Pydantic V2 model.
- Happy path: 2 audit lines for the same session with distinct agents =>
  at least one :class:`InferredHandoff` record emitted.
- Idempotency: second invocation on the same audit + offsets => 0 lines
  processed, 0 records emitted (AC-5.5).
- Rotation guard: persisted offset > file size => reset to 0 + WARN (AC-5.4).
- Declared-precedence dedup: ``handoff_declared`` key matches an inferred
  triple => that triple is suppressed (AC-5.3, D-20).
- CLI: ``_parse_args`` + ``_cli_main`` drive a full JSONL sink run to
  exit code 0; HTTP ``--out`` URL dispatches to :class:`HttpForensicSink`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from nautilus.core.models import AuditEntry, HandoffDecision, InferredHandoff
from nautilus.forensics import handoff_worker
from nautilus.forensics.handoff_worker import (
    WorkerReport,
    _build_sink,  # pyright: ignore[reportPrivateUsage]
    _cli_main,  # pyright: ignore[reportPrivateUsage]
    _parse_args,  # pyright: ignore[reportPrivateUsage]
    run_worker,
)
from nautilus.forensics.offsets import ProcessedOffsets
from nautilus.forensics.sinks import (
    ForensicSink,
    HttpForensicSink,
    JSONLForensicSink,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _audit_line(
    *,
    timestamp: datetime,
    agent_id: str,
    request_id: str,
    session_id: str = "sess-1",
    event_type: str = "request",
    sources_queried: list[str] | None = None,
    handoff_id: str | None = None,
    handoff_decision: HandoffDecision | None = None,
) -> str:
    """Build a single AuditEntry JSONL line for the fixture audit file."""
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
    with path.open("w", encoding="utf-8", newline="") as fh:
        for line in lines:
            fh.write(line + "\n")


# ---------------------------------------------------------------------------
# Import + model smoke
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_module_exports_run_worker_and_report() -> None:
    """Public surface: ``run_worker`` + ``WorkerReport`` are re-exported."""
    assert callable(run_worker)
    assert WorkerReport.__name__ == "WorkerReport"
    assert "run_worker" in handoff_worker.__all__
    assert "WorkerReport" in handoff_worker.__all__


@pytest.mark.unit
def test_worker_report_is_pydantic_v2_valid() -> None:
    """``WorkerReport`` parses via ``model_validate`` and round-trips."""
    report = WorkerReport.model_validate(
        {"lines_processed": 7, "records_emitted": 2, "new_offset": 1234}
    )
    assert report.lines_processed == 7
    assert report.records_emitted == 2
    assert report.new_offset == 1234
    # Round-trip through JSON.
    parsed = WorkerReport.model_validate_json(report.model_dump_json())
    assert parsed == report


# ---------------------------------------------------------------------------
# Happy path + idempotency
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_happy_path_emits_at_least_one_inferred(tmp_path: Path) -> None:
    """Two distinct agents on one session => engine fires => >= 1 emit."""
    audit = tmp_path / "audit.jsonl"
    offsets = tmp_path / "offsets.json"
    out = tmp_path / "out.jsonl"

    t0 = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=10)
    _write_audit(
        audit,
        [
            _audit_line(timestamp=t0, agent_id="alice", request_id="r-1"),
            _audit_line(timestamp=t1, agent_id="bob", request_id="r-2"),
        ],
    )

    sink = JSONLForensicSink(out)
    try:
        report = await run_worker(audit, offsets, sink, window_s=3600)
    finally:
        await sink.close()

    assert report.lines_processed == 2
    assert report.records_emitted >= 1
    assert report.new_offset > 0

    emitted_lines = out.read_text(encoding="utf-8").splitlines()
    assert len(emitted_lines) >= 1
    # Each emitted line must parse as :class:`InferredHandoff`.
    for raw in emitted_lines:
        rec = InferredHandoff.model_validate_json(raw)
        assert rec.session_id == "sess-1"
        assert rec.source_agent in {"alice", "bob"}
        assert rec.receiving_agent in {"alice", "bob"}
        assert rec.source_agent != rec.receiving_agent


@pytest.mark.unit
async def test_second_run_is_idempotent(tmp_path: Path) -> None:
    """AC-5.5: second run on identical audit + offsets => 0 lines, 0 emits."""
    audit = tmp_path / "audit.jsonl"
    offsets = tmp_path / "offsets.json"
    out = tmp_path / "out.jsonl"

    t0 = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=10)
    _write_audit(
        audit,
        [
            _audit_line(timestamp=t0, agent_id="alice", request_id="r-1"),
            _audit_line(timestamp=t1, agent_id="bob", request_id="r-2"),
        ],
    )

    first = JSONLForensicSink(out)
    try:
        first_report = await run_worker(audit, offsets, first, window_s=3600)
    finally:
        await first.close()
    assert first_report.lines_processed == 2

    second = JSONLForensicSink(out)
    try:
        second_report = await run_worker(audit, offsets, second, window_s=3600)
    finally:
        await second.close()

    assert second_report.lines_processed == 0
    assert second_report.records_emitted == 0
    assert second_report.new_offset == first_report.new_offset


# ---------------------------------------------------------------------------
# Rotation guard (AC-5.4)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_rotation_resets_offset_and_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Persisted offset > file size => reset to 0 + WARN; lines re-processed."""
    audit = tmp_path / "audit.jsonl"
    offsets_path = tmp_path / "offsets.json"
    out = tmp_path / "out.jsonl"

    # Pre-write a wildly-large offset to simulate a post-rotation state.
    ProcessedOffsets(last_byte_offset=10**9).save(offsets_path)

    t0 = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=10)
    _write_audit(
        audit,
        [
            _audit_line(timestamp=t0, agent_id="alice", request_id="r-1"),
            _audit_line(timestamp=t1, agent_id="bob", request_id="r-2"),
        ],
    )

    sink = JSONLForensicSink(out)
    try:
        with caplog.at_level("WARNING"):
            report = await run_worker(audit, offsets_path, sink, window_s=3600)
    finally:
        await sink.close()

    # Reset is the intended recovery path — both lines are processed fresh.
    assert report.lines_processed == 2
    warn_records = [
        r for r in caplog.records if "handoff_worker" in r.message and "truncated" in r.message
    ]
    assert len(warn_records) == 1

    # Persisted offset now reflects the post-rotation size.
    reloaded = ProcessedOffsets.load(offsets_path)
    assert reloaded.last_byte_offset == report.new_offset


# ---------------------------------------------------------------------------
# Declared-precedence dedup (AC-5.3, D-20)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_declared_precedence_suppresses_matching_inferred(tmp_path: Path) -> None:
    """A declared (alice->bob) triple suppresses the inferred equivalent.

    Key shape: ``(session_id, entry.agent_id, decision.handoff_id)`` — so a
    declared entry whose author is ``alice`` with ``handoff_id="bob"`` maps
    to the inferred triple ``(sess-1, alice, bob)``. That specific triple
    must be absent from the emitted output even though the rule pack would
    otherwise produce it (alice at t0, bob at t1).
    """
    audit = tmp_path / "audit.jsonl"
    offsets = tmp_path / "offsets.json"
    out = tmp_path / "out.jsonl"

    t0 = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=10)
    t2 = t0 + timedelta(seconds=20)
    _write_audit(
        audit,
        [
            _audit_line(timestamp=t0, agent_id="alice", request_id="r-1"),
            _audit_line(timestamp=t1, agent_id="bob", request_id="r-2"),
            _audit_line(
                timestamp=t2,
                agent_id="alice",
                request_id="r-3",
                event_type="handoff_declared",
                handoff_id="bob",
                handoff_decision=HandoffDecision(handoff_id="bob", action="allow"),
            ),
        ],
    )

    sink = JSONLForensicSink(out)
    try:
        report = await run_worker(audit, offsets, sink, window_s=3600)
    finally:
        await sink.close()

    assert report.lines_processed == 3
    emitted = [
        InferredHandoff.model_validate_json(line)
        for line in out.read_text(encoding="utf-8").splitlines()
    ]
    # The (sess-1, alice, bob) triple MUST NOT appear — it was declared.
    suppressed_triples = {(r.session_id, r.source_agent, r.receiving_agent) for r in emitted}
    assert ("sess-1", "alice", "bob") not in suppressed_triples


@pytest.mark.unit
async def test_malformed_audit_line_is_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Malformed JSON on a line => WARN, skip, keep going."""
    audit = tmp_path / "audit.jsonl"
    offsets = tmp_path / "offsets.json"
    out = tmp_path / "out.jsonl"

    t0 = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=10)
    good_line1 = _audit_line(timestamp=t0, agent_id="alice", request_id="r-1")
    bad_line = json.dumps({"not": "an audit entry"})
    good_line2 = _audit_line(timestamp=t1, agent_id="bob", request_id="r-2")
    _write_audit(audit, [good_line1, bad_line, good_line2])

    sink = JSONLForensicSink(out)
    try:
        with caplog.at_level("WARNING"):
            report = await run_worker(audit, offsets, sink, window_s=3600)
    finally:
        await sink.close()

    # All three lines are counted (post sha-dedup), but only the two valid
    # ones feed into the engine.
    assert report.lines_processed == 3
    skip_records = [
        r for r in caplog.records if "handoff_worker" in r.message and "malformed" in r.message
    ]
    assert len(skip_records) == 1


# ---------------------------------------------------------------------------
# CLI surface: _parse_args, _build_sink, _cli_main
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_args_parses_full_cli(tmp_path: Path) -> None:
    """``_parse_args`` extracts all four fields with the right types."""
    ns = _parse_args(
        [
            "--audit",
            str(tmp_path / "a.jsonl"),
            "--offsets",
            str(tmp_path / "o.json"),
            "--out",
            str(tmp_path / "out.jsonl"),
            "--window-s",
            "3600",
        ]
    )
    assert Path(ns.audit).name == "a.jsonl"
    assert Path(ns.offsets).name == "o.json"
    assert Path(ns.out).name == "out.jsonl"
    assert ns.window_s == 3600


@pytest.mark.unit
def test_parse_args_defaults_window_s(tmp_path: Path) -> None:
    """``--window-s`` defaults to 3600 when omitted."""
    ns = _parse_args(
        [
            "--audit",
            str(tmp_path / "a.jsonl"),
            "--offsets",
            str(tmp_path / "o.json"),
            "--out",
            str(tmp_path / "out.jsonl"),
        ]
    )
    assert ns.window_s == 3600


@pytest.mark.unit
async def test_build_sink_dispatches_http_for_url() -> None:
    """``http://`` and ``https://`` URLs build an :class:`HttpForensicSink`."""
    http_sink = _build_sink("http://receiver/emit")
    try:
        assert isinstance(http_sink, HttpForensicSink)
        assert isinstance(http_sink, ForensicSink)
    finally:
        await http_sink.close()

    https_sink = _build_sink("https://receiver/emit")
    try:
        assert isinstance(https_sink, HttpForensicSink)
    finally:
        await https_sink.close()


@pytest.mark.unit
async def test_build_sink_dispatches_file_for_path(tmp_path: Path) -> None:
    """Non-URL paths build a :class:`JSONLForensicSink`."""
    target = tmp_path / "out.jsonl"
    sink = _build_sink(str(target))
    try:
        assert isinstance(sink, JSONLForensicSink)
        assert sink._path == target  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    finally:
        await sink.close()


@pytest.mark.unit
async def test_cli_main_runs_full_pipeline_to_jsonl(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``_cli_main`` returns 0, prints WorkerReport JSON, writes JSONL sink."""
    audit = tmp_path / "audit.jsonl"
    offsets = tmp_path / "offsets.json"
    out = tmp_path / "out.jsonl"

    t0 = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=10)
    _write_audit(
        audit,
        [
            _audit_line(timestamp=t0, agent_id="alice", request_id="r-1"),
            _audit_line(timestamp=t1, agent_id="bob", request_id="r-2"),
        ],
    )

    ns = _parse_args(
        [
            "--audit",
            str(audit),
            "--offsets",
            str(offsets),
            "--out",
            str(out),
            "--window-s",
            "3600",
        ]
    )
    exit_code = await _cli_main(ns)
    assert exit_code == 0

    captured = capsys.readouterr()
    report = WorkerReport.model_validate_json(captured.out.strip())
    assert report.lines_processed == 2
    assert report.records_emitted >= 1
    assert out.exists()


@pytest.mark.unit
async def test_cli_main_with_http_out_uses_mock_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--out http://...`` constructs :class:`HttpForensicSink`; mock httpx.

    We monkeypatch ``_build_sink`` to inject a mock-transport-backed
    :class:`HttpForensicSink` so the CLI exercises the HTTP dispatch branch
    without touching the network.
    """
    audit = tmp_path / "audit.jsonl"
    offsets = tmp_path / "offsets.json"

    t0 = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=10)
    _write_audit(
        audit,
        [
            _audit_line(timestamp=t0, agent_id="alice", request_id="r-1"),
            _audit_line(timestamp=t1, agent_id="bob", request_id="r-2"),
        ],
    )

    posted: list[dict[str, Any]] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        posted.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    def _mock_build_sink(out_arg: str) -> ForensicSink:
        assert out_arg.startswith("http://"), out_arg
        sink = HttpForensicSink(url=out_arg)
        sink._client = httpx.AsyncClient(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            transport=httpx.MockTransport(_handler)
        )
        return sink

    monkeypatch.setattr(handoff_worker, "_build_sink", _mock_build_sink)

    ns = _parse_args(
        [
            "--audit",
            str(audit),
            "--offsets",
            str(offsets),
            "--out",
            "http://receiver/emit",
            "--window-s",
            "3600",
        ]
    )
    exit_code = await _cli_main(ns)
    assert exit_code == 0
    # At least one POST — the inferred handoff.
    assert len(posted) >= 1
    assert posted[0]["session_id"] == "sess-1"
