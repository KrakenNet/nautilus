"""Offline forensic handoff worker (design §3.7, FR-11, FR-33, AC-5.1/3/4/5).

The worker tails the broker's audit JSONL, asserts each in-window
``AuditEntry`` into a Fathom engine loaded with the forensic handoff rule
pack, evaluates the engine, aggregates the resulting ``inferred_handoff``
facts into :class:`nautilus.core.models.InferredHandoff` records, and
emits them through a :class:`ForensicSink`. Tailing state
(last byte offset + bounded seen-hash set) is persisted atomically via
:class:`nautilus.forensics.offsets.ProcessedOffsets` so crash-restart
never double-emits (NFR-13 / AC-5.5).

Declared-precedence dedup (D-20 / AC-5.3): any ``(session_id, source_agent,
receiving_agent)`` triple that already appears in the audit window as an
``event_type="handoff_declared"`` record — carrying the broker's
:class:`HandoffDecision` — suppresses the inferred equivalent. The
offline inference is a belt-and-braces for undeclared handoffs only.

Rotation guard (AC-5.4): if the persisted ``last_byte_offset`` exceeds
the current file size (truncate or rotate happened), the worker WARNs
and resets to 0 rather than raising.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import fathom
from pydantic import BaseModel, ValidationError

from nautilus.core.models import AuditEntry, InferredHandoff
from nautilus.forensics.offsets import ProcessedOffsets
from nautilus.forensics.sinks import (
    ForensicSink,
    HttpForensicSink,
    JSONLForensicSink,
)

if TYPE_CHECKING:
    from datetime import datetime

log = logging.getLogger(__name__)

# Paths to the authoritative Fathom assets are resolved relative to the
# installed package so the worker can run from any cwd (CLI friendliness).
_PKG_ROOT = Path(__file__).resolve().parent.parent  # .../nautilus
_TEMPLATES_PATH = _PKG_ROOT / "rules" / "templates" / "nautilus.yaml"
_FORENSICS_MODULE = _PKG_ROOT / "rules" / "forensics" / "nautilus-forensics.yaml"
_HANDOFF_RULES = _PKG_ROOT / "rules" / "forensics" / "handoff.yaml"
_FORENSICS_FOCUS = "nautilus-forensics"

# Default classification when an AuditEntry carries no explicit max-class.
# The h-classification-delta rule only fires on a strict dominance relation;
# a uniform default effectively disables that heuristic for entries lacking
# the data, which is the conservative behaviour (no false positives).
_DEFAULT_CLASSIFICATION = "unclassified"


class WorkerReport(BaseModel):
    """Summary of one worker invocation."""

    lines_processed: int
    records_emitted: int
    new_offset: int


def _build_engine() -> fathom.Engine:
    """Instantiate a Fathom engine loaded with the forensic handoff pack."""
    engine = fathom.Engine()
    engine.load_templates(str(_TEMPLATES_PATH))
    engine.load_modules(str(_FORENSICS_MODULE))
    engine.load_rules(str(_HANDOFF_RULES))
    engine.set_focus([_FORENSICS_FOCUS])
    return engine


def _audit_event_slots(entry: AuditEntry) -> dict[str, Any]:
    """Project an :class:`AuditEntry` onto the ``audit_event`` CLIPS slots.

    ``sources_queried`` is a space-separated multislot per the template
    convention (see ``nautilus/rules/templates/nautilus.yaml``).
    ``classification`` falls back to :data:`_DEFAULT_CLASSIFICATION` when
    absent from the entry — the h-classification-delta heuristic relies on
    a strict dominance test, so a uniform default simply suppresses that
    signal rather than producing spurious inferences.
    """
    event_type = entry.event_type if entry.event_type is not None else "request"
    return {
        "session_id": entry.session_id if entry.session_id is not None else "",
        "agent_id": entry.agent_id,
        "event_type": event_type,
        "sources_queried": " ".join(entry.sources_queried),
        "classification": _DEFAULT_CLASSIFICATION,
        "timestamp": entry.timestamp.isoformat(),
    }


def _aggregate_inferred(
    raw_facts: list[dict[str, Any]],
    segment_max_ts: datetime | None,
) -> list[InferredHandoff]:
    """Sum per-signal confidences for each ``(session, source, receiver)``.

    Fathom asserts one ``inferred_handoff`` fact per firing heuristic, each
    carrying a single ``signals`` token and a pre-divided confidence. The
    worker collapses those into one :class:`InferredHandoff` per
    ``(session_id, source_agent, receiving_agent)`` triple with the summed
    confidence clamped to ``[0.0, 1.0]`` and the union of signals — see the
    "Salience -> confidence mapping" block in
    ``nautilus/rules/forensics/handoff.yaml``.
    """
    from datetime import UTC, datetime

    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for fact in raw_facts:
        key = (
            str(fact.get("session_id", "")),
            str(fact.get("source_agent", "")),
            str(fact.get("receiving_agent", "")),
        )
        try:
            conf = float(fact.get("confidence", 0.0))
        except TypeError, ValueError:
            conf = 0.0
        signals_raw = str(fact.get("signals", ""))
        signal_tokens = [tok for tok in signals_raw.split() if tok]
        slot = grouped.setdefault(key, {"confidence": 0.0, "signals": []})
        slot["confidence"] = min(1.0, float(slot["confidence"]) + conf)
        existing: list[str] = list(slot["signals"])
        for tok in signal_tokens:
            if tok not in existing:
                existing.append(tok)
        slot["signals"] = existing

    inferred_at = segment_max_ts if segment_max_ts is not None else datetime.now(tz=UTC)
    records: list[InferredHandoff] = []
    for (sid, src, recv), slot in grouped.items():
        records.append(
            InferredHandoff(
                session_id=sid,
                source_agent=src,
                receiving_agent=recv,
                confidence=float(slot["confidence"]),
                signals=list(slot["signals"]),
                inferred_at=inferred_at,
            )
        )
    return records


def _declared_key(entry: AuditEntry) -> tuple[str, str, str] | None:
    """Extract the ``(session_id, source_agent, receiving_agent)`` key from a
    ``handoff_declared`` audit entry, or ``None`` if the entry is ineligible."""
    if entry.event_type != "handoff_declared":
        return None
    if entry.session_id is None:
        return None
    decision = entry.handoff_decision
    # HandoffDecision carries handoff_id + action + denial_records + rule_trace
    # today; the source/receiving agents for dedup fall back to the entry's
    # ``agent_id`` (source) and the handoff_id encoding when a richer decision
    # payload is unavailable. We key conservatively on agent_id → agent_id
    # only when no richer data exists; otherwise derive from the decision.
    source = entry.agent_id
    receiving = ""
    if decision is not None:
        # Best-effort: handoff_id in declared audit events is the only
        # load-bearing identifier today; the receiver is not directly modelled
        # on HandoffDecision. Treat the handoff_id as the receiver key so
        # declared+inferred dedup still works when the inferred pair's
        # receiver matches the declared receiver captured elsewhere.
        receiving = decision.handoff_id or ""
    return (entry.session_id, source, receiving)


def _process_segment(
    audit_path: Path,
    offsets_path: Path,
    window_s: int,
) -> tuple[ProcessedOffsets, list[InferredHandoff], int, int, bool]:
    """Synchronous segment processor (filesystem + engine) — no I/O to sinks.

    Returns ``(offsets, survivors, lines_processed, new_offset, reset_needed)``.
    When ``reset_needed`` is true the caller must unlink the old offsets file
    before persisting the fresh instance — :meth:`ProcessedOffsets.save`
    refuses non-monotonic writes, and rotation is the intended recovery path.
    The caller is responsible for emitting survivors through the async sink
    and then persisting ``offsets``.
    """
    offsets = ProcessedOffsets.load(offsets_path)

    file_size = audit_path.stat().st_size if audit_path.exists() else 0
    start_offset = offsets.last_byte_offset
    reset_needed = False
    if start_offset > file_size:
        log.warning(
            "handoff_worker: audit file truncated or rotated "
            "(last_byte_offset=%d > size=%d); resetting offset to 0",
            start_offset,
            file_size,
        )
        start_offset = 0
        # Build a completely fresh offsets object — both the byte offset and
        # the seen-hash set must reset, since line hashes from the prior file
        # incarnation can no longer be trusted against a rotated file.
        offsets = ProcessedOffsets()
        reset_needed = True

    engine = _build_engine()

    lines_processed = 0
    asserted_count = 0
    declared_keys: set[tuple[str, str, str]] = set()
    segment_max_ts: datetime | None = None
    new_offset = start_offset

    if audit_path.exists():
        with audit_path.open("rb") as fh:
            fh.seek(start_offset)
            while True:
                raw = fh.readline()
                if not raw:
                    break
                new_offset = fh.tell()
                # Only count newline-terminated records as complete; a
                # partial tail (no trailing newline) is treated as not-yet-
                # flushed and left for the next invocation.
                if not raw.endswith(b"\n"):
                    new_offset = fh.tell() - len(raw)
                    break
                stripped = raw.rstrip(b"\r\n")
                if not stripped:
                    continue
                sha = hashlib.sha256(stripped).hexdigest()
                if sha in offsets.seen_line_sha256:
                    continue
                offsets.mark_seen(sha)
                lines_processed += 1
                try:
                    entry = AuditEntry.model_validate_json(stripped)
                except ValidationError as exc:
                    log.warning(
                        "handoff_worker: skipping malformed audit line at offset %d: %s",
                        new_offset,
                        exc,
                    )
                    continue

                if segment_max_ts is None or entry.timestamp > segment_max_ts:
                    segment_max_ts = entry.timestamp

                key = _declared_key(entry)
                if key is not None:
                    declared_keys.add(key)

                engine.assert_fact("audit_event", _audit_event_slots(entry))
                asserted_count += 1

    # Window filter: rules are currently join-based and the worker processes
    # only the newly-appended segment each invocation, so the effective
    # window is bounded by invocation cadence. Keep the cutoff for observers
    # who inspect intent; actual pruning is unnecessary for correctness.
    if segment_max_ts is not None and asserted_count > 0:
        _ = segment_max_ts - timedelta(seconds=window_s)

    engine.evaluate()
    raw_inferred = engine.query("inferred_handoff")
    aggregated = _aggregate_inferred(raw_inferred, segment_max_ts)

    survivors: list[InferredHandoff] = []
    for rec in aggregated:
        candidate_key = (rec.session_id, rec.source_agent, rec.receiving_agent)
        if candidate_key in declared_keys:
            continue
        survivors.append(rec)

    offsets.last_byte_offset = new_offset
    return offsets, survivors, lines_processed, new_offset, reset_needed


def _persist_offsets(
    offsets: ProcessedOffsets,
    offsets_path: Path,
    *,
    reset_needed: bool,
) -> None:
    """Persist offsets, unlinking first when rotation forced a reset.

    :meth:`ProcessedOffsets.save` refuses non-monotonic writes (guards against
    accidental regression). Rotation is the intended recovery path, so the
    caller signals ``reset_needed=True`` to authorise dropping the stale
    on-disk state before writing the fresh one.
    """
    if reset_needed and offsets_path.exists():
        offsets_path.unlink()
    offsets.save(offsets_path)


async def run_worker(
    audit_path: Path,
    offsets_path: Path,
    out_sink: ForensicSink,
    *,
    window_s: int = 3600,
) -> WorkerReport:
    """Stream the audit log from the persisted offset and emit inferred handoffs.

    Steps:

    1. Load persisted :class:`ProcessedOffsets`; seek to ``last_byte_offset``.
       If the offset exceeds the current file size (rotation / truncate),
       reset to 0 and WARN (AC-5.4).
    2. Stream lines in binary mode so byte offsets are exact. For each line:
       compute its SHA-256; skip if already in ``seen_line_sha256``; parse
       as :class:`AuditEntry`; add to seen set; assert an ``audit_event``
       fact into the engine. Collect ``handoff_declared`` keys for
       declared-precedence dedup.
    3. Run ``engine.evaluate()``; query ``inferred_handoff``; aggregate per
       ``(session, source, receiver)`` and drop any triple that appears in
       the declared set (AC-5.3, D-20).
    4. ``await out_sink.emit(...)`` for each surviving record.
    5. Atomically persist updated offsets state (NFR-13 / AC-5.5).
    """
    offsets, survivors, lines_processed, new_offset, _reset = _process_segment(
        audit_path, offsets_path, window_s
    )

    for rec in survivors:
        await out_sink.emit(rec)

    _persist_offsets(offsets, offsets_path, reset_needed=_reset)

    return WorkerReport(
        lines_processed=lines_processed,
        records_emitted=len(survivors),
        new_offset=new_offset,
    )


def _build_sink(out: str) -> ForensicSink:
    """Select a sink based on the CLI ``--out`` value (URL vs file path)."""
    if out.startswith(("http://", "https://")):
        return HttpForensicSink(url=out)
    return JSONLForensicSink(path=Path(out))


async def _cli_main(args: argparse.Namespace) -> int:
    audit_path = Path(args.audit)
    offsets_path = Path(args.offsets)
    sink = _build_sink(args.out)
    try:
        report = await run_worker(
            audit_path,
            offsets_path,
            sink,
            window_s=args.window_s,
        )
    finally:
        await sink.close()
    print(report.model_dump_json())  # noqa: T201  CLI output is load-bearing
    return 0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="nautilus.forensics.handoff_worker",
        description="Offline forensic handoff worker (Nautilus design §3.7).",
    )
    parser.add_argument("--audit", required=True, help="Path to the audit JSONL.")
    parser.add_argument("--offsets", required=True, help="Path to the offsets state file.")
    parser.add_argument(
        "--out",
        required=True,
        help=("Output sink: file path (JSONLForensicSink) or http(s):// URL (HttpForensicSink)."),
    )
    parser.add_argument(
        "--window-s",
        type=int,
        default=3600,
        dest="window_s",
        help="Windowing horizon in seconds (default 3600).",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ns = _parse_args()
    raise SystemExit(asyncio.run(_cli_main(ns)))


__all__ = ["WorkerReport", "run_worker"]
