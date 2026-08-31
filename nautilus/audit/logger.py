"""``AuditLogger`` — thin wrapper over a Fathom :class:`AuditSink` (design §3.7).

The Fathom-provided :class:`fathom.audit.AuditSink` Protocol accepts a
:class:`fathom.audit.AuditRecord`, whose schema is Fathom-centric
(``modules_traversed``, ``rules_fired``, ``decision``, …). The Nautilus
:class:`AuditEntry` (design §4.9) is richer: it carries routing decisions,
scope constraints, denial records, error records, and per-category
source-ID buckets.

Mapping strategy:
- Populate the Fathom ``AuditRecord`` fields that align naturally
  (``timestamp`` ISO8601, ``session_id``, ``rules_fired`` ← ``rule_trace``,
  ``duration_us``, ``decision``/``reason`` synthesised from
  ``sources_queried``/``sources_denied`` summaries).
- Persist the full Nautilus ``AuditEntry`` JSON into ``metadata`` under a
  single key so the on-disk line is a complete, loss-less record of the
  request — satisfies NFR-8 "complete audit entry" and AC-7.1 / AC-7.3.

Serialization hardening (Task 2.10 / AC-7.3, AC-7.5, NFR-8):
- Nautilus ``AuditEntry`` JSON is produced via
  ``model_dump_json(by_alias=False)`` then post-processed so ``timestamp``
  ends with a literal ``Z`` suffix rather than ``+00:00`` (AC-7.5).
- After every sink write, the logger flushes any available file buffer
  (sink ``flush()`` method, ``fsync`` on the sink's underlying path)
  so a process crash cannot silently lose the tail record (NFR-8).
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, get_args, runtime_checkable

from fathom.models import AuditRecord

from nautilus.core.models import AuditEntry


@runtime_checkable
class AuditSink(Protocol):
    """Subset of the Fathom ``AuditSink`` Protocol used by Nautilus.

    Mirrors :class:`fathom.audit.AuditSink` so callers can inject any
    duck-typed sink (e.g. an in-memory list collector in tests) without
    depending on fathom's Protocol class directly.
    """

    def write(self, record: AuditRecord) -> None:
        """Persist one Fathom :class:`AuditRecord` to the sink.

        Args:
            record: The Fathom-shaped audit record to append.
        """
        ...


# Metadata key under which the full Nautilus AuditEntry JSON lives. Kept as
# a module constant so test helpers can re-deserialise with one import.
NAUTILUS_METADATA_KEY: str = "nautilus_audit_entry"


def _iso8601_utc_z(ts: datetime) -> str:
    """Render ``ts`` as ISO8601 UTC with a trailing ``Z`` suffix (AC-7.5).

    Naive datetimes are treated as UTC (the broker always stamps
    :meth:`AuditLogger.utcnow` which is TZ-aware, but defensive code
    normalises anyway). Non-UTC offsets are converted to UTC first so
    the on-disk timestamp is canonically comparable.
    """
    ts = ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)
    # ``isoformat()`` on a UTC datetime yields ``...+00:00``; swap for ``Z``.
    iso = ts.isoformat()
    if iso.endswith("+00:00"):
        iso = iso[: -len("+00:00")] + "Z"
    return iso


def _serialize_entry(entry: AuditEntry) -> str:
    """Canonical Nautilus ``AuditEntry`` → JSONL payload.

    Calls :meth:`AuditEntry.model_dump_json` with ``by_alias=False`` so
    field names match the Pydantic declarations (AC-7.3 "deterministic
    JSONL output"), then rewrites the ``timestamp`` field so it ends
    with the literal ``Z`` suffix (AC-7.5).
    """
    raw_json = entry.model_dump_json(by_alias=False)
    payload = json.loads(raw_json)
    payload["timestamp"] = _iso8601_utc_z(entry.timestamp)
    return json.dumps(payload, separators=(",", ":"))


def _flush_sink(sink: object) -> None:
    """Best-effort flush+fsync of a sink's underlying storage (NFR-8).

    The Fathom :class:`fathom.audit.FileSink` opens + closes the file
    per ``write`` so its buffer is already flushed by the time we
    return. For extra durability we additionally ``fsync`` the path if
    the sink exposes one (``_path`` or ``path``), which collapses the
    kernel page cache to disk. Sinks that expose ``flush()`` directly
    (e.g. in-memory test doubles or streaming sinks) are also honoured.
    """
    flush = getattr(sink, "flush", None)
    if callable(flush):
        flush()
    path_attr = getattr(sink, "_path", None) or getattr(sink, "path", None)
    if path_attr is None:
        return
    try:
        path = Path(path_attr)
    except TypeError:
        return
    if not path.exists():
        return
    # Open RDONLY purely to obtain an fd we can fsync — avoids racing the
    # append-mode writer the sink itself used.
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError:
        # fsync on some platforms (e.g. Windows RDONLY) can refuse; the
        # per-write close in FileSink has already flushed the buffer.
        pass
    finally:
        os.close(fd)


class AuditLogger:
    """Append-only audit logger backed by a Fathom ``AuditSink``.

    Per design §3.7 / §9.1 the default sink is ``fathom.audit.FileSink`` but
    any Protocol-compatible sink is accepted. :meth:`emit` converts a
    Nautilus :class:`AuditEntry` into a Fathom :class:`AuditRecord` and
    writes it to the sink. Writes are best-effort: sink failures propagate
    to the caller so the broker can still return a response while the
    operator sees the I/O error.
    """

    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink

    def emit(self, entry: AuditEntry) -> None:
        """Serialise ``entry`` and write it to the underlying sink.

        The Nautilus :class:`AuditEntry` is rendered via
        :func:`_serialize_entry` (canonical ``model_dump_json`` output
        with Z-suffixed timestamp) and stashed under
        ``metadata[NAUTILUS_METADATA_KEY]``. After the sink write we
        issue a best-effort flush so a process crash cannot lose the
        tail record (NFR-8).
        """
        payload_json = _serialize_entry(entry)
        # ``decision`` summary: "allow" if any source queried, "deny" if any
        # denied and none queried, "error" if only errors occurred, else
        # "skip". The full detail lives in ``metadata`` under
        # ``NAUTILUS_METADATA_KEY`` (loss-less JSON of the AuditEntry).
        if entry.sources_queried:
            decision = "allow"
        elif entry.sources_denied:
            decision = "deny"
        elif entry.sources_errored:
            decision = "error"
        else:
            decision = "skip"
        reason = (
            f"queried={len(entry.sources_queried)} "
            f"denied={len(entry.sources_denied)} "
            f"skipped={len(entry.sources_skipped)} "
            f"errored={len(entry.sources_errored)}"
        )

        record = AuditRecord(
            timestamp=_iso8601_utc_z(entry.timestamp),
            session_id=entry.session_id or entry.request_id,
            modules_traversed=[],
            rules_fired=list(entry.rule_trace),
            decision=decision,
            reason=reason,
            duration_us=entry.duration_ms * 1000,
            metadata={NAUTILUS_METADATA_KEY: payload_json},
        )
        self._sink.write(record)
        _flush_sink(self._sink)

    @property
    def sink(self) -> AuditSink:
        """The underlying sink, so the broker can close what holds a lock."""
        return self._sink

    @property
    def path(self) -> Path | None:
        """File this logger writes to, or ``None`` for a non-file sink."""
        raw = getattr(self._sink, "path", None) or getattr(self._sink, "_path", None)
        return Path(raw) if raw is not None else None

    def probe(self) -> str | None:
        """Why this logger could not write, or ``None`` when it can.

        Every request writes an entry before it answers, so an audit sink that
        has stopped accepting writes fails every request — the one dependency
        whose failure is total. ``/readyz`` calls this to take the instance out
        of rotation instead of reporting ready while 500ing.

        Cheap by construction: a permission check on the file (or, before the
        first write, on its directory), not a probe append, so the readiness
        endpoint cannot pollute the log an operator reads.
        """
        path = self.path
        if path is None:  # non-file sink: nothing local to check.
            return None
        if path.exists():
            if not os.access(path, os.W_OK):
                return f"audit log {path} is not writable"
            return None
        parent = path.parent
        if not parent.exists():
            return f"audit log directory {parent} does not exist"
        if not os.access(parent, os.W_OK):
            return f"audit log directory {parent} is not writable"
        return None

    def emit_event(self, entry: Any) -> None:
        """Emit a governance / meta-rule audit event.

        Accepts a plain ``dict`` produced by
        :class:`~nautilus.rkm.audit_emitter.AuditEventEmitter` and writes it
        through the same :meth:`emit` path every other entry takes, so the
        audit API can read it back.

        This used to write the sparse dict as-is. ``decode_nautilus_entry``
        and ``AuditReader._parse_line`` both validate a full ``AuditEntry``,
        so every governance event -- ``proposal_approved``, ``rule_promoted``,
        all eight of them -- was reported to the operator as a *corrupt* audit
        line, and "who approved this rule" came back empty from an intact log.
        ``Broker.emit_adapter_event`` already solved this by filling the
        request-shaped fields with placeholders; this does the same.
        """
        if isinstance(entry, AuditEntry):
            self.emit(entry)
            return
        self.emit(_event_entry(entry))

    @classmethod
    def utcnow(cls) -> datetime:
        """UTC timestamp helper so broker callers don't import datetime directly."""
        return datetime.now(tz=UTC)


_EVENT_TYPES: frozenset[str] = frozenset(
    get_args(AuditEntry.model_fields["event_type"].annotation.__args__[0])  # pyright: ignore[reportOptionalMemberAccess]
)

# Keys the dict shares with ``AuditEntry``; everything else is an event field.
_EVENT_ENTRY_KEYS: frozenset[str] = frozenset(
    {
        "event_type",
        "timestamp",
        "session_id",
        "trace_id",
        "schema_version",
        "request_id",
        "agent_id",
    }
)


def _event_entry(event: dict[str, Any]) -> AuditEntry:
    """Build a request-shaped ``AuditEntry`` around a governance event dict."""
    raw_ts = event.get("timestamp")
    if isinstance(raw_ts, datetime):
        timestamp = raw_ts
    elif isinstance(raw_ts, str):
        timestamp = datetime.fromisoformat(raw_ts)
    else:
        timestamp = datetime.now(tz=UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)

    trace_id = event.get("trace_id")
    event_type = event.get("event_type")
    fields = {k: v for k, v in event.items() if k not in _EVENT_ENTRY_KEYS}
    if event_type is not None and event_type not in _EVENT_TYPES:
        # An unrecognised type would fail validation and lose the whole
        # record; keep it readable rather than dropping it.
        fields["unrecognised_event_type"] = event_type
        event_type = None

    return AuditEntry(
        timestamp=timestamp,
        # The event is not a request. ``request_id`` is required and is what
        # the reader keys on, so the trace id stands in when there is one.
        request_id=str(event.get("request_id") or trace_id or uuid.uuid4()),
        agent_id=str(event.get("agent_id") or "<broker>"),
        session_id=event.get("session_id"),
        facts_asserted_summary={},
        denial_records=[],
        error_records=[],
        rule_trace=[],
        sources_queried=[],
        sources_denied=[],
        sources_errored=[],
        duration_ms=0,
        event_type=event_type,  # pyright: ignore[reportArgumentType]
        trace_id=trace_id,
        schema_version=event.get("schema_version"),
        event_fields=fields or None,
    )


def decode_nautilus_entry(record: AuditRecord) -> AuditEntry:
    """Round-trip helper: extract the Nautilus ``AuditEntry`` from an ``AuditRecord``.

    Useful for tests and downstream verifiers that read the JSONL file via
    fathom and want to inspect the richer Nautilus structure.
    """
    raw = record.metadata.get(NAUTILUS_METADATA_KEY)
    if raw is None:
        raise KeyError(f"AuditRecord has no {NAUTILUS_METADATA_KEY!r} metadata")
    return AuditEntry.model_validate(json.loads(raw))


__all__ = ["AuditLogger", "AuditSink", "NAUTILUS_METADATA_KEY", "decode_nautilus_entry"]
