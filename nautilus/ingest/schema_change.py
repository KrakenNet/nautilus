"""``SchemaChangeDetector`` + ``SchemaAckStore`` — publisher schema-drift gate (Task 28, US-4).

Implements AC-4.10 / AC-4.12 / FR-20: on every ingest, hash the currently
published schema and compare it to the most recent operator-acknowledged
hash stored in ``nautilus_schema_ack``. On mismatch, the configured
``on_publisher_schema_change`` mode decides whether to pause the source
(raise :class:`~nautilus.ingest.errors.IngestPausedError`) or warn-only
(log + continue). Either way, an ``event_type="schema_change_detected"``
audit entry is emitted so operators see drift land on the same JSONL
stream used for request + handoff events (FR-59).

Failure policy is inherited from
:class:`~nautilus.core.postgres_store.BasePostgresStore`:

- ``on_failure="fail_closed"``: connect / DDL errors raise
  :class:`SchemaAckStoreUnavailableError` with ``__cause__`` preserved.
- ``on_failure="fallback_memory"``: degrade silently to an in-memory
  ``dict[str, SchemaAck]``; ``mode`` flips to ``"degraded_memory"`` and a
  WARNING log fires (operator sees drift gating survive PG outage, but
  ack history will not survive restart).
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from nautilus.core.models import AuditEntry
from nautilus.core.postgres_store import BasePostgresStore
from nautilus.ingest.errors import IngestPausedError

if TYPE_CHECKING:
    from nautilus.audit.logger import AuditLogger

__all__ = [
    "SchemaAck",
    "SchemaAckStore",
    "SchemaAckStoreUnavailableError",
    "SchemaChangeDetector",
]


_LOG = logging.getLogger(__name__)

# Hex SHA-256 digest: 64 lowercase hex chars. Used by :meth:`_normalize_hash`
# to tell "already-hashed input" from "raw schema payload that needs hashing".
_HEX_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


# DDL Block 4 — copied verbatim from design.md §DDL (lines 372-378).
_DDL: str = (
    "CREATE TABLE IF NOT EXISTS nautilus_schema_ack ("
    "source_id TEXT PRIMARY KEY, "
    "acked_hash TEXT NOT NULL, "
    "actor TEXT NOT NULL, "
    "acked_at TIMESTAMPTZ NOT NULL DEFAULT now()"
    ")"
)


@dataclass(frozen=True, slots=True)
class SchemaAck:
    """Immutable snapshot of one ``nautilus_schema_ack`` row.

    Attributes:
        source_id: Stable identifier of the source (registry key).
        acked_hash: SHA-256 hex digest of the schema the operator last
            acknowledged.
        actor: Principal who wrote the ack (required).
        acked_at: Last-write timestamp, tz-aware UTC.
    """

    source_id: str
    acked_hash: str
    actor: str
    acked_at: datetime


class SchemaAckStoreUnavailableError(Exception):
    """Raised when a ``fail_closed`` :class:`SchemaAckStore` cannot reach PG.

    The underlying ``asyncpg`` / network exception is preserved on
    ``__cause__`` so operators can diagnose the root cause (NFR-DEGRAD).
    """


class SchemaAckStore(BasePostgresStore):
    """asyncpg-backed persistence for per-source schema acknowledgements.

    Satisfies FR-20 (AC-4.10, AC-4.12). Slot: :meth:`get_ack` on every
    ingest via :class:`SchemaChangeDetector.check`; :meth:`set_ack` from
    the operator ack CLI / transport endpoint (lands later).
    """

    _DDL: str = _DDL
    _TABLE: str = "nautilus_schema_ack"

    def _init_memory_backend(self) -> dict[str, SchemaAck]:
        """Return a fresh empty dict keyed by ``source_id``."""
        _LOG.warning(
            "schema_ack backend degraded to memory: operator ack history will not "
            "survive restart [nautilus.schema_ack.store.degraded=1]"
        )
        return {}

    def _unavailable_error(self) -> type[Exception]:
        return SchemaAckStoreUnavailableError

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def set_ack(
        self,
        source_id: str,
        *,
        acked_hash: str,
        actor: str,
    ) -> SchemaAck:
        """Upsert the ack row for ``source_id`` and return the post-image.

        Idempotent by design: calling twice with the same ``acked_hash``
        overwrites ``actor`` and refreshes ``acked_at`` without raising.
        """
        now = datetime.now(UTC)
        if self._mode == "degraded_memory":
            backend: dict[str, SchemaAck] = self._memory_backend
            ack = SchemaAck(
                source_id=source_id,
                acked_hash=acked_hash,
                actor=actor,
                acked_at=now,
            )
            backend[source_id] = ack
            return ack
        if self._pool is None:
            raise SchemaAckStoreUnavailableError(
                "SchemaAckStore.set_ack() called before setup() succeeded"
            )
        row: Any = await self._pool.fetchrow(
            "INSERT INTO nautilus_schema_ack "
            "(source_id, acked_hash, actor, acked_at) "
            "VALUES ($1, $2, $3, $4) "
            "ON CONFLICT (source_id) DO UPDATE SET "
            "acked_hash = EXCLUDED.acked_hash, "
            "actor = EXCLUDED.actor, "
            "acked_at = EXCLUDED.acked_at "
            "RETURNING source_id, acked_hash, actor, acked_at",
            source_id,
            acked_hash,
            actor,
            now,
        )
        return _row_to_ack(row)

    async def get_ack(self, source_id: str) -> SchemaAck | None:
        """Return the ack row for ``source_id`` or ``None`` if absent."""
        if self._mode == "degraded_memory":
            backend: dict[str, SchemaAck] = self._memory_backend
            return backend.get(source_id)
        if self._pool is None:
            raise SchemaAckStoreUnavailableError(
                "SchemaAckStore.get_ack() called before setup() succeeded"
            )
        row: Any = await self._pool.fetchrow(
            "SELECT source_id, acked_hash, actor, acked_at "
            "FROM nautilus_schema_ack WHERE source_id = $1",
            source_id,
        )
        if row is None:
            return None
        return _row_to_ack(row)


def _row_to_ack(row: Any) -> SchemaAck:
    """Normalize an asyncpg row (mapping-like) into a :class:`SchemaAck`."""
    return SchemaAck(
        source_id=row["source_id"],
        acked_hash=row["acked_hash"],
        actor=row["actor"],
        acked_at=row["acked_at"],
    )


class SchemaChangeDetector:
    """Compare current-published schema hash against stored operator ack.

    Enforces :attr:`IngestIntegrityConfig.on_publisher_schema_change`
    (AC-4.10). Instantiated once per :class:`~nautilus.core.broker.Broker`
    and shared across sources; ``check()`` is called at the top of every
    ingest-adapter execution.

    Args:
        ack_store: Persistence for operator acknowledgements.
        audit_logger: Optional sink for ``schema_change_detected`` audit
            events. ``None`` in unit tests that don't exercise the audit
            hop; production wiring always injects the real
            :class:`~nautilus.audit.logger.AuditLogger`.
    """

    def __init__(
        self,
        ack_store: SchemaAckStore,
        *,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self._ack_store: SchemaAckStore = ack_store
        self._audit_logger: AuditLogger | None = audit_logger

    async def check(
        self,
        source_id: str,
        *,
        current_schema_hash: str,
        mode: Literal["warn", "pause"],
    ) -> None:
        """Raise / warn if ``current_schema_hash`` differs from the stored ack.

        Args:
            source_id: Source identifier (registry key).
            current_schema_hash: Either a SHA-256 hex digest already
                computed by the caller, or an arbitrary string that will
                be SHA-256-hashed here. Bytes / dicts are a caller concern
                (hash them upstream).
            mode: ``"pause"`` raises :class:`IngestPausedError`;
                ``"warn"`` logs a WARNING and returns. Both emit an audit
                event on mismatch.

        Raises:
            IngestPausedError: On hash mismatch when ``mode == "pause"``.
        """
        current_hash = _normalize_hash(current_schema_hash)
        ack = await self._ack_store.get_ack(source_id)
        if ack is not None and ack.acked_hash == current_hash:
            # Hot path — cheap no-op when hashes match.
            return

        acked_label = ack.acked_hash if ack is not None else "none"
        self._emit_schema_change_audit(
            source_id=source_id,
            current_hash=current_hash,
            acked_hash=acked_label,
            mode=mode,
        )

        message = (
            f"schema mismatch for {source_id}: "
            f"current={current_hash[:12]}, acked={acked_label[:12] if ack else 'none'}"
        )
        if mode == "pause":
            raise IngestPausedError(message)
        _LOG.warning("%s (mode=warn — continuing)", message)

    def _emit_schema_change_audit(
        self,
        *,
        source_id: str,
        current_hash: str,
        acked_hash: str,
        mode: Literal["warn", "pause"],
    ) -> None:
        """Write a single ``event_type="schema_change_detected"`` audit entry.

        Reuses the same JSONL stream as request / handoff / cap-breach
        events so operators see schema drift alongside the rest (FR-59).
        ``error_records`` carries the two hashes + mode in its
        ``message`` so downstream grep / tooling can fish them out
        without parsing a bespoke shape.
        """
        if self._audit_logger is None:
            return
        entry = AuditEntry(
            event_type="schema_change_detected",
            timestamp=datetime.now(UTC),
            request_id=f"schema-drift-{uuid.uuid4()}",
            agent_id="system",
            raw_intent="",
            facts_asserted_summary={},
            routing_decisions=[],
            scope_constraints=[],
            denial_records=[],
            error_records=[],
            rule_trace=[
                f"schema_change_detected source={source_id} "
                f"current={current_hash} acked={acked_hash} mode={mode}"
            ],
            sources_queried=[source_id],
            sources_denied=[],
            sources_skipped=[],
            sources_errored=[],
            attestation_token=None,
            duration_ms=0,
        )
        self._audit_logger.emit(entry)


def _normalize_hash(candidate: str) -> str:
    """Return ``candidate`` if it's already a hex SHA-256; else hash it.

    Callers often pre-hash the canonicalised schema document (via
    :func:`rfc8785.dumps` + ``sha256``). Passing an already-hex digest
    through lets the detector reuse that work for free.
    """
    if _HEX_SHA256.fullmatch(candidate):
        return candidate
    return hashlib.sha256(candidate.encode("utf-8")).hexdigest()
