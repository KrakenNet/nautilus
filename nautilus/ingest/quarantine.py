"""``QuarantineLogStore`` + ``QuarantineSink`` — append-only quarantine of rows
that fail ingest-integrity validation (Task 29, US-4).

Under ``on_schema_violation="quarantine"`` (the default), the ingest
orchestrator (:mod:`nautilus.ingest.validator`, Task 30) forwards each
violating row to :meth:`QuarantineSink.record`, which appends a row to
``nautilus_quarantine_log`` so operators can inspect rejected payloads
out-of-band (design §4 quarantine flow, AC-4.6, AC-4.7, AC-4.12).

The store subclasses :class:`nautilus.core.postgres_store.BasePostgresStore`
for shared asyncpg lifecycle + failure-mode semantics (TD-11). Under
``on_failure="fallback_memory"`` the backend degrades to a bounded
:class:`collections.deque` so a broker with a broken Postgres link does
not leak memory during sustained violation bursts; the deque evicts the
oldest row on overflow (``maxlen`` default 10 000).

Each :meth:`QuarantineSink.record` call bumps the
``nautilus.ingest.quarantine.total`` counter with ``source_id`` + ``reason``
labels (design line 1045, FR-33).

Retention of the primary table is out-of-band ops policy (ADR in
design.md lines 991-997); this module never deletes rows.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import deque
from datetime import UTC, datetime
from typing import Any

from nautilus.core.postgres_store import BasePostgresStore
from nautilus.core.types import FailureMode
from nautilus.observability.metrics import NautilusMetrics

__all__ = [
    "QuarantineLogStore",
    "QuarantineLogStoreUnavailableError",
    "QuarantineSink",
]


_LOG = logging.getLogger(__name__)
_metrics = NautilusMetrics()

# DDL Block 3 — copied verbatim from design.md lines 361-370 (including the
# ``ix_nautilus_quarantine_log_source_received`` compound index on
# ``(source_id, received_at DESC)``).
_DDL: str = (
    "CREATE TABLE IF NOT EXISTS nautilus_quarantine_log ("
    "id UUID PRIMARY KEY, "
    "source_id TEXT NOT NULL, "
    "received_at TIMESTAMPTZ NOT NULL DEFAULT now(), "
    "original_payload JSONB NOT NULL, "
    "violation_reason TEXT NOT NULL, "
    "schema_hash TEXT NOT NULL"
    "); "
    "CREATE INDEX IF NOT EXISTS ix_nautilus_quarantine_log_source_received "
    "ON nautilus_quarantine_log (source_id, received_at DESC)"
)

_DEFAULT_MAXLEN: int = 10_000
"""Default bound for the degraded-memory deque.

Sized to roughly 10 MB assuming ~1 KB per row (typical nautobot/device
row shape). Operators running degraded for extended windows should monitor
the ``nautilus.ingest.quarantine.total`` counter vs the log-emitted
capacity warning to gauge data loss.
"""


class QuarantineLogStoreUnavailableError(Exception):
    """Raised when a ``fail_closed`` :class:`QuarantineLogStore` cannot reach PG.

    The underlying ``asyncpg`` / network exception is preserved on
    ``__cause__`` for operator diagnosis (NFR-DEGRAD).
    """


class QuarantineLogStore(BasePostgresStore):
    """asyncpg-backed persistence for the ``nautilus_quarantine_log`` table.

    Satisfies FR-33, AC-4.6, AC-4.7, AC-4.8, AC-4.12.

    Slot: instantiated from ``Broker.setup()`` when any configured source has
    ``ingest_integrity`` enabled; ``setup()`` is called once at startup so
    the DDL runs idempotently. :meth:`append` is called from
    :meth:`QuarantineSink.record`; :meth:`recent` is a read helper for
    CLI/debugging use.

    Args:
        dsn: Postgres DSN.
        on_failure: Fail-mode policy (``"fail_closed"`` default).
        memory_maxlen: Upper bound for the degraded-memory deque. Default
            ``10_000``; lower values are useful in tests.
    """

    _DDL: str = _DDL
    _TABLE: str = "nautilus_quarantine_log"

    def __init__(
        self,
        dsn: str,
        *,
        on_failure: FailureMode = "fail_closed",
        memory_maxlen: int = _DEFAULT_MAXLEN,
    ) -> None:
        super().__init__(dsn, on_failure=on_failure)
        self._memory_maxlen: int = memory_maxlen

    # ------------------------------------------------------------------
    # Abstract hooks
    # ------------------------------------------------------------------

    def _init_memory_backend(self) -> deque[dict[str, Any]]:
        """Return a fresh bounded :class:`collections.deque`.

        The bound protects a long-running broker in degraded mode: once the
        deque hits ``maxlen`` the oldest row is evicted on every append,
        which limits RSS growth at the cost of silently dropping violations
        that pre-date the current window.
        """
        _LOG.warning(
            "quarantine backend degraded to memory: violations may be lost "
            "on broker restart [nautilus.quarantine.store.degraded=1]"
        )
        return deque(maxlen=self._memory_maxlen)

    def _unavailable_error(self) -> type[Exception]:
        return QuarantineLogStoreUnavailableError

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    async def append(
        self,
        *,
        source_id: str,
        row: dict[str, Any],
        reason: str,
        schema_hash: str | None,
    ) -> None:
        """Insert a quarantine entry (primary) or append to the bounded deque (memory).

        Args:
            source_id: Stable source identifier (adapter-level, not row-level).
            row: The original payload that failed validation (JSON-serialisable).
            reason: Violation reason string (schema path + message, or
                ``"anomaly_sigma: z=4.1"`` for baseline hits).
            schema_hash: SHA-256 of the validating schema doc for post-hoc
                audit. ``None`` degrades to an empty string to respect the
                design DDL's ``NOT NULL`` constraint; callers from the
                orchestrator (Task 30) always pass a real hash.
        """
        received_at = datetime.now(UTC)
        hash_for_row = schema_hash if schema_hash is not None else ""

        if self._mode == "degraded_memory":
            backend: deque[dict[str, Any]] = self._memory_backend
            # Capacity warning fires BEFORE the append, i.e. on the transition
            # step when the deque is already full. Operators see a recurring
            # warning under sustained violation bursts.
            if backend.maxlen is not None and len(backend) >= backend.maxlen:
                _LOG.warning(
                    "quarantine deque at capacity (maxlen=%d); oldest row "
                    "will be evicted on this append [source_id=%s]",
                    backend.maxlen,
                    source_id,
                )
            backend.append(
                {
                    "id": str(uuid.uuid4()),
                    "source_id": source_id,
                    "received_at": received_at,
                    "original_payload": row,
                    "violation_reason": reason,
                    "schema_hash": hash_for_row,
                }
            )
            return

        if self._pool is None:
            raise QuarantineLogStoreUnavailableError(
                "QuarantineLogStore.append() called before setup() succeeded"
            )

        # Serialise the payload as a JSON string and let Postgres cast it to
        # jsonb (``$3::jsonb``). asyncpg can bind jsonb directly from a dict
        # but only if the codec is registered on the pool; passing a string
        # + explicit cast keeps the module self-contained.
        await self._pool.execute(
            "INSERT INTO nautilus_quarantine_log "
            "(id, source_id, original_payload, violation_reason, schema_hash, received_at) "
            "VALUES ($1, $2, $3::jsonb, $4, $5, $6)",
            str(uuid.uuid4()),
            source_id,
            json.dumps(row),
            reason,
            hash_for_row,
            received_at,
        )

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------

    async def recent(self, source_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Return the ``limit`` most-recent quarantine rows for ``source_id``.

        Sorted by ``received_at`` DESC (uses the compound index from DDL
        block 3). The in-memory branch iterates the deque in reverse for
        the same ordering guarantee.

        Primary-mode rows are normalised so ``original_payload`` is a dict
        regardless of whether asyncpg returned a ``str`` (no codec) or a
        ``dict`` (codec registered).
        """
        if self._mode == "degraded_memory":
            backend: deque[dict[str, Any]] = self._memory_backend
            matching = [e for e in backend if e["source_id"] == source_id]
            matching.reverse()
            return matching[:limit]

        if self._pool is None:
            raise QuarantineLogStoreUnavailableError(
                "QuarantineLogStore.recent() called before setup() succeeded"
            )

        rows: list[Any] = await self._pool.fetch(
            "SELECT id, source_id, received_at, original_payload, "
            "violation_reason, schema_hash "
            "FROM nautilus_quarantine_log "
            "WHERE source_id = $1 "
            "ORDER BY received_at DESC "
            "LIMIT $2",
            source_id,
            limit,
        )
        return [_normalise_row(r) for r in rows]


def _normalise_row(row: Any) -> dict[str, Any]:
    """Coerce an asyncpg row into a plain dict with a decoded ``original_payload``."""
    payload: Any = row["original_payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return {
        "id": row["id"],
        "source_id": row["source_id"],
        "received_at": row["received_at"],
        "original_payload": payload,
        "violation_reason": row["violation_reason"],
        "schema_hash": row["schema_hash"],
    }


class QuarantineSink:
    """Thin façade over :class:`QuarantineLogStore` used by the ingest orchestrator.

    Separates the "what to do on a violation" contract (:meth:`record`) from
    the "how to persist" lifecycle (the store). The orchestrator
    (:mod:`nautilus.ingest.validator`, Task 30) depends only on this façade,
    so tests for the validator can inject a fake sink without touching
    asyncpg.
    """

    def __init__(self, store: QuarantineLogStore) -> None:
        self._store: QuarantineLogStore = store

    async def record(
        self,
        source_id: str,
        row: dict[str, Any],
        reason: str,
        schema_hash: str | None = None,
    ) -> None:
        """Append one quarantine entry and emit the observability counter.

        Positional argument order matches the design sequence diagram at
        line 276: ``(source_id, row, reason, schema_hash)``.
        """
        await self._store.append(
            source_id=source_id,
            row=row,
            reason=reason,
            schema_hash=schema_hash,
        )
        _metrics.ingest_quarantine_total.add(
            1, attributes={"source_id": source_id, "reason": reason}
        )
