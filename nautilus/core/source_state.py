"""``SourceStateStore`` — persistent per-source enable/disable (US-3).

Subclass of :class:`~nautilus.core.postgres_store.BasePostgresStore`. Persists
``(source_id, enabled, reason, actor, changed_at)`` rows in the
``nautilus_source_state`` table so operator enable/disable decisions survive
broker restarts (FR-29, FR-31, FR-32; AC-3.1, AC-3.2, AC-3.3, AC-3.6).

Failure policy is inherited from the base:

- ``on_failure="fail_closed"``: connect / DDL errors raise
  :class:`SourceStateStoreUnavailableError` with the original exception on
  ``__cause__``. The broker refuses to start (design §Component
  Responsibilities → *Failure modes*).
- ``on_failure="fallback_memory"``: degrades to an in-memory ``dict`` keyed by
  ``source_id`` and emits a WARNING log + a structured "degraded" tag.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from nautilus.core.models import AuditEntry
from nautilus.core.postgres_store import BasePostgresStore
from nautilus.core.types import FailureMode

if TYPE_CHECKING:
    from nautilus.audit.logger import AuditLogger

__all__ = [
    "SourceState",
    "SourceStateStore",
    "SourceStateStoreUnavailableError",
]


_LOG = logging.getLogger(__name__)


# DDL Block 1 — copied verbatim from design.md §DDL (lines 338-345).
_DDL: str = (
    "CREATE TABLE IF NOT EXISTS nautilus_source_state ("
    "source_id TEXT PRIMARY KEY, "
    "enabled BOOLEAN NOT NULL, "
    "reason TEXT, "
    "actor TEXT NOT NULL, "
    "changed_at TIMESTAMPTZ NOT NULL DEFAULT now()"
    ")"
)


@dataclass(frozen=True, slots=True)
class SourceState:
    """Immutable snapshot of one ``nautilus_source_state`` row.

    Attributes:
        source_id: Stable identifier of the source (registry key).
        enabled: Whether the broker may route to this source.
        reason: Operator-supplied reason string, or ``None``.
        actor: Principal who made the last change (required — AC-3.6).
        changed_at: Last-write timestamp, tz-aware UTC.
    """

    source_id: str
    enabled: bool
    reason: str | None
    actor: str
    changed_at: datetime


class SourceStateStoreUnavailableError(Exception):
    """Raised when a ``fail_closed`` :class:`SourceStateStore` cannot reach PG.

    The underlying ``asyncpg`` / network exception is preserved on
    ``__cause__`` so operators can diagnose the root cause (NFR-DEGRAD).
    """


class SourceStateStore(BasePostgresStore):
    """asyncpg-backed persistence for per-source enable/disable state.

    Satisfies FR-29, FR-31, FR-32; AC-3.1, AC-3.2, AC-3.3, AC-3.6.

    Slot: :meth:`load_all` runs at the top of ``Broker.arequest()``;
    :meth:`set_enabled` is called from ``POST /v1/sources/{id}/{enable,disable}``
    and from the ``nautilus sources disable/enable`` CLI.
    """

    _DDL: str = _DDL
    _TABLE: str = "nautilus_source_state"

    def __init__(
        self,
        dsn: str,
        *,
        on_failure: FailureMode = "fail_closed",
        audit_logger: AuditLogger | None = None,
    ) -> None:
        super().__init__(dsn, on_failure=on_failure)
        # Optional audit emit sink (US-3, FR-59). ``None`` in unit tests that
        # don't care about the audit hop; production wiring in
        # :meth:`Broker._build_source_state_store` always injects the real
        # :class:`AuditLogger` so ``source_state_changed`` events land on the
        # same JSONL stream as request events.
        self._audit_logger: AuditLogger | None = audit_logger

    # ------------------------------------------------------------------
    # Abstract hooks
    # ------------------------------------------------------------------

    def _init_memory_backend(self) -> dict[str, SourceState]:
        """Return a fresh empty dict keyed by ``source_id``."""
        # TODO(Task 18/Phase 8): emit nautilus.source_state.store.degraded=1
        # gauge via nautilus.observability once a gauge facility is wired up;
        # for now we rely on the WARNING log in ``_handle_failure`` plus the
        # structured tag below so operators see the degrade event in logs.
        _LOG.warning(
            "source_state backend degraded to memory: disable/enable will not "
            "survive restart [nautilus.source_state.store.degraded=1]"
        )
        return {}

    def _unavailable_error(self) -> type[Exception]:
        return SourceStateStoreUnavailableError

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def load_all(self) -> dict[str, SourceState]:
        """Return every row as a ``{source_id: SourceState}`` dict.

        In ``degraded_memory`` mode, returns a shallow copy of the in-memory
        backend so callers may mutate the result without racing the store.
        """
        if self._mode == "degraded_memory":
            backend: dict[str, SourceState] = self._memory_backend
            return dict(backend)
        if self._pool is None:
            raise SourceStateStoreUnavailableError(
                "SourceStateStore.load_all() called before setup() succeeded"
            )
        rows: list[Any] = await self._pool.fetch(
            "SELECT source_id, enabled, reason, actor, changed_at FROM nautilus_source_state"
        )
        return {row["source_id"]: _row_to_state(row) for row in rows}

    async def set_enabled(
        self,
        source_id: str,
        *,
        enabled: bool,
        reason: str | None,
        actor: str,
    ) -> SourceState:
        """Upsert the row for ``source_id`` and return the post-image.

        Idempotent by design (AC-3.6): calling ``set_enabled`` twice with the
        same ``enabled`` value overwrites ``reason`` / ``actor`` and refreshes
        ``changed_at`` without raising.
        """
        now = datetime.now(UTC)
        if self._mode == "degraded_memory":
            backend: dict[str, SourceState] = self._memory_backend
            state = SourceState(
                source_id=source_id,
                enabled=enabled,
                reason=reason,
                actor=actor,
                changed_at=now,
            )
            backend[source_id] = state
            self._emit_state_changed_audit(state)
            return state
        if self._pool is None:
            raise SourceStateStoreUnavailableError(
                "SourceStateStore.set_enabled() called before setup() succeeded"
            )
        # ON CONFLICT upsert — primary key is source_id. Bump ``changed_at``
        # to now() on every write so operators can see the most recent
        # idempotent repeat (AC-3.6).
        row: Any = await self._pool.fetchrow(
            "INSERT INTO nautilus_source_state "
            "(source_id, enabled, reason, actor, changed_at) "
            "VALUES ($1, $2, $3, $4, $5) "
            "ON CONFLICT (source_id) DO UPDATE SET "
            "enabled = EXCLUDED.enabled, "
            "reason = EXCLUDED.reason, "
            "actor = EXCLUDED.actor, "
            "changed_at = EXCLUDED.changed_at "
            "RETURNING source_id, enabled, reason, actor, changed_at",
            source_id,
            enabled,
            reason,
            actor,
            now,
        )
        state = _row_to_state(row)
        self._emit_state_changed_audit(state)
        return state

    def _emit_state_changed_audit(self, state: SourceState) -> None:
        """Emit a ``source_state_changed`` :class:`AuditEntry` via the logger.

        Reuses the existing audit path (same signing, same JSONL writer) so
        operators see source enable/disable events on the single stream used
        for request + handoff events (FR-59, US-3). No-op when no logger is
        wired — tests that don't care about audit skip the emit.
        """
        if self._audit_logger is None:
            return
        entry = AuditEntry(
            event_type="source_state_changed",
            timestamp=state.changed_at,
            request_id=f"src-state-{uuid.uuid4()}",
            agent_id=state.actor or "system",
            raw_intent="",
            facts_asserted_summary={},
            routing_decisions=[],
            scope_constraints=[],
            denial_records=[],
            error_records=[],
            rule_trace=[],
            sources_queried=[state.source_id],
            sources_denied=[],
            sources_skipped=[],
            sources_errored=[],
            attestation_token=None,
            duration_ms=0,
        )
        self._audit_logger.emit(entry)

    async def get(self, source_id: str) -> SourceState | None:
        """Return the row for ``source_id`` or ``None`` if absent."""
        if self._mode == "degraded_memory":
            backend: dict[str, SourceState] = self._memory_backend
            return backend.get(source_id)
        if self._pool is None:
            raise SourceStateStoreUnavailableError(
                "SourceStateStore.get() called before setup() succeeded"
            )
        row: Any = await self._pool.fetchrow(
            "SELECT source_id, enabled, reason, actor, changed_at "
            "FROM nautilus_source_state WHERE source_id = $1",
            source_id,
        )
        if row is None:
            return None
        return _row_to_state(row)


def _row_to_state(row: Any) -> SourceState:
    """Normalize an asyncpg row (mapping-like) into a :class:`SourceState`."""
    return SourceState(
        source_id=row["source_id"],
        enabled=row["enabled"],
        reason=row["reason"],
        actor=row["actor"],
        changed_at=row["changed_at"],
    )
