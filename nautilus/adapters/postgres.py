"""PostgreSQL adapter using asyncpg.

Implements design §3.5 (PostgresAdapter) and §6 (Scope Enforcement).

All scope values flow through ``$N`` positional placeholders; no user-supplied
value is ever string-interpolated (NFR-4, AC-4.1). The operator templates come
from the table at design §6.1.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any, ClassVar, cast

import asyncpg  # pyright: ignore[reportMissingTypeStubs]

from nautilus.adapters.base import (
    AdapterError,
    ScopeEnforcementError,
    quote_identifier,
    render_field,
    validate_operator,
)
from nautilus.adapters.schema import AdapterField, AdapterSchema, AdapterTable
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# Default row cap applied when the intent does not specify a ``LIMIT``.
_DEFAULT_LIMIT: int = 1000

# Array-cast hints used by the IN / NOT IN templates (design §6.1). ``asyncpg``
# will coerce to the column's actual type at execution; ``text[]`` is the
# universal default because scope values arrive as arbitrary Python objects.
_IN_ARRAY_CAST: str = "text[]"


class PostgresAdapter:
    """PostgreSQL adapter backed by an ``asyncpg.Pool``.

    Phase 1 shortcut: requires ``SourceConfig.table`` to be set (postgres and
    pgvector sources both carry it); the cross-cutting refactor lands in
    Phase 2.
    """

    source_type: ClassVar[str] = "postgres"

    def __init__(self, pool: Any = None) -> None:
        # ``pool`` is optional to support injecting a mock pool in unit tests
        # (Done-when requirement: instantiates against a mocked ``asyncpg.Pool``
        # without error). ``connect()`` is the normal construction path.
        self._pool: Any = pool
        self._config: SourceConfig | None = None
        self._closed: bool = False

    async def connect(self, config: SourceConfig) -> None:
        """Create the ``asyncpg.Pool`` from ``config.connection`` (DSN)."""
        if config.table is None:
            raise AdapterError(
                f"PostgresAdapter requires 'table' on source '{config.id}' (Phase 1 shortcut)"
            )
        self._config = config
        if self._pool is None:
            # asyncpg has no stubs; result is typed Any via the ignore above.
            # Any infra failure from ``create_pool`` is wrapped as
            # :class:`AdapterError` per design §3.5 / FR-18 so the broker can
            # record a ``sources_errored`` entry rather than propagating the
            # raw asyncpg / OSError to the agent.
            try:
                self._pool = await asyncpg.create_pool(dsn=config.connection)  # pyright: ignore[reportUnknownMemberType]
            except AdapterError:
                raise
            except Exception as exc:
                raise AdapterError(
                    f"PostgresAdapter failed to connect to source '{config.id}': {exc}"
                ) from exc

    async def close(self) -> None:
        """Release the pool. Idempotent — second call is a no-op (FR-17)."""
        if self._closed:
            return
        self._closed = True
        pool = self._pool
        self._pool = None
        if pool is not None:
            await pool.close()

    def _build_sql(
        self,
        table: str,
        scope: list[ScopeConstraint],
        limit: int,
    ) -> tuple[str, list[Any]]:
        """Compose a parameterized ``SELECT`` using only positional placeholders.

        Returns ``(sql, params)`` where ``params`` are positional values aligned
        to ``$1..$N`` in ``sql``. ``table`` is treated as a trusted identifier
        (validated at config-load time) but is still quoted with double quotes.

        Each operator branch renders per the §6.1 template table.
        """
        # ``table`` is trusted config (validated at config-load time) but
        # still routed through :func:`quote_identifier` so the regex guard and
        # double-quoting happen in one vetted helper (NFR-4, Task 2.8).
        quoted_table = quote_identifier(table.split(".")[-1])

        where_clauses: list[str] = []
        params: list[Any] = []
        pidx = 1  # next positional placeholder index

        for constraint in scope:
            validate_operator(constraint.operator)
            # ``render_field`` re-runs ``validate_field`` so invalid idents
            # (e.g. leading digit, embedded quote) raise before any SQL is
            # composed — no injection vector reaches the f-string.
            field_sql = render_field(constraint.field)
            op = constraint.operator
            value = constraint.value

            if op in ("=", "!=", "<", ">", "<=", ">="):
                where_clauses.append(f"{field_sql} {op} ${pidx}")
                params.append(value)
                pidx += 1
            elif op == "IN":
                if not isinstance(value, list):
                    raise ScopeEnforcementError(
                        f"Operator 'IN' requires a list value, got {type(value).__name__}"
                    )
                where_clauses.append(f"{field_sql} = ANY(${pidx}::{_IN_ARRAY_CAST})")
                params.append(value)
                pidx += 1
            elif op == "NOT IN":
                if not isinstance(value, list):
                    raise ScopeEnforcementError(
                        f"Operator 'NOT IN' requires a list value, got {type(value).__name__}"
                    )
                where_clauses.append(f"{field_sql} <> ALL(${pidx}::{_IN_ARRAY_CAST})")
                params.append(value)
                pidx += 1
            elif op == "LIKE":
                if not isinstance(value, str):
                    raise ScopeEnforcementError(
                        f"Operator 'LIKE' requires a string value, got {type(value).__name__}"
                    )
                where_clauses.append(f"{field_sql} LIKE ${pidx}")
                params.append(value)
                pidx += 1
            elif op == "BETWEEN":
                if not (isinstance(value, (list, tuple)) and len(cast(Any, value)) == 2):
                    raise ScopeEnforcementError("Operator 'BETWEEN' requires a 2-tuple/list value")
                value_seq: list[Any] = list(cast(Any, value))
                where_clauses.append(f"{field_sql} BETWEEN ${pidx} AND ${pidx + 1}")
                params.extend(value_seq)
                pidx += 2
            elif op == "IS NULL":
                where_clauses.append(f"{field_sql} IS NULL")
            else:  # pragma: no cover  # unreachable: validate_operator guards this branch
                raise ScopeEnforcementError(f"Operator '{op}' unhandled in _build_sql")

        # ``LIMIT $N`` is always the last positional placeholder — asserts the
        # Done-when requirement that the generated SQL contains a positional
        # placeholder (even when ``scope`` is empty).
        where_sql = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        sql = f"SELECT * FROM {quoted_table}{where_sql} LIMIT ${pidx}"
        params.append(limit)
        return sql, params

    # Method definition — the grep guard's DB-call regex (Task 3.13) matches
    # ``execute(`` and this sits within 5 lines of the ``_build_sql`` f-string
    # at the tail of ``_build_sql``. The f-string uses only ``$N`` positional
    # placeholders (hardened in Task 2.8); tag the method line so the guard
    # treats it as a non-call.
    async def execute(  # noqa: SQLGREP
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Run the parameterized query against the pool and wrap rows."""
        del intent, context  # Phase 1: intent/context not consumed by postgres adapter
        if self._pool is None or self._config is None:
            raise AdapterError("PostgresAdapter.execute called before connect()")
        table = self._config.table
        if table is None:
            raise AdapterError(f"PostgresAdapter missing 'table' for source '{self._config.id}'")

        sql, params = self._build_sql(table, scope, _DEFAULT_LIMIT)

        started = time.perf_counter()
        async with self._pool.acquire() as conn:
            records = await conn.fetch(sql, *params)
        duration_ms = int((time.perf_counter() - started) * 1000)

        rows: list[dict[str, Any]] = [dict(r) for r in records]
        return AdapterResult(
            source_id=self._config.id,
            rows=rows,
            duration_ms=duration_ms,
        )

    async def get_schema(self) -> AdapterSchema:
        """Return schema via ``information_schema`` queries. AC-21, OQ3."""
        if self._pool is None or self._config is None:
            return AdapterSchema.unknown(
                self._config.id if self._config else "postgres",
                self.source_type,
            )
        try:
            async with self._pool.acquire() as conn:
                col_rows = await conn.fetch(
                    """
                    SELECT table_name, column_name, data_type, is_nullable
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                    ORDER BY table_name, ordinal_position
                    """
                )
                idx_rows = await conn.fetch(
                    """
                    SELECT tablename, indexname
                    FROM pg_indexes
                    WHERE schemaname = 'public'
                    ORDER BY tablename, indexname
                    """
                )
                pk_rows = await conn.fetch(
                    """
                    SELECT tc.table_name, kcu.column_name
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu
                      ON tc.constraint_name = kcu.constraint_name
                     AND tc.table_schema = kcu.table_schema
                    WHERE tc.constraint_type = 'PRIMARY KEY'
                      AND tc.table_schema = 'public'
                    ORDER BY tc.table_name, kcu.ordinal_position
                    """
                )

            # Group columns by table.
            tables_cols: dict[str, list[AdapterField]] = {}
            for row in col_rows:
                tname = row["table_name"]
                tables_cols.setdefault(tname, []).append(
                    AdapterField(
                        name=row["column_name"],
                        type=row["data_type"],
                        nullable=(row["is_nullable"] == "YES"),
                    )
                )

            # Group indexes by table.
            tables_idx: dict[str, list[str]] = {}
            for row in idx_rows:
                tables_idx.setdefault(row["tablename"], []).append(row["indexname"])

            # Group PKs by table.
            tables_pk: dict[str, list[str]] = {}
            for row in pk_rows:
                tables_pk.setdefault(row["table_name"], []).append(row["column_name"])

            adapter_tables = tuple(
                AdapterTable(
                    name=tname,
                    fields=tuple(fields),
                    indexes=tuple(tables_idx.get(tname, [])),
                    primary_key=tuple(tables_pk.get(tname, [])),
                )
                for tname, fields in sorted(tables_cols.items())
            )
            return AdapterSchema(
                adapter_id=self._config.id,
                source_type=self.source_type,
                tables=adapter_tables,
                capability_flags={"deterministic": True},
                fetched_at=datetime.now(UTC),
            )
        except Exception:  # noqa: BLE001
            return AdapterSchema.unknown(self._config.id, self.source_type)


__all__ = ["PostgresAdapter"]
