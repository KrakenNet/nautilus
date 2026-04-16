"""Unit tests for :class:`PostgresAdapter` SQL construction + error paths (Task 3.6).

Six Done-when cases from tasks.md Task 3.6:

a) Each operator in the design §6.1 allowlist emits the correct SQL template.
b) An unknown operator raises :class:`ScopeEnforcementError`.
c) A bad field name raises :class:`ScopeEnforcementError` before SQL composition.
d) Multiple scope constraints combine with ``AND``.
e) :meth:`PostgresAdapter.close` is idempotent — second call is a no-op (FR-17).
f) A connection failure from :func:`asyncpg.create_pool` surfaces as
   :class:`AdapterError` (FR-18).

The ``asyncpg.Pool`` is replaced with :class:`unittest.mock.AsyncMock` — no real
database is contacted. ``_build_sql`` is exercised directly for the SQL-shape
cases; the lifecycle cases patch ``asyncpg.create_pool`` to either return an
``AsyncMock`` pool or raise.
"""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest

from nautilus.adapters.base import AdapterError, ScopeEnforcementError
from nautilus.adapters.postgres import PostgresAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import ScopeConstraint

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_postgres_source() -> SourceConfig:
    """A minimal postgres ``SourceConfig`` suitable for unit testing.

    ``table`` is set because ``PostgresAdapter`` requires it for Phase 1
    (see ``nautilus/adapters/postgres.py`` docstring).
    """
    return SourceConfig(
        id="vulns",
        type="postgres",
        description="vulnerability table",
        classification="secret",
        data_types=["vulnerability"],
        allowed_purposes=["research"],
        connection="postgres://localhost/vulns",
        table="vulns",
    )


def _adapter_with_config() -> PostgresAdapter:
    adapter = PostgresAdapter(pool=AsyncMock())
    adapter._config = _make_postgres_source()  # pyright: ignore[reportPrivateUsage]
    return adapter


def _build(
    adapter: PostgresAdapter,
    scope: list[ScopeConstraint],
    limit: int = 100,
    table: str = "vulns",
) -> tuple[str, list[Any]]:
    return adapter._build_sql(table=table, scope=scope, limit=limit)  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# (a) Each operator in the allowlist emits the correct SQL template.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_operator_eq_emits_equals_placeholder() -> None:
    adapter = _adapter_with_config()
    sql, params = _build(
        adapter,
        [ScopeConstraint(source_id="vulns", field="severity", operator="=", value="high")],
    )
    assert '"severity" = $1' in sql
    assert params[0] == "high"


@pytest.mark.unit
def test_operator_neq_emits_neq_placeholder() -> None:
    adapter = _adapter_with_config()
    sql, params = _build(
        adapter,
        [ScopeConstraint(source_id="vulns", field="severity", operator="!=", value="low")],
    )
    assert '"severity" != $1' in sql
    assert params[0] == "low"


@pytest.mark.unit
@pytest.mark.parametrize("op", ["<", ">", "<=", ">="])
def test_operator_relational_emits_matching_template(op: str) -> None:
    adapter = _adapter_with_config()
    sql, params = _build(
        adapter,
        [ScopeConstraint(source_id="vulns", field="cvss", operator=op, value=7.5)],  # pyright: ignore[reportArgumentType]
    )
    assert f'"cvss" {op} $1' in sql
    assert params[0] == 7.5


@pytest.mark.unit
def test_operator_in_emits_any_array_cast() -> None:
    """IN → ``ANY($n::text[])`` per design §6.1 (no string interpolation)."""
    adapter = _adapter_with_config()
    sql, params = _build(
        adapter,
        [
            ScopeConstraint(
                source_id="vulns",
                field="severity",
                operator="IN",
                value=["high", "critical"],
            )
        ],
    )
    assert '"severity" = ANY($1::text[])' in sql
    assert params[0] == ["high", "critical"]


@pytest.mark.unit
def test_operator_not_in_emits_not_all_array_cast() -> None:
    """NOT IN → ``<> ALL($n::text[])`` per design §6.1."""
    adapter = _adapter_with_config()
    sql, params = _build(
        adapter,
        [
            ScopeConstraint(
                source_id="vulns",
                field="severity",
                operator="NOT IN",
                value=["info"],
            )
        ],
    )
    assert '"severity" <> ALL($1::text[])' in sql
    assert params[0] == ["info"]


@pytest.mark.unit
def test_operator_like_emits_like_placeholder() -> None:
    adapter = _adapter_with_config()
    sql, params = _build(
        adapter,
        [ScopeConstraint(source_id="vulns", field="title", operator="LIKE", value="CVE-%")],
    )
    assert '"title" LIKE $1' in sql
    assert params[0] == "CVE-%"


@pytest.mark.unit
def test_operator_between_emits_two_placeholders() -> None:
    """BETWEEN consumes two positional placeholders ``$n AND $n+1``."""
    adapter = _adapter_with_config()
    sql, params = _build(
        adapter,
        [
            ScopeConstraint(
                source_id="vulns",
                field="cvss",
                operator="BETWEEN",
                value=[5.0, 9.0],
            )
        ],
    )
    assert '"cvss" BETWEEN $1 AND $2' in sql
    # limit param follows the BETWEEN range.
    assert params[0] == 5.0
    assert params[1] == 9.0


@pytest.mark.unit
def test_operator_is_null_emits_no_placeholder() -> None:
    """IS NULL binds no value — only the LIMIT placeholder is used."""
    adapter = _adapter_with_config()
    sql, params = _build(
        adapter,
        [ScopeConstraint(source_id="vulns", field="patched_at", operator="IS NULL", value=None)],
    )
    assert '"patched_at" IS NULL' in sql
    # Only the trailing LIMIT placeholder should be present.
    assert "LIMIT $1" in sql
    assert params == [100]


# ---------------------------------------------------------------------------
# (b) Unknown operator → ScopeEnforcementError.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_unknown_operator_raises_scope_enforcement_error() -> None:
    """An operator outside the §6.1 allowlist is rejected before SQL is built.

    ``ScopeConstraint.operator`` uses ``Literal[...]`` at the type level but
    accepts any string at runtime (pydantic only validates against the literal
    set). We bypass that guard with ``model_construct`` so the runtime
    validator inside ``_build_sql`` is exercised in isolation — exactly the
    contract §6.1 pins for defence in depth.
    """
    adapter = _adapter_with_config()
    bogus = ScopeConstraint.model_construct(
        source_id="vulns",
        field="severity",
        operator=cast(Any, "UNION"),  # not in the allowlist
        value="high",
    )

    with pytest.raises(ScopeEnforcementError):
        _build(adapter, [bogus])


# ---------------------------------------------------------------------------
# (c) Bad field name → ScopeEnforcementError.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_bad_field_name_raises_scope_enforcement_error() -> None:
    """A field failing the §6.2 regex (leading digit) is rejected at build time.

    Overlaps with ``tests/unit/test_field_identifier.py`` by design — this
    test file is the home for the full adapter suite per Task 3.6 notes.
    """
    adapter = _adapter_with_config()
    with pytest.raises(ScopeEnforcementError):
        _build(
            adapter,
            [ScopeConstraint(source_id="vulns", field="1bad", operator="=", value="x")],
        )


# ---------------------------------------------------------------------------
# (d) Multiple scopes combine with AND.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_multiple_scopes_combine_with_and() -> None:
    """Two constraints → ``WHERE a ... AND b ...`` with independent placeholders."""
    adapter = _adapter_with_config()
    sql, params = _build(
        adapter,
        [
            ScopeConstraint(source_id="vulns", field="severity", operator="=", value="high"),
            ScopeConstraint(source_id="vulns", field="cvss", operator=">=", value=7.0),
        ],
    )
    assert '"severity" = $1' in sql
    assert '"cvss" >= $2' in sql
    assert " AND " in sql
    # severity param first, cvss second, LIMIT last — positional placeholders
    # must line up ``$1, $2, $3``.
    assert params[0] == "high"
    assert params[1] == 7.0
    assert params[2] == 100  # the trailing LIMIT


# ---------------------------------------------------------------------------
# (e) close() idempotency (FR-17).
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_close_is_idempotent() -> None:
    """Second ``close()`` must be a no-op — the mock pool's ``close`` is called
    exactly once regardless of how many times the adapter is closed (FR-17)."""
    pool = AsyncMock()
    adapter = PostgresAdapter(pool=pool)
    adapter._config = _make_postgres_source()  # pyright: ignore[reportPrivateUsage]

    await adapter.close()
    await adapter.close()  # second call must not blow up or touch the pool again.

    assert pool.close.await_count == 1


# ---------------------------------------------------------------------------
# (f) Connection failure → AdapterError (FR-18).
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_connection_failure_raises_adapter_error() -> None:
    """``asyncpg.create_pool`` failure must surface as :class:`AdapterError`.

    We patch ``asyncpg.create_pool`` inside ``nautilus.adapters.postgres`` to
    raise on await. The broker layer (FR-18) converts this into a
    ``sources_errored`` entry rather than propagating to the agent.

    Per design §3.5 adapter invariants, every infra failure must present as
    an :class:`AdapterError` to the broker — which includes subclasses like
    :class:`ScopeEnforcementError`. The current adapter also surfaces the
    Phase-1 ``table`` precondition as :class:`AdapterError`; here we use a
    well-formed ``SourceConfig`` so the only failure path is ``create_pool``
    raising. ``pytest.raises(AdapterError)`` also matches any subclass that
    wraps the underlying exception.
    """
    adapter = PostgresAdapter()  # no pre-injected pool → ``connect()`` calls create_pool

    async def _boom(*_args: Any, **_kwargs: Any) -> Any:
        # Raw asyncpg surfaces connection issues as OSError-shaped errors;
        # the adapter must catch and wrap.
        raise OSError("connection refused")

    with (
        patch("nautilus.adapters.postgres.asyncpg.create_pool", side_effect=_boom),
        pytest.raises(AdapterError) as excinfo,
    ):
        await adapter.connect(_make_postgres_source())

    # The underlying OSError is chained via ``raise ... from exc`` so the
    # broker can inspect the original cause when logging.
    assert isinstance(excinfo.value.__cause__, OSError)
    assert "connection refused" in str(excinfo.value)
