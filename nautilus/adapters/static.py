"""In-memory adapter over rows declared in ``nautilus.yaml`` (source type ``static``).

The fastest path to a working broker was to hand-transcribe an adapter class
out of the getting-started page, even though the repo already ships this exact
adapter in the ``nautilus adapters new`` template. Registering it as a built-in
source type means a first config needs no database, no driver and no code:

.. code-block:: yaml

    sources:
      - id: orders
        type: static
        classification: unclassified
        data_types: [orders]
        rows:
          - {order_id: 1001, user_id: 42, total: 19.99}

Scope constraints are enforced in Python against the declared rows, using the
same operator allowlist every other adapter validates against — an operator
this adapter cannot enforce is refused, not ignored.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any, ClassVar, cast

from nautilus.adapters.base import (
    AdapterError,
    ScopeEnforcementError,
    validate_field,
    wrap_execute,
)
from nautilus.adapters.schema import AdapterField, AdapterSchema, AdapterTable
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# What in-memory comparison can honestly enforce. ``BETWEEN`` and the ordering
# operators are deliberately absent: the values come from YAML and are not
# guaranteed mutually comparable, and a scope constraint that silently matches
# nothing is worse than one that is refused.
_VALID_OPERATORS: frozenset[str] = frozenset({"=", "!=", "IN", "NOT IN", "LIKE", "IS NULL"})


def _matches(row: dict[str, Any], constraint: ScopeConstraint) -> bool:
    """Apply one scope constraint to one row."""
    cell = row.get(constraint.field)
    value = constraint.value
    operator = constraint.operator
    if operator == "=":
        return str(cell) == str(value)
    if operator == "!=":
        return str(cell) != str(value)
    if operator in ("IN", "NOT IN"):
        values = (
            [str(v) for v in cast("list[Any]", value)] if isinstance(value, list) else [str(value)]
        )
        return (str(cell) in values) if operator == "IN" else (str(cell) not in values)
    if operator == "LIKE":
        return str(value).replace("%", "").lower() in str(cell if cell is not None else "").lower()
    # IS NULL — the only remaining member of the allowlist above.
    return cell is None or cell == ""


class StaticAdapter:
    """Serve the rows declared on a source, scoped."""

    source_type: ClassVar[str] = "static"

    def __init__(self) -> None:
        self._config: SourceConfig | None = None
        self._rows: list[dict[str, Any]] = []

    async def connect(self, config: SourceConfig) -> None:
        """Take a copy of the declared rows. No I/O, so this cannot fail."""
        self._config = config
        self._rows = [dict(row) for row in config.rows]

    @wrap_execute
    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Filter the declared rows by ``scope`` and return what survives."""
        del intent, context
        if self._config is None:
            raise AdapterError("StaticAdapter.execute() called before connect()")

        started = time.perf_counter()
        rows = self._rows
        for constraint in scope:
            if constraint.operator not in _VALID_OPERATORS:
                raise ScopeEnforcementError(
                    f"source '{self._config.id}': the static adapter cannot enforce "
                    f"operator '{constraint.operator}' (supports "
                    f"{', '.join(sorted(_VALID_OPERATORS))})"
                )
            validate_field(constraint.field)
            rows = [row for row in rows if _matches(row, constraint)]

        return AdapterResult(
            source_id=self._config.id,
            rows=rows,
            duration_ms=int((time.perf_counter() - started) * 1000),
            error=None,
        )

    async def get_schema(self) -> AdapterSchema:
        """Describe the declared rows so an edited config registers as drift."""
        if self._config is None:
            raise AdapterError("StaticAdapter.get_schema() called before connect()")
        names: list[str] = []
        for row in self._rows:
            names.extend(key for key in row if key not in names)
        return AdapterSchema(
            adapter_id=self._config.id,
            source_type=self.source_type,
            tables=(
                AdapterTable(
                    name=self._config.id,
                    fields=tuple(
                        AdapterField(name=name, type="yaml", nullable=True) for name in names
                    ),
                ),
            ),
            capability_flags={},
            fetched_at=datetime.now(UTC),
        )

    async def close(self) -> None:
        """Release the rows. Idempotent."""
        self._rows = []


__all__ = ["StaticAdapter"]
