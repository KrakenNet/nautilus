"""Example: CSV file adapter built with the Nautilus Adapter SDK.

Demonstrates how to implement the Adapter protocol for a simple data source.
This adapter reads CSV files and applies scope constraints as row filters.

Usage:
    See README.md for instructions, or run the compliance suite:
        pytest test_compliance.py -v
"""

from __future__ import annotations

import csv
import time
from pathlib import Path
from typing import Any, ClassVar

from nautilus_adapter_sdk.config import SourceConfig
from nautilus_adapter_sdk.exceptions import AdapterError, ScopeEnforcementError
from nautilus_adapter_sdk.protocols import Adapter
from nautilus_adapter_sdk.types import AdapterResult, IntentAnalysis, ScopeConstraint

# Operators supported by this adapter.
_VALID_OPERATORS = {"=", "!=", "IN", "NOT IN", "LIKE", "IS NULL"}


class CsvAdapter:
    """CSV file adapter — reads rows from a CSV and applies scope filters.

    ``source_type`` is ``"csv"`` and is registered via the
    ``nautilus.adapters`` entry-point group in pyproject.toml:

        [project.entry-points."nautilus.adapters"]
        csv = "my_csv_adapter:CsvAdapter"
    """

    source_type: ClassVar[str] = "csv"

    def __init__(self) -> None:
        self._path: Path | None = None
        self._headers: list[str] = []
        self._rows: list[dict[str, str]] = []
        self._closed: bool = False

    async def connect(self, config: SourceConfig) -> None:
        """Load the CSV file specified by ``config.connection``.

        ``config.connection`` should be the file path (string).
        ``config.table`` is unused for CSV but could specify a sheet name
        in a future multi-sheet extension.
        """
        path = Path(str(config.connection))
        if not path.is_file():
            raise AdapterError(f"CSV file not found: {path}")

        self._path = path
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            self._headers = list(reader.fieldnames or [])
            self._rows = list(reader)

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Filter CSV rows by scope constraints and return matches."""
        if self._path is None:
            raise AdapterError("CsvAdapter.execute() called before connect()")

        started = time.perf_counter()
        rows = list(self._rows)

        for constraint in scope:
            op = constraint.operator
            if op not in _VALID_OPERATORS:
                raise ScopeEnforcementError(
                    f"CsvAdapter: unsupported operator '{op}'"
                )

            field = constraint.field
            value = constraint.value

            if op == "=":
                rows = [r for r in rows if r.get(field) == str(value)]
            elif op == "!=":
                rows = [r for r in rows if r.get(field) != str(value)]
            elif op == "IN":
                values = [str(v) for v in value] if isinstance(value, list) else [str(value)]
                rows = [r for r in rows if r.get(field) in values]
            elif op == "NOT IN":
                values = [str(v) for v in value] if isinstance(value, list) else [str(value)]
                rows = [r for r in rows if r.get(field) not in values]
            elif op == "LIKE":
                pattern = str(value).replace("%", "").lower()
                rows = [r for r in rows if pattern in r.get(field, "").lower()]
            elif op == "IS NULL":
                rows = [r for r in rows if not r.get(field)]

        duration_ms = int((time.perf_counter() - started) * 1000)

        return AdapterResult(
            source_id=constraint.source_id if scope else "csv",
            data=rows,
            metadata={
                "row_count": len(rows),
                "total_rows": len(self._rows),
                "headers": self._headers,
                "file": str(self._path),
                "duration_ms": duration_ms,
            },
        )

    async def close(self) -> None:
        """Release resources. Idempotent — second call is a no-op."""
        if self._closed:
            return
        self._closed = True
        self._rows = []
        self._headers = []


__all__ = ["CsvAdapter"]
