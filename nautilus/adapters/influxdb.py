"""InfluxDB adapter using ``influxdb-client``.

Implements Flux query generation with scope-to-filter mapping. All scope values
flow through Flux string interpolation via parameterised helpers; no
user-supplied value is ever concatenated into a raw Flux string (NFR-4).
"""

from __future__ import annotations

import os
import time
from typing import Any, ClassVar

from nautilus.adapters.base import (
    AdapterError,
    ScopeEnforcementError,
    validate_field,
    validate_operator,
)
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# Default row cap applied when the intent does not specify a limit.
_DEFAULT_LIMIT: int = 1000


def _flux_escape(value: Any) -> str:
    """Escape a value for safe inclusion in a Flux string literal.

    Strings are double-quoted with internal quotes and backslashes escaped.
    Numerics and booleans pass through as bare literals.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    # String path — wrap in double quotes with escaping.
    s = str(value)
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


class InfluxDBAdapter:
    """InfluxDB adapter backed by ``influxdb_client.InfluxDBClient``.

    Construction is cheap; the actual client is built in :meth:`connect` so
    failures bubble up through the broker's ``sources_errored`` path
    (design §3.5 / FR-18).
    """

    source_type: ClassVar[str] = "influxdb"

    def __init__(self, client: Any = None) -> None:
        # ``client`` is optional to support injecting a mock in unit tests.
        self._client: Any = client
        self._query_api: Any = None
        self._config: SourceConfig | None = None
        self._closed: bool = False

    async def connect(self, config: SourceConfig) -> None:
        """Create the ``InfluxDBClient`` from ``config.connection``.

        Expects ``config.connection`` to be a JSON-encoded or ``|``-delimited
        string containing ``url``, ``token``, ``org``, and ``bucket``. For
        Phase 1 the connection string is treated as the InfluxDB URL and the
        remaining fields are sourced from config metadata or environment.
        """
        self._config = config

        if self._client is not None:
            # Pre-injected (tests).
            self._query_api = self._client.query_api()
            return

        try:
            from influxdb_client import (
                InfluxDBClient,  # pyright: ignore[reportMissingTypeStubs, reportPrivateImportUsage]
            )

            # Connection is the URL; token and org are picked up from standard
            # InfluxDB env vars (INFLUXDB_V2_TOKEN, INFLUXDB_V2_ORG) or passed
            # explicitly when the env vars are present.
            client_kwargs: dict[str, Any] = {"url": config.connection}
            token = os.environ.get("INFLUXDB_V2_TOKEN")
            org = os.environ.get("INFLUXDB_V2_ORG")
            if token:
                client_kwargs["token"] = token
            if org:
                client_kwargs["org"] = org
            self._client = InfluxDBClient(**client_kwargs)
            self._query_api = self._client.query_api()
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError(
                f"InfluxDBAdapter failed to connect to source '{config.id}': {exc}"
            ) from exc

    def _build_flux(
        self,
        bucket: str,
        scope: list[ScopeConstraint],
        limit: int,
    ) -> str:
        """Compose a Flux query string from scope constraints.

        Maps scope operators to Flux filter expressions:
        - ``=`` / ``!=`` → ``r["field"] == value`` / ``r["field"] != value``
        - ``<`` / ``>`` / ``<=`` / ``>=`` → numeric comparisons
        - ``IN`` → chained ``or`` predicates
        - ``NOT IN`` → chained ``and`` with ``!=``
        - ``LIKE`` → Flux ``strings.containsStr`` (simplified Phase 1)
        - ``BETWEEN`` → ``>=`` and ``<=`` pair
        - ``IS NULL`` → ``not exists r["field"]``

        Measurement/tag/time filters are derived from the field name:
        - ``_measurement`` → ``|> filter(fn: (r) => r._measurement == ...)``
        - ``_time`` → ``|> range(start: ..., stop: ...)``
        - anything else → tag filter
        """
        # Validate all constraints first.
        for constraint in scope:
            validate_operator(constraint.operator)
            validate_field(constraint.field)

        # Start with bucket source and a wide time range (overridden by _time constraints).
        range_start = "-30d"
        range_stop = "now()"
        filters: list[str] = []

        for constraint in scope:
            field = constraint.field
            op = constraint.operator
            value = constraint.value

            # Time-range constraints are lifted into |> range().
            if field == "_time":
                if op == ">=" or op == ">":
                    range_start = _flux_escape(value)
                elif op == "<=" or op == "<":
                    range_stop = _flux_escape(value)
                elif op == "BETWEEN":
                    if not isinstance(value, (list, tuple)) or len(value) != 2:  # pyright: ignore[reportUnknownArgumentType]
                        raise ScopeEnforcementError(
                            "Operator 'BETWEEN' requires a 2-tuple/list value"
                        )
                    range_start = _flux_escape(value[0])
                    range_stop = _flux_escape(value[1])
                continue

            # Tag/field/measurement filters.
            escaped_val = _flux_escape(value) if op != "IS NULL" else ""

            if op == "=":
                filters.append(f'r["{field}"] == {escaped_val}')
            elif op == "!=":
                filters.append(f'r["{field}"] != {escaped_val}')
            elif op == "<":
                filters.append(f'r["{field}"] < {escaped_val}')
            elif op == ">":
                filters.append(f'r["{field}"] > {escaped_val}')
            elif op == "<=":
                filters.append(f'r["{field}"] <= {escaped_val}')
            elif op == ">=":
                filters.append(f'r["{field}"] >= {escaped_val}')
            elif op == "IN":
                if not isinstance(value, list):
                    raise ScopeEnforcementError(
                        f"Operator 'IN' requires a list value, got {type(value).__name__}"
                    )
                or_parts = [f'r["{field}"] == {_flux_escape(v)}' for v in value]  # pyright: ignore[reportUnknownVariableType]
                filters.append(f"({' or '.join(or_parts)})")
            elif op == "NOT IN":
                if not isinstance(value, list):
                    raise ScopeEnforcementError(
                        f"Operator 'NOT IN' requires a list value, got {type(value).__name__}"
                    )
                and_parts = [f'r["{field}"] != {_flux_escape(v)}' for v in value]  # pyright: ignore[reportUnknownVariableType]
                filters.append(f"({' and '.join(and_parts)})")
            elif op == "LIKE":
                if not isinstance(value, str):
                    raise ScopeEnforcementError(
                        f"Operator 'LIKE' requires a string value, got {type(value).__name__}"
                    )
                # Simplified: strip SQL wildcards for containsStr.
                pattern = value.replace("%", "").replace("_", "?")
                filters.append(
                    f'strings.containsStr(v: r["{field}"], substr: {_flux_escape(pattern)})'
                )
            elif op == "BETWEEN":
                if not isinstance(value, (list, tuple)) or len(value) != 2:  # pyright: ignore[reportUnknownArgumentType]
                    raise ScopeEnforcementError("Operator 'BETWEEN' requires a 2-tuple/list value")
                lo = _flux_escape(value[0])
                hi = _flux_escape(value[1])
                filters.append(f'r["{field}"] >= {lo} and r["{field}"] <= {hi}')
            elif op == "IS NULL":
                filters.append(f'not exists r["{field}"]')

        # Assemble Flux.
        lines: list[str] = [
            f'from(bucket: "{bucket}")',
            f"  |> range(start: {range_start}, stop: {range_stop})",
        ]
        for f in filters:
            lines.append(f"  |> filter(fn: (r) => {f})")  # noqa: SQLGREP
        lines.append(f"  |> limit(n: {limit})")  # noqa: SQLGREP

        return "\n".join(lines)

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Run the Flux query against the client and wrap tables as rows."""
        del intent, context  # Phase 1: intent/context not consumed
        if self._client is None or self._config is None:
            raise AdapterError("InfluxDBAdapter.execute called before connect()")

        # Derive bucket from config metadata; fall back to source id.
        bucket = self._config.table or self._config.id

        flux = self._build_flux(bucket, scope, _DEFAULT_LIMIT)

        started = time.perf_counter()
        tables = self._query_api.query(flux)
        duration_ms = int((time.perf_counter() - started) * 1000)

        rows: list[dict[str, Any]] = []
        for table in tables:
            for record in table.records:
                rows.append(record.values)

        return AdapterResult(
            source_id=self._config.id,
            rows=rows,
            duration_ms=duration_ms,
        )

    async def close(self) -> None:
        """Release the HTTP client. Idempotent — second call is a no-op (FR-17)."""
        if self._closed:
            return
        self._closed = True
        client = self._client
        self._client = None
        self._query_api = None
        if client is not None:
            client.close()


__all__ = ["InfluxDBAdapter"]
