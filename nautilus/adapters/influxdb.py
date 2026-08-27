"""InfluxDB adapter using ``influxdb-client``.

Implements Flux query generation with scope-to-filter mapping. All scope values
flow through Flux string interpolation via parameterised helpers; no
user-supplied value is ever concatenated into a raw Flux string (NFR-4).
"""

from __future__ import annotations

import os
import re
import time
from datetime import UTC, datetime
from typing import Any, ClassVar

from nautilus.adapters.base import (
    AdapterError,
    ScopeEnforcementError,
    validate_field,
    validate_operator,
    wrap_execute,
)
from nautilus.adapters.schema import AdapterField, AdapterSchema, AdapterTable
from nautilus.config.models import BearerAuth, NoneAuth, SourceConfig
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


# Flux duration literal (``-30d``, ``1h30m``) and RFC3339 instant. ``range()``
# takes a time or a duration, never a string, so a bound has to be emitted bare
# -- which means it has to be validated here instead of being neutralised by
# quoting (NFR-4).
_DURATION_RE = re.compile(r"^-?\d+(ns|us|ms|s|m|h|d|w|mo|y)(\d+(ns|us|ms|s|m|h|d|w|mo|y))*$")
_RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def _flux_time(value: Any) -> str:
    """Render a ``_time`` bound as a Flux time/duration literal.

    ``_flux_escape`` quoted every non-numeric bound, and Flux's ``range()``
    rejects a string: ``range(start: "2023-11-14T00:00:00Z")`` is a type
    error, so every time-scoped query failed closed with an ``ErrorRecord``
    and the caller saw an empty result. Bare emission means the value cannot
    be neutralised by quoting, so the three shapes ``range()`` accepts are
    matched explicitly and anything else is refused.
    """
    if isinstance(value, bool):  # bool is an int subclass; never a time bound.
        raise ScopeEnforcementError(
            f"InfluxDBAdapter: '_time' bound {value!r} is not a time, duration or "
            f"Unix-second integer"
        )
    if isinstance(value, int):
        return str(value)  # Unix seconds -- what range() takes for an integer.
    s = str(value)
    if _DURATION_RE.match(s) or _RFC3339_RE.match(s):
        return s
    raise ScopeEnforcementError(
        f"InfluxDBAdapter: '_time' bound {value!r} is not a Flux duration "
        f"(e.g. '-30d'), an RFC3339 instant (e.g. '2023-11-14T00:00:00Z') or a "
        f"Unix-second integer"
    )


# Seconds per Flux duration unit. ``mo``/``y`` are averages: these values are
# used only to *compare* two bounds, never to build the query, which always
# emits the operator's own literal.
_UNIT_SECONDS: dict[str, float] = {
    "ns": 1e-9,
    "us": 1e-6,
    "ms": 1e-3,
    "mo": 2629800.0,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
    "w": 604800.0,
    "y": 31557600.0,
}
_DURATION_PART_RE = re.compile(r"(\d+)(ns|us|ms|mo|s|m|h|d|w|y)")


def _bound_seconds(literal: str, now: float) -> float:
    """Absolute epoch seconds for a ``range()`` bound, for comparison only."""
    if literal == "now()":
        return now
    if _RFC3339_RE.match(literal):
        return datetime.fromisoformat(literal.replace("Z", "+00:00")).timestamp()
    if _DURATION_RE.match(literal):
        sign = -1.0 if literal.startswith("-") else 1.0
        total = sum(
            int(n) * _UNIT_SECONDS[u] for n, u in _DURATION_PART_RE.findall(literal.lstrip("-"))
        )
        return now + sign * total
    return float(literal)  # Unix seconds.


def _narrow(current: str, bound: str, now: float, *, lower: bool) -> str:
    """Intersect a time bound with the one already in force.

    Both slots used to be assigned, so a second bound on the same side replaced
    the first: a rule that had narrowed the window to the last hour was widened
    back to the 30-day default by a looser bound arriving after it. Scope
    constraints only ever narrow.
    """
    keep = _bound_seconds(current, now) >= _bound_seconds(bound, now)
    return current if keep == lower else bound


def _flux_like(field: str, pattern: str) -> str:
    """Translate a SQL ``LIKE`` pattern into an equivalently anchored Flux test.

    The previous translation stripped every ``%`` and always emitted
    ``containsStr``, so the anchored pattern ``public/%`` also matched
    ``internal/restricted/public/leak`` -- a widening of the constraint. Each
    anchoring now maps to the Flux predicate that means the same thing.

    ``_`` (single-character wildcard) has no Flux equivalent and used to be
    rewritten to a literal ``?``, which matched nothing; it raises now rather
    than silently changing the predicate in either direction.
    """
    if "_" in pattern:
        raise ScopeEnforcementError(
            f"InfluxDBAdapter: LIKE pattern {pattern!r} uses the '_' single-character "
            f"wildcard, which Flux cannot express"
        )
    ref = f'r["{field}"]'
    starts, ends = pattern.startswith("%"), pattern.endswith("%")
    body = pattern[1 if starts else None : -1 if ends else None]
    if "%" in body:
        raise ScopeEnforcementError(
            f"InfluxDBAdapter: LIKE pattern {pattern!r} has an interior '%' wildcard, "
            f"which Flux cannot express"
        )
    escaped = _flux_escape(body)
    if starts and ends:
        return f"strings.containsStr(v: {ref}, substr: {escaped})"
    if starts:
        return f"strings.hasSuffix(v: {ref}, suffix: {escaped})"
    if ends:
        return f"strings.hasPrefix(v: {ref}, prefix: {escaped})"
    return f"{ref} == {escaped}"


def _auth_token(config: SourceConfig) -> str | None:
    """The token a source's ``auth:`` block declares, if it can be one.

    ``config.auth`` was read by nothing here, so a source that declared
    credentials connected with whatever ``INFLUXDB_V2_TOKEN`` happened to hold
    — or with none. InfluxDB v2 authenticates with a token, so ``bearer`` is
    the block that maps; anything else is named and refused the way
    :mod:`nautilus.adapters.s3` refuses an auth type it cannot honour.
    """
    auth = config.auth
    if auth is None or isinstance(auth, NoneAuth):
        return None
    if isinstance(auth, BearerAuth):
        return auth.token
    raise AdapterError(
        f"InfluxDBAdapter: source '{config.id}' declares auth type {auth.type!r}, which "
        f"InfluxDB cannot use. Use 'bearer' (token=the InfluxDB API token), or omit "
        f"'auth' to read INFLUXDB_V2_TOKEN from the environment."
    )


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

            # Connection is the URL. The token comes from the source's own
            # ``auth: {type: bearer}`` block when it declares one, else from the
            # standard InfluxDB env vars (INFLUXDB_V2_TOKEN, INFLUXDB_V2_ORG).
            client_kwargs: dict[str, Any] = {"url": config.connection}
            token = _auth_token(config) or os.environ.get("INFLUXDB_V2_TOKEN")
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
        - ``LIKE`` → ``strings.hasPrefix`` / ``hasSuffix`` / ``containsStr``
          / equality, chosen by where the ``%`` wildcards sit
        - ``BETWEEN`` → ``>=`` and ``<=`` pair
        - ``IS NULL`` → ``not exists r["field"]``

        Measurement/tag/time filters are derived from the field name:
        - ``_measurement`` → ``|> filter(fn: (r) => r._measurement == ...)``
        - ``_time`` → ``|> range(start: ..., stop: ...)``; an operator that
          cannot be lifted into a range raises rather than being dropped
        - anything else → tag filter
        """
        # Validate all constraints first.
        for constraint in scope:
            validate_operator(constraint.operator)
            validate_field(constraint.field)

        # Start with bucket source and a wide time range (narrowed by _time
        # constraints; see ``_narrow``).
        range_start = "-30d"
        range_stop = "now()"
        now = time.time()
        filters: list[str] = []

        for constraint in scope:
            field = constraint.field
            op = constraint.operator
            value = constraint.value

            # Time-range constraints are lifted into |> range().
            if field == "_time":
                if op == ">=" or op == ">":
                    range_start = _narrow(range_start, _flux_time(value), now, lower=True)
                elif op == "<=" or op == "<":
                    range_stop = _narrow(range_stop, _flux_time(value), now, lower=False)
                elif op == "BETWEEN":
                    if not isinstance(value, (list, tuple)) or len(value) != 2:  # pyright: ignore[reportUnknownArgumentType]
                        raise ScopeEnforcementError(
                            "Operator 'BETWEEN' requires a 2-tuple/list value"
                        )
                    range_start = _narrow(range_start, _flux_time(value[0]), now, lower=True)
                    range_stop = _narrow(range_stop, _flux_time(value[1]), now, lower=False)
                else:
                    # Anything the range lift cannot express used to fall
                    # through an unconditional `continue`: the constraint
                    # vanished with no error and no denial, leaving the
                    # wide-open -30d default window. Fail closed instead.
                    raise ScopeEnforcementError(
                        f"InfluxDBAdapter: operator {op!r} is not expressible as a "
                        f"time range on '_time' (use <, <=, >, >= or BETWEEN)"
                    )
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
                filters.append(_flux_like(field, value))
            elif op == "BETWEEN":
                if not isinstance(value, (list, tuple)) or len(value) != 2:  # pyright: ignore[reportUnknownArgumentType]
                    raise ScopeEnforcementError("Operator 'BETWEEN' requires a 2-tuple/list value")
                lo = _flux_escape(value[0])
                hi = _flux_escape(value[1])
                filters.append(f'r["{field}"] >= {lo} and r["{field}"] <= {hi}')
            elif op == "IS NULL":
                filters.append(f'not exists r["{field}"]')

        # Assemble Flux. ``_flux_like`` reaches for the ``strings`` package,
        # which Flux does not load implicitly: without the import the server
        # rejects the whole query as an undefined identifier, so every LIKE-
        # scoped read failed closed. ``get_schema`` already imports its package.
        lines: list[str] = []
        if any("strings." in f for f in filters):
            lines.append('import "strings"')
        lines += [
            f'from(bucket: "{bucket}")',
            f"  |> range(start: {range_start}, stop: {range_stop})",
        ]
        for f in filters:
            lines.append(f"  |> filter(fn: (r) => {f})")  # sqlgrep: ignore
        lines.append(f"  |> limit(n: {limit})")  # sqlgrep: ignore

        return "\n".join(lines)

    @wrap_execute
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
            truncated=len(rows) >= _DEFAULT_LIMIT,
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

    async def get_schema(self) -> AdapterSchema:
        """Return schema via SHOW MEASUREMENTS + SHOW FIELD KEYS. AC-21, OQ3.

        Raises on a backend outage rather than returning
        :meth:`AdapterSchema.unknown`. Swallowing the error made an outage
        indistinguishable from major schema drift: the broker quarantined the
        source and wrote ``schema_drift_detected`` describing an event that did
        not occur, and ``schema-ack`` -- the prescribed remediation -- baselined
        the ``unknown()`` fingerprint, re-quarantining the source when the
        backend *recovered*. ``Broker._check_adapter_schema`` already handles a
        raising ``get_schema`` by skipping the fingerprint check.
        """
        if self._query_api is None or self._config is None:
            return AdapterSchema.unknown(
                self._config.id if self._config else "influxdb",
                self.source_type,
            )
        bucket = self._config.table or self._config.id
        try:
            meas_flux = (
                f'import "influxdata/influxdb/schema"\nschema.measurements(bucket: "{bucket}")'
            )
            meas_tables: Any = self._query_api.query(meas_flux)
            measurements: list[str] = []
            for table in meas_tables:
                for record in table.records:
                    val = record.get_value()
                    if val is not None:
                        measurements.append(str(val))

            adapter_tables: list[AdapterTable] = []
            for meas in measurements:
                fields_flux = (
                    f'import "influxdata/influxdb/schema"\n'
                    f'schema.measurementFieldKeys(bucket: "{bucket}", measurement: "{meas}")'
                )
                field_tables: Any = self._query_api.query(fields_flux)
                field_list: list[AdapterField] = []
                for ft in field_tables:
                    for record in ft.records:
                        fname = record.get_value()
                        if fname is not None:
                            field_list.append(
                                AdapterField(name=str(fname), type="field", nullable=True)
                            )
                adapter_tables.append(AdapterTable(name=meas, fields=tuple(field_list)))

            return AdapterSchema(
                adapter_id=self._config.id,
                source_type=self.source_type,
                tables=tuple(adapter_tables),
                capability_flags={"deterministic": False},
                fetched_at=datetime.now(UTC),
            )
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError(
                f"influxdb: get_schema failed for source '{self._config.id}': {exc}"
            ) from exc


__all__ = ["InfluxDBAdapter"]
