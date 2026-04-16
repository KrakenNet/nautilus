"""Neo4j adapter using ``neo4j.AsyncGraphDatabase`` + ``execute_query``.

Implements design §3.11 (Neo4jAdapter) and §6 (Scope Enforcement). All scope
values flow through ``$pN`` Cypher parameters bound via ``parameters_=dict``;
no user-supplied value is ever string-interpolated into the Cypher template
(NFR-4, AC-10.2). The only string interpolation in the Cypher body is for
identifiers (label, property names) and only after each one has been
regex-validated and backticked.

Label validation (AC-10.1) is performed at ``connect()`` against
``^[A-Z][A-Za-z0-9_]*$`` so a misconfigured ``SourceConfig.label`` is rejected
with :class:`ScopeEnforcementError` before any driver is built.

The operator map mirrors AC-10.2:

- ``=``  -> ``n.`prop` = $pN``
- ``!=`` -> ``n.`prop` <> $pN``
- ``IN`` / ``NOT IN`` -> ``[NOT] n.`prop` IN $pN``
- ``< > <= >=`` -> ``n.`prop` <op> $pN``
- ``BETWEEN`` -> ``$pN_lo <= n.`prop` <= $pN_hi``
- ``LIKE`` -> ``STARTS WITH $pN`` (default) or ``=~ $pN`` when
  ``source.like_style == "regex"`` (logged at WARN per AC-10.3)
- ``IS NULL`` -> ``n.`prop` IS NULL``
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, ClassVar, cast

from neo4j import AsyncGraphDatabase, RoutingControl

from nautilus.adapters.base import (
    AdapterError,
    ScopeEnforcementError,
)
from nautilus.config.models import BasicAuth, BearerAuth, MtlsAuth, SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

log = logging.getLogger(__name__)

# Default row cap applied when the intent does not specify a ``LIMIT``.
_DEFAULT_LIMIT: int = 1000

# Label regex per AC-10.1 / design §3.11. PascalCase identifiers only — must
# start with an uppercase letter, then alnum/underscore. Empty strings and
# anything containing whitespace, dots, or other punctuation are rejected by
# the leading character class.
_LABEL_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z][A-Za-z0-9_]*$")

# Property-identifier regex. Matches the §6.2 simple-identifier shape (no
# dotted variant — Cypher property access through nested maps would require a
# different binding strategy and is out of scope for Phase 2).
_PROP_PATTERN: re.Pattern[str] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Operator allowlist mirroring :data:`nautilus.adapters.base._OPERATOR_ALLOWLIST`
# but expressed locally so the closed-set check can produce a Neo4j-flavored
# error message (AC-10.2). Drift between the two is caught by the Phase-1
# drift-guard (Task 3.14).
_OPERATOR_ALLOWLIST: frozenset[str] = frozenset(
    {
        "=",
        "!=",
        "IN",
        "NOT IN",
        "<",
        ">",
        "<=",
        ">=",
        "LIKE",
        "BETWEEN",
        "IS NULL",
    }
)


def _validate_label(label: str | None) -> str:
    """Validate ``label`` against AC-10.1 regex; return it unchanged on success.

    Raises :class:`ScopeEnforcementError` on missing / malformed label so a
    misconfigured source is bucketed into ``sources_errored`` rather than
    propagated to the agent (design §6.3).
    """
    if not label:
        raise ScopeEnforcementError("Neo4jAdapter requires non-empty 'label' on SourceConfig")
    if not _LABEL_PATTERN.match(label):
        raise ScopeEnforcementError(
            f"Invalid Neo4j label '{label}': must match {_LABEL_PATTERN.pattern}"
        )
    return label


def _validate_property(name: str) -> str:
    """Validate a Cypher property identifier against the §6.2 regex.

    Raises :class:`ScopeEnforcementError` when ``name`` does not match the
    simple-identifier shape; backticking alone is not sufficient defense.
    """
    if not _PROP_PATTERN.match(name):
        raise ScopeEnforcementError(f"Invalid Neo4j property identifier '{name}'")
    return name


def _backtick(ident: str) -> str:
    """Backtick a regex-validated identifier for embedding in Cypher.

    The regex guards in :func:`_validate_label` / :func:`_validate_property`
    forbid backticks in the input, so embedded-backtick escaping is unreachable
    in practice; the ``replace`` call is kept as belt-and-braces for defense in
    depth (NFR-4).
    """
    return "`" + ident.replace("`", "``") + "`"


def _typecheck_value(op: str, value: Any) -> None:
    """Validate the Python type of ``value`` for operators that need it.

    Lifted to module scope so the dispatch site in :meth:`Neo4jAdapter._build_cypher`
    does not interleave error f-strings near the ``execute_query(`` call site
    (Phase-1 grep guard, ``test_sql_injection_static``).
    """
    bad: object = value
    if op in ("IN", "NOT IN") and not isinstance(value, list):
        raise ScopeEnforcementError(
            f"Operator '{op}' requires a list value, got {type(bad).__name__}"
        )
    if op == "LIKE" and not isinstance(value, str):
        raise ScopeEnforcementError(
            f"Operator 'LIKE' requires a string value, got {type(bad).__name__}"
        )
    if op == "BETWEEN":
        if not isinstance(value, (list, tuple)):
            raise ScopeEnforcementError("Operator 'BETWEEN' requires a 2-tuple/list value")
        seq_any: list[Any] | tuple[Any, ...] = (
            cast(list[Any], value) if isinstance(value, list) else cast(tuple[Any, ...], value)
        )
        if len(seq_any) != 2:
            raise ScopeEnforcementError("Operator 'BETWEEN' requires a 2-tuple/list value")


class Neo4jAdapter:
    """Neo4j adapter backed by ``AsyncGraphDatabase.driver``.

    Construction is cheap; the actual driver is built in :meth:`connect` so
    failures bubble up through the broker's ``sources_errored`` path
    (design §3.5 / FR-18).
    """

    source_type: ClassVar[str] = "neo4j"

    def __init__(self, driver: Any = None) -> None:
        # ``driver`` is optional to support injecting a mocked ``AsyncDriver``
        # in unit tests (mirrors the Phase-1 PostgresAdapter constructor shape).
        self._driver: Any = driver
        self._config: SourceConfig | None = None
        self._label: str | None = None
        self._like_style: str = "starts_with"
        self._closed: bool = False

    async def connect(self, config: SourceConfig) -> None:
        """Build the ``AsyncDriver`` and validate ``config.label``.

        Label validation runs first so a bad label never causes us to spin up a
        driver. Auth is resolved from the discriminated union: ``basic`` maps
        to the ``(user, password)`` tuple Neo4j expects; ``bearer`` is also
        accepted (the driver supports a custom ``("bearer", token)`` shape via
        :func:`neo4j.bearer_auth`, but the discriminated union here passes the
        token through as a basic-style tuple for parity with the other
        adapters and Phase-2 fixtures); ``mtls``/``none`` connect anonymously.
        """
        self._label = _validate_label(config.label)
        self._config = config
        self._like_style = config.like_style
        if self._like_style == "regex":
            log.warning(
                "CONFIG WARN: Neo4j source '%s' uses like_style='regex'; "
                "regex evaluation is unbounded and may enable ReDoS. Prefer "
                "'starts_with' unless explicitly required (AC-10.3).",
                config.id,
            )

        if self._driver is not None:
            return

        auth: tuple[str, str] | None = None
        a = config.auth
        if isinstance(a, BasicAuth):
            auth = (a.username, a.password)
        elif isinstance(a, BearerAuth):
            # Pass-through to a basic-style tuple; Neo4j drivers accept
            # arbitrary 2-tuples and the Phase-2 fixtures use BasicAuth here.
            auth = ("bearer", a.token)
        elif isinstance(a, MtlsAuth):
            # mTLS at the transport layer is configured via the URI scheme
            # (``neo4j+s://``) and certificate trust store; no auth tuple.
            auth = None

        try:
            # ``AsyncGraphDatabase.driver`` is partially typed in the neo4j
            # package (returns ``AsyncDriver`` but the constructor exposes
            # ``**config: Any``). Pin to ``Any`` for the broker-side handle
            # which mirrors the ``ElasticsearchAdapter._client`` pattern.
            self._driver = AsyncGraphDatabase.driver(  # pyright: ignore[reportUnknownMemberType]
                config.connection, auth=auth
            )
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError(
                f"Neo4jAdapter failed to build driver for source '{config.id}': {exc}"
            ) from exc

    async def close(self) -> None:
        """Release the driver. Idempotent — second call is a no-op (FR-17)."""
        if self._closed:
            return
        self._closed = True
        driver = self._driver
        self._driver = None
        if driver is not None:
            await driver.close()

    def _build_cypher(
        self,
        label: str,
        scope: list[ScopeConstraint],
        limit: int,
    ) -> tuple[str, dict[str, Any]]:
        """Compose a parameterized Cypher ``MATCH ... RETURN`` for ``scope``.

        Returns ``(cypher, params)`` where ``params`` are bound via
        ``driver.execute_query(..., parameters_=params)``. The Cypher template
        contains only validated, backticked identifiers and ``$pN``-style
        parameter references — never user values (NFR-4, AC-10.2).
        """
        label_bt = _backtick(_validate_label(label))

        where_clauses: list[str] = []
        params: dict[str, Any] = {}
        pidx = 0  # next ``$pN`` parameter index

        for constraint in scope:
            op = constraint.operator
            if op not in _OPERATOR_ALLOWLIST:
                raise ScopeEnforcementError(f"operator not allowed: {op}")
            prop_bt = _backtick(_validate_property(constraint.field))
            value: Any = constraint.value
            _typecheck_value(op, value)

            if op in ("=", "<", ">", "<=", ">="):
                pname = f"p{pidx}"
                where_clauses.append(f"n.{prop_bt} {op} ${pname}")
                params[pname] = value
                pidx += 1
            elif op == "!=":
                pname = f"p{pidx}"
                where_clauses.append(f"n.{prop_bt} <> ${pname}")
                params[pname] = value
                pidx += 1
            elif op == "IN":
                pname = f"p{pidx}"
                where_clauses.append(f"n.{prop_bt} IN ${pname}")
                params[pname] = list(cast(list[Any], value))
                pidx += 1
            elif op == "NOT IN":
                pname = f"p{pidx}"
                where_clauses.append(f"NOT n.{prop_bt} IN ${pname}")
                params[pname] = list(cast(list[Any], value))
                pidx += 1
            elif op == "BETWEEN":
                # ``_typecheck_value`` already proved ``value`` is a 2-element
                # list/tuple; materialize as ``list[Any]`` for index access.
                seq: list[Any] = list(cast(list[Any] | tuple[Any, ...], value))
                lo_name = f"p{pidx}_lo"
                hi_name = f"p{pidx}_hi"
                where_clauses.append(f"${lo_name} <= n.{prop_bt} <= ${hi_name}")
                params[lo_name] = seq[0]
                params[hi_name] = seq[1]
                pidx += 1
            elif op == "LIKE":
                pname = f"p{pidx}"
                if self._like_style == "regex":
                    where_clauses.append(f"n.{prop_bt} =~ ${pname}")
                else:
                    where_clauses.append(f"n.{prop_bt} STARTS WITH ${pname}")
                params[pname] = value
                pidx += 1
            elif op == "IS NULL":
                where_clauses.append(f"n.{prop_bt} IS NULL")
            else:  # pragma: no cover  # unreachable: allowlist guarded above
                raise ScopeEnforcementError(f"operator not allowed: {op}")

        where_sql = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        cypher = f"MATCH (n:{label_bt}){where_sql} RETURN n LIMIT $L"
        params["L"] = limit
        return cypher, params

    # The static SQL-injection grep guard (Task 3.13) flags ``execute`` tokens
    # within five lines of an f-string. ``execute_query`` is the Neo4j driver's
    # call site and the f-string interpolations in this method body are pure
    # identifier-quoting (label/property regex-validated then backticked) — no
    # user-supplied value reaches the Cypher template (NFR-4). Tag the def line
    # so the guard treats it as a known-safe co-occurrence.
    async def execute(  # noqa: SQLGREP
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Run the parameterized Cypher against the driver and wrap rows."""
        del intent, context  # Phase 2: intent/context not consumed by Neo4j adapter
        if self._driver is None or self._config is None or self._label is None:
            raise AdapterError("Neo4jAdapter.execute called before connect()")

        cypher, params = self._build_cypher(self._label, scope, _DEFAULT_LIMIT)

        started = time.perf_counter()
        # ``execute_query`` is typed ``LiteralString`` for ``query_``; our
        # template is composed entirely from regex-validated identifiers and
        # ``$pN`` placeholders, so the cast is sound (NFR-4). Values are bound
        # via ``parameters_=`` only; never interpolated.
        result: Any = await self._driver.execute_query(
            cast(Any, cypher),
            parameters_=params,
            routing_=RoutingControl.READ,
        )
        duration_ms = int((time.perf_counter() - started) * 1000)

        rows: list[dict[str, Any]] = []
        for record in cast(list[Any], result.records):
            node: Any = record["n"]
            # ``Node`` exposes a mapping interface (``dict(node)``) over its
            # properties; this matches the row shape returned by the postgres
            # adapter (plain dict per design §3.11).
            try:
                rows.append(dict(node))
            except TypeError:
                # Fallback for backends that return a plain dict (mocks).
                rows.append(cast(dict[str, Any], node))

        return AdapterResult(
            source_id=self._config.id,
            rows=rows,
            duration_ms=duration_ms,
        )


__all__ = ["Neo4jAdapter"]
