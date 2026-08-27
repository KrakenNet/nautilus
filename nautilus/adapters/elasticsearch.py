"""Elasticsearch adapter using ``AsyncElasticsearch`` + ``elasticsearch.dsl``.

Implements design §3.11 (ElasticsearchAdapter) and §6 (Scope Enforcement). All
scope values flow through DSL query objects (``Term``, ``Terms``, ``Range``,
``Wildcard``, ``Exists``, ``Bool(must_not=...)``); no user-supplied value is
ever string-interpolated into a query body (NFR-4, AC-8.3). The operator
mapping comes from AC-8.2.

Index name validation (AC-8.1) is performed at ``connect()`` against the regex
``^[a-z0-9][a-z0-9._-]*$`` so a misconfigured ``SourceConfig.index`` is
rejected with :class:`ScopeEnforcementError` before any client is built.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, ClassVar, cast

from elasticsearch import AsyncElasticsearch
from elasticsearch.dsl import AsyncSearch
from elasticsearch.dsl.query import Bool, Exists, Range, Term, Terms, Wildcard

from nautilus.adapters.base import (
    AdapterError,
    ScopeEnforcementError,
    mtls_context,
    validate_field,
    wrap_execute,
)
from nautilus.adapters.schema import AdapterField, AdapterSchema, AdapterTable
from nautilus.config.models import BasicAuth, BearerAuth, MtlsAuth, SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# Default row cap applied when the intent does not specify a ``LIMIT``.
_DEFAULT_LIMIT: int = 1000

# Index-name regex per AC-8.1 / design §3.11. Lowercase only, must start with
# alnum, then alnum/dot/dash/underscore. Empty strings are rejected by the
# leading character class.
_INDEX_PATTERN: re.Pattern[str] = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

# Operator allowlist mirroring :data:`nautilus.adapters.base._OPERATOR_ALLOWLIST`
# but expressed locally so the closed-set check can produce an
# Elasticsearch-flavored error message (AC-8.2). Drift between the two is caught
# by the Phase-1 drift-guard (Task 3.14).
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


def _validate_index(index: str | None) -> str:
    """Validate ``index`` against AC-8.1 regex; return it unchanged on success.

    Raises :class:`ScopeEnforcementError` on missing / malformed index, so a
    misconfigured source is bucketed into ``sources_errored`` rather than
    propagated to the agent (design §6.3).
    """
    if not index:
        raise ScopeEnforcementError(
            "ElasticsearchAdapter requires non-empty 'index' on SourceConfig"
        )
    if not _INDEX_PATTERN.match(index):
        raise ScopeEnforcementError(
            f"Invalid Elasticsearch index '{index}': must match {_INDEX_PATTERN.pattern}"
        )
    return index


def _translate_like(pattern: str) -> str:
    """Translate a SQL-style ``LIKE`` pattern to an Elasticsearch wildcard glob.

    SQL ``%`` -> ES ``*``; SQL ``_`` -> ES ``?``. ``*``, ``?`` and ``\\`` are
    literal characters in a SQL LIKE pattern, so they are escaped first --
    otherwise ``owner LIKE '*'`` reaches ES as the match-everything glob and
    silently *widens* the constraint. (``like_style`` is a Neo4j-only knob and
    never reached this function.)
    """
    escaped = pattern.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
    return escaped.replace("%", "*").replace("_", "?")


# Builder signature: ``(field, value) -> DSL query``. The return type is ``Any``
# because elasticsearch.dsl exposes a wide query-class hierarchy and downstream
# only feeds the result into ``AsyncSearch.query(...)``.
_BuilderFn = Callable[[str, Any], Any]


def _b_eq(field: str, value: Any) -> Any:
    return Term(**{field: value})


def _b_ne(field: str, value: Any) -> Any:
    return Bool(must_not=[Term(**{field: value})])


def _b_in(field: str, value: Any) -> Any:
    kwargs: dict[str, Any] = {field: list(cast(list[Any], value))}
    return Terms(**kwargs)


def _b_not_in(field: str, value: Any) -> Any:
    kwargs: dict[str, Any] = {field: list(cast(list[Any], value))}
    return Bool(must_not=[Terms(**kwargs)])


def _b_lt(field: str, value: Any) -> Any:
    return Range(**{field: {"lt": value}})


def _b_gt(field: str, value: Any) -> Any:
    return Range(**{field: {"gt": value}})


def _b_lte(field: str, value: Any) -> Any:
    return Range(**{field: {"lte": value}})


def _b_gte(field: str, value: Any) -> Any:
    return Range(**{field: {"gte": value}})


def _b_between(field: str, value: Any) -> Any:
    seq: list[Any] = list(value)
    return Range(**{field: {"gte": seq[0], "lte": seq[1]}})


def _b_like(field: str, value: Any) -> Any:
    return Wildcard(**{field: _translate_like(cast(str, value))})


def _b_is_null(field: str, value: Any) -> Any:
    del value
    return Bool(must_not=[Exists(field=field)])


def _typecheck_value(op: str, value: Any) -> None:
    """Validate the Python type of ``value`` for operators that need it.

    Lifted to module scope so the dispatch site in
    :meth:`ElasticsearchAdapter._constraint_to_query` does not interleave
    error f-strings with the ``.query(...)`` callers (Phase-1 grep guard,
    ``test_sql_injection_static``).
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


# Operator -> DSL builder dispatch table. Lifted to module scope so the per-row
# build loop in :meth:`ElasticsearchAdapter._build_search` contains no error
# f-strings adjacent to ``.query(...)`` calls (Phase-1 grep guard,
# ``test_sql_injection_static``).
_DSL_BUILDERS: dict[str, _BuilderFn] = {
    "=": _b_eq,
    "!=": _b_ne,
    "IN": _b_in,
    "NOT IN": _b_not_in,
    "<": _b_lt,
    ">": _b_gt,
    "<=": _b_lte,
    ">=": _b_gte,
    "BETWEEN": _b_between,
    "LIKE": _b_like,
    "IS NULL": _b_is_null,
}


# Operators whose DSL builders do not analyse their input, so they must run
# against a verbatim-indexed field. Range operators belong here too: they are
# lexicographic over the *analysed terms*, so ``classification >= 'public'`` on
# a dynamically-mapped string ranks 'top secret' by its 'secret' token and
# answers wrongly with no error.
_EXACT_OPERATORS: frozenset[str] = frozenset(
    {"=", "!=", "IN", "NOT IN", "LIKE", "<", "<=", ">", ">=", "BETWEEN"}
)


def _strings(value: Any) -> list[str]:
    """Every string in a constraint value (scalars, ``IN`` lists, ``BETWEEN`` pairs)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [v for v in cast("list[Any]", value) if isinstance(v, str)]
    return []


class ElasticsearchAdapter:
    """Elasticsearch adapter backed by ``AsyncElasticsearch``.

    Construction is cheap; the actual client is built in :meth:`connect` so
    failures bubble up through the broker's ``sources_errored`` path
    (design §3.5 / FR-18).
    """

    source_type: ClassVar[str] = "elasticsearch"

    def __init__(self, client: Any = None) -> None:
        # ``client`` is optional to support injecting a mocked ``AsyncElasticsearch``
        # in unit tests (mirrors the Phase-1 PostgresAdapter constructor shape).
        self._client: Any = client
        self._config: SourceConfig | None = None
        self._index: str | None = None
        self._closed: bool = False
        # Index mapping properties, cached for the query path (see
        # ``_exact_field``). ``get_schema`` always refetches so schema-drift
        # detection cannot be answered from a stale cache.
        self._props: dict[str, Any] | None = None

    async def connect(self, config: SourceConfig) -> None:
        """Create the ``AsyncElasticsearch`` client and validate ``config.index``.

        Index validation runs first so a bad index never causes us to spin up a
        client. Auth is resolved from the discriminated union; ``mtls`` is
        passed through as ``ca_certs`` only (the cert/key pair lands on the
        underlying transport via the connection URL or env in Phase 2).
        """
        self._index = _validate_index(config.index)
        self._config = config

        if self._client is not None:
            return

        client_kwargs: dict[str, Any] = {"hosts": [config.connection]}
        auth = config.auth
        if isinstance(auth, BasicAuth):
            client_kwargs["basic_auth"] = (auth.username, auth.password)
        elif isinstance(auth, BearerAuth):
            # ES python client uses ``api_key`` for bearer-style tokens.
            client_kwargs["api_key"] = auth.token
        elif isinstance(auth, MtlsAuth):
            # The client certificate is the credential here; forwarding only
            # ``ca_path`` (and only when it was set) meant the connection
            # presented nothing and the operator was told nothing.
            client_kwargs["ssl_context"] = mtls_context(auth, config.id)

        try:
            self._client = AsyncElasticsearch(**client_kwargs)
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError(
                f"ElasticsearchAdapter failed to build client for source '{config.id}': {exc}"
            ) from exc

    async def close(self) -> None:
        """Release the client. Idempotent — second call is a no-op (FR-17)."""
        if self._closed:
            return
        self._closed = True
        client = self._client
        self._client = None
        if client is not None:
            await client.close()

    async def _fetch_properties(self) -> dict[str, Any]:
        """GET the index mapping's ``properties``. Raises on a backend outage."""
        try:
            mapping: Any = await self._client.indices.get_mapping(index=self._index)  # pyright: ignore[reportUnknownMemberType]
        except Exception as exc:
            raise AdapterError(
                f"ElasticsearchAdapter could not read the mapping for index '{self._index}': {exc}"
            ) from exc
        index_mapping: Any = mapping.get(self._index, {})
        props: dict[str, Any] = index_mapping.get("mappings", {}).get("properties", {})
        self._props = props
        return props

    def _exact_field(self, field: str, value: Any = None) -> str:
        """Return the field a term-level query must target for ``field``.

        ES default dynamic mapping indexes every string as ``text`` (analysed)
        plus a ``.keyword`` subfield (verbatim). ``Term``/``Terms``/``Wildcard``
        do not analyse their input, so run against the bare ``text`` field they
        compare an unanalysed value to analysed terms: ``=`` fails closed and
        ``!=`` / ``NOT IN`` fail **open**, returning the document the operator
        was supposed to exclude.

        A ``text`` field with no ``keyword`` subfield cannot be matched exactly
        at all, so the constraint raises rather than being silently dropped --
        ``developing-adapters.md``: "silently dropping a constraint returns
        over-scoped data".
        """
        props = self._props or {}
        if "." in field:
            # The caller targeted a subfield explicitly (``validate_field``
            # permits one dotted segment); respect it.
            return field
        definition = props.get(field)
        if not isinstance(definition, dict) or definition.get("type") != "text":
            # Unmapped, or already an exact type (keyword/long/date/boolean...).
            return field
        subfields = cast("dict[str, Any]", definition.get("fields") or {})
        keywords: dict[str, dict[str, Any]] = {
            name: cast("dict[str, Any]", sub)
            for name, sub in subfields.items()
            if isinstance(sub, dict) and cast("dict[str, Any]", sub).get("type") == "keyword"
        }
        if not keywords:
            raise ScopeEnforcementError(
                f"ElasticsearchAdapter: field '{field}' is mapped as analysed 'text' "
                f"with no 'keyword' subfield, so it cannot be matched exactly. An "
                f"exact-match constraint on it would silently return over-scoped "
                f"data. Add a keyword subfield to the mapping, or target one "
                f"explicitly as 'field.<subfield>'."
            )
        # A keyword subfield with ``ignore_above`` does not index values longer
        # than the limit *at all*, so a term query for one matches nothing and
        # ``!=`` / ``NOT IN`` match everything -- the same fail-open the
        # ``.keyword`` routing exists to close. Prefer an unlimited subfield;
        # refuse the constraint if the only one available would drop the value.
        unlimited: list[str] = sorted(
            n for n, sub in keywords.items() if sub.get("ignore_above") is None
        )
        if unlimited:
            return f"{field}.{unlimited[0]}"
        limits: dict[str, int] = {n: int(sub["ignore_above"]) for n, sub in keywords.items()}
        chosen = sorted(limits, key=lambda n: (-limits[n], n))[0]
        limit = limits[chosen]
        longest = max((len(v) for v in _strings(value)), default=0)
        if longest > limit:
            raise ScopeEnforcementError(
                f"ElasticsearchAdapter: the only exact subfield for '{field}' is "
                f"'{field}.{chosen}', which has ignore_above={limit}, and the "
                f"constraint compares a value of length {longest}. Values over the "
                f"limit are not indexed, so the comparison would silently return "
                f"over-scoped data. Raise ignore_above on the mapping, or target a "
                f"subfield without one as 'field.<subfield>'."
            )
        return f"{field}.{chosen}"

    def _constraint_to_query(self, constraint: ScopeConstraint) -> Any:
        """Translate one :class:`ScopeConstraint` into a DSL query object per AC-8.2.

        Pre-validates the operator (closed-set, AC-8.4) and the field identifier
        (design §6.2 regex) before any DSL construction. Returns a typed query
        object — never a string. Raises :class:`ScopeEnforcementError` on type
        mismatch or unknown operator so the broker can record a
        ``sources_errored`` entry rather than propagating to the agent.
        """
        op = constraint.operator
        if op not in _OPERATOR_ALLOWLIST:
            raise ScopeEnforcementError(f"operator not allowed: {op}")
        field = constraint.field
        validate_field(field)
        value: Any = constraint.value
        _typecheck_value(op, value)
        if op in _EXACT_OPERATORS:
            field = self._exact_field(field, value)
        return _DSL_BUILDERS[op](field, value)

    def _build_search(
        self,
        index: str,
        scope: list[ScopeConstraint],
        limit: int,
    ) -> AsyncSearch:
        """Compose an :class:`AsyncSearch` from ``scope`` per AC-8.2.

        Operator dispatch happens via :meth:`_constraint_to_query` so this
        method contains no error-message f-strings near the ``.query(...)``
        call sites (NFR-4 / Phase-1 ``test_sql_injection_static`` pattern).
        """
        search: AsyncSearch = AsyncSearch(using=self._client, index=index)
        # ``extra(size=...)`` is the DSL-level analogue of ``LIMIT $L``.
        search = search.extra(size=limit)
        for constraint in scope:
            q = self._constraint_to_query(constraint)
            search = search.query(q)
        return search

    @wrap_execute
    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Run the DSL search against the client and wrap hits as rows."""
        del intent, context  # Phase 2: intent/context not consumed by ES adapter
        if self._client is None or self._config is None or self._index is None:
            raise AdapterError("ElasticsearchAdapter.execute called before connect()")

        # ``_exact_field`` needs the mapping to know which fields are analysed.
        # Fetched only when a constraint actually needs it, and refetched when one
        # names a field the cache has never seen: an index gains fields over a
        # broker's lifetime, and a field missing from a stale cache reads as
        # "unmapped" and routes to the bare analysed field -- the fail-open this
        # whole path exists to close.
        needed = {c.field.split(".", 1)[0] for c in scope if c.operator in _EXACT_OPERATORS}
        if needed and (self._props is None or not needed <= set(self._props)):
            await self._fetch_properties()

        search = self._build_search(self._index, scope, _DEFAULT_LIMIT)

        started = time.perf_counter()
        response = await search.execute()
        duration_ms = int((time.perf_counter() - started) * 1000)

        rows: list[dict[str, Any]] = []
        for hit in response:  # pyright: ignore[reportUnknownVariableType]
            # ``hit.to_dict()`` returns the ``_source`` document; this matches
            # the row shape returned by the postgres adapter (plain dict).
            rows.append(hit.to_dict())  # pyright: ignore[reportUnknownArgumentType, reportUnknownMemberType]

        return AdapterResult(
            source_id=self._config.id,
            rows=rows,
            duration_ms=duration_ms,
            truncated=len(rows) >= _DEFAULT_LIMIT,
        )

    async def get_schema(self) -> AdapterSchema:
        """Return schema via GET _mapping API. AC-21, OQ3.

        Raises on a backend outage rather than returning
        :meth:`AdapterSchema.unknown`. Swallowing the error made an outage
        indistinguishable from major schema drift: the broker quarantined the
        source and wrote ``schema_drift_detected`` describing an event that did
        not occur, and ``schema-ack`` -- the prescribed remediation -- baselined
        the ``unknown()`` fingerprint, re-quarantining the source when the
        backend *recovered*. ``Broker._check_adapter_schema`` already handles a
        raising ``get_schema`` by skipping the fingerprint check.
        """
        if self._client is None or self._config is None or self._index is None:
            return AdapterSchema.unknown(
                self._config.id if self._config else "elasticsearch",
                self.source_type,
            )
        props = await self._fetch_properties()
        fields = tuple(
            AdapterField(
                name=fname,
                type=str(fdef.get("type", "object")),
                nullable=True,
            )
            for fname, fdef in sorted(props.items())
        )
        table = AdapterTable(name=self._index, fields=fields)
        return AdapterSchema(
            adapter_id=self._config.id,
            source_type=self.source_type,
            tables=(table,),
            capability_flags={"deterministic": False},
            fetched_at=datetime.now(UTC),
        )


__all__ = ["ElasticsearchAdapter"]
