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
from typing import Any, ClassVar, cast

from elasticsearch import AsyncElasticsearch
from elasticsearch.dsl import AsyncSearch
from elasticsearch.dsl.query import Bool, Exists, Range, Term, Terms, Wildcard

from nautilus.adapters.base import (
    AdapterError,
    ScopeEnforcementError,
    validate_field,
)
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

    SQL ``%`` -> ES ``*``; SQL ``_`` -> ES ``?``. Existing literal ``*`` / ``?``
    in the input are preserved (callers rely on this via the ``like_style``
    knob in higher layers).
    """
    return pattern.replace("%", "*").replace("_", "?")


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
        elif isinstance(auth, MtlsAuth) and auth.ca_path is not None:
            client_kwargs["ca_certs"] = auth.ca_path

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
        )


__all__ = ["ElasticsearchAdapter"]
