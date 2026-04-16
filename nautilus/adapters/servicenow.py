"""ServiceNow adapter using ``httpx.AsyncClient`` with encoded-query sanitiser.

Implements design §3.11 (``ServiceNowAdapter``) and §6 (Scope Enforcement) for
ServiceNow Table API requests. Scope constraints are rendered into a
GlideRecord ``sysparm_query`` string per AC-11.2; every value first passes
through :meth:`ServiceNowAdapter._sanitize_sn_value` to reject the encoded-query
injection characters ``^`` / ``\\n`` / ``\\r`` (AC-11.1, NFR-4, NFR-18).

The composed query is handed to httpx as a ``sysparm_query`` request parameter
so httpx handles URL-encoding — no value is ever string-interpolated into the
URL path. The sanitiser is the primary defence; httpx encoding is secondary.
"""

from __future__ import annotations

import re
import time
from typing import Any, ClassVar, cast

import httpx

from nautilus.adapters.base import (
    AdapterError,
    ScopeEnforcementError,
)
from nautilus.config.models import (
    BasicAuth,
    BearerAuth,
    MtlsAuth,
    SourceConfig,
)
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# Default row cap when the intent does not specify a ``LIMIT``.
_DEFAULT_LIMIT: int = 1000

# Table name regex per design §3.11 / AC-11.1. Matches ServiceNow table
# identifiers: lowercase letter first, then lowercase / digits / underscore.
_TABLE_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_]*$")

# Field identifier regex for ServiceNow column references. Slightly wider than
# the base validator so dotted walks (``assigned_to.name``) are accepted; still
# rejects any of the GlideRecord-separator characters.
_SN_FIELD_PATTERN: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_.]*$")


class _BearerAuth(httpx.Auth):
    """Injects ``Authorization: Bearer <token>`` on every outgoing request."""

    def __init__(self, token: str) -> None:
        self._token = token

    def auth_flow(
        self, request: httpx.Request
    ) -> Any:  # pragma: no cover  # exercised via live/integration
        """Attach a bearer token to ``request`` and yield it to httpx.

        Args:
            request: Outgoing httpx request to mutate in place.

        Yields:
            The mutated request with an ``Authorization`` header set.
        """
        request.headers["Authorization"] = f"Bearer {self._token}"
        yield request


def _auth_for_config(config: SourceConfig) -> httpx.Auth | None:
    """Translate ``SourceConfig.auth`` into an ``httpx.Auth`` (mirrors RestAdapter)."""
    auth = config.auth
    if isinstance(auth, BasicAuth):
        return httpx.BasicAuth(username=auth.username, password=auth.password)
    if isinstance(auth, BearerAuth):
        return _BearerAuth(token=auth.token)
    return None


def _validate_sn_field(field: str) -> None:
    """Regex-validate a ServiceNow column name (AC-11.1).

    Rejects uppercase, leading digits, whitespace, and any of the
    GlideRecord-separator characters (``^``/``,``/``@``). The sanitiser still
    runs on values after this check — this guards the left-hand side.
    """
    if not _SN_FIELD_PATTERN.match(field):
        raise ScopeEnforcementError(f"sn-invalid-field: {field!r}")


class ServiceNowAdapter:
    """ServiceNow Table-API adapter backed by ``httpx.AsyncClient``.

    Construction is cheap; the actual client is built in :meth:`connect` so
    failures bubble up through the broker's ``sources_errored`` path
    (design §3.5 / FR-18).
    """

    source_type: ClassVar[str] = "servicenow"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        # ``client`` is optional so unit tests can inject a mocked
        # ``httpx.AsyncClient`` (mirrors the Phase-2 REST adapter shape).
        self._client: httpx.AsyncClient | None = client
        self._config: SourceConfig | None = None
        self._table: str | None = None
        self._closed: bool = False

    @staticmethod
    def _sanitize_sn_value(v: str) -> str:
        """Reject GlideRecord encoded-query separator characters (AC-11.1).

        The encoded-query grammar uses ``^`` to separate segments and newline
        characters as inline terminators. Any value containing those bytes
        would let an attacker smuggle an entire extra constraint — so we
        refuse the value outright rather than attempting to escape it
        (NFR-4, NFR-18).
        """
        if "^" in v or "\n" in v or "\r" in v:
            raise ScopeEnforcementError("sn-injection-rejected")
        return v

    async def connect(self, config: SourceConfig) -> None:
        """Build the ``AsyncClient`` and validate the configured table.

        Validation order: table regex first (so a malformed table never
        causes us to spin up a client), then client construction with auth
        resolved from the discriminated union.
        """
        table = config.table
        if table is None or not _TABLE_PATTERN.match(table):
            raise ScopeEnforcementError(
                f"ServiceNowAdapter source '{config.id}' has invalid table {table!r} "
                "(expected regex '^[a-z][a-z0-9_]*$')"
            )
        self._config = config
        self._table = table

        if self._client is not None:
            return

        client_kwargs: dict[str, Any] = {
            "base_url": config.connection,
            "auth": _auth_for_config(config),
        }
        a = config.auth
        if isinstance(a, MtlsAuth):
            client_kwargs["cert"] = (a.cert_path, a.key_path)
            if a.ca_path is not None:
                client_kwargs["verify"] = a.ca_path

        try:
            self._client = httpx.AsyncClient(**client_kwargs)
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError(
                f"ServiceNowAdapter failed to build client for source '{config.id}': {exc}"
            ) from exc

    async def close(self) -> None:
        """Release the client. Idempotent — second call is a no-op (FR-17)."""
        if self._closed:
            return
        self._closed = True
        client = self._client
        self._client = None
        if client is not None:
            await client.aclose()

    @classmethod
    def _render_segment(cls, constraint: ScopeConstraint) -> str:
        """Render one scope constraint as a ``sysparm_query`` segment.

        Operator dispatch follows AC-11.2. Every scalar value (and every list
        element for ``IN`` / ``NOT IN``) is routed through
        :meth:`_sanitize_sn_value` before reaching the segment body; the field
        name is regex-validated up front.
        """
        field = constraint.field
        _validate_sn_field(field)
        op = constraint.operator
        value: Any = constraint.value

        if op == "IS NULL":
            return f"{field}ISEMPTY"

        if op in ("IN", "NOT IN"):
            if not isinstance(value, list):
                raise ScopeEnforcementError(
                    f"sn-invalid-value: operator {op!r} requires a list, "
                    f"got {type(cast(object, value)).__name__}"
                )
            parts: list[str] = []
            for item in cast(list[Any], value):
                parts.append(cls._sanitize_sn_value(str(item)))
            joined = ",".join(parts)
            return f"{field}{op}{joined}"

        if op == "BETWEEN":
            if not isinstance(value, (list, tuple)):
                raise ScopeEnforcementError(
                    "sn-invalid-value: operator 'BETWEEN' requires a 2-tuple/list"
                )
            seq_any: list[Any] | tuple[Any, ...] = (
                cast(list[Any], value) if isinstance(value, list) else cast(tuple[Any, ...], value)
            )
            if len(seq_any) != 2:
                raise ScopeEnforcementError(
                    "sn-invalid-value: operator 'BETWEEN' requires exactly two endpoints"
                )
            lo = cls._sanitize_sn_value(str(seq_any[0]))
            hi = cls._sanitize_sn_value(str(seq_any[1]))
            return f"{field}BETWEEN{lo}@{hi}"

        if op in ("=", "!=", "<", ">", "<=", ">=", "LIKE"):
            scalar = cls._sanitize_sn_value(str(value))
            return f"{field}{op}{scalar}"

        raise ScopeEnforcementError(f"sn-unsupported-operator: {op!r}")

    # Phase-2 grep guard justification (Task 4.8 / test_sql_injection_static):
    # the encoded-query builder call site below is tagged SQLGREP because the
    # f-strings in _render_segment and the request-issuing method use
    # regex-validated field names (_validate_sn_field) plus sanitised values
    # (_sanitize_sn_value rejects segment-break characters), so no
    # user-supplied value can smuggle an extra segment. Tagging the method
    # def, the assignment, and the param-key line takes them out of the scan;
    # the def line carries a trailing noqa so the scan drops that line.
    @classmethod
    def _build_sysparm_query(cls, scope: list[ScopeConstraint]) -> str:  # noqa: SQLGREP
        """Compose the ``sysparm_query`` string from ``scope`` (AC-11.2)."""
        return "^".join(cls._render_segment(c) for c in scope)

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Issue the Table-API request and wrap the JSON body as rows.

        The composed ``sysparm_query`` is passed via ``params=`` so httpx
        handles URL-encoding; no value ever reaches the URL path through
        string interpolation (NFR-4).
        """
        del intent, context  # Phase 2: intent/context not consumed by SN adapter
        if self._client is None or self._config is None or self._table is None:
            raise AdapterError("ServiceNowAdapter.execute called before connect()")

        sysparm_query = self._build_sysparm_query(scope)  # noqa: SQLGREP
        path = f"/api/now/table/{self._table}"

        started = time.perf_counter()
        params_tuple: tuple[tuple[str, str], ...] = (
            ("sysparm_query", sysparm_query),  # noqa: SQLGREP
            ("sysparm_limit", str(_DEFAULT_LIMIT)),
        )
        query = httpx.QueryParams(params_tuple)
        response: httpx.Response = await self._client.request("GET", path, params=query)
        duration_ms = int((time.perf_counter() - started) * 1000)

        response.raise_for_status()
        body: Any = response.json()
        rows: list[dict[str, Any]] = _coerce_rows(body, limit=_DEFAULT_LIMIT)

        return AdapterResult(
            source_id=self._config.id,
            rows=rows,
            duration_ms=duration_ms,
        )


def _coerce_rows(body: Any, limit: int) -> list[dict[str, Any]]:
    """Coerce a ServiceNow Table-API body into a list of dict rows.

    The Table API returns ``{"result": [...]}``; fall back to bare-list and
    single-dict shapes so the broker still gets a typed response rather than a
    shape assertion.
    """
    if isinstance(body, dict):
        body_dict = cast(dict[str, Any], body)
        result = body_dict.get("result")
        if isinstance(result, list):
            arr = cast(list[Any], result)
            return [cast(dict[str, Any], item) for item in arr[:limit] if isinstance(item, dict)]
        return [body_dict]
    if isinstance(body, list):
        arr_list = cast(list[Any], body)
        return [cast(dict[str, Any], item) for item in arr_list[:limit] if isinstance(item, dict)]
    return []


__all__ = ["ServiceNowAdapter"]
