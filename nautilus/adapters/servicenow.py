"""ServiceNow adapter using ``httpx.AsyncClient`` with encoded-query sanitiser.

Implements design §3.11 (``ServiceNowAdapter``) and §6 (Scope Enforcement) for
ServiceNow Table API requests. Scope constraints are rendered into a
GlideRecord ``sysparm_query`` string per AC-11.2; every value first passes
through :meth:`ServiceNowAdapter._sanitize_sn_value` to reject the encoded-query
injection characters ``^`` / ``\\n`` / ``\\r`` (AC-11.1, NFR-4, NFR-18).

The composed query is handed to httpx as a ``sysparm_query`` request parameter
so httpx handles URL-encoding — no value is ever string-interpolated into the
URL path. The sanitiser is the primary defence; httpx encoding is secondary.

A ``sys_attachment`` source whose scope pins ``sys_id`` additionally fetches
the attachment binary via the Attachment API and returns it on the row as
``content_b64`` (see :meth:`ServiceNowAdapter._attach_content` for the guard
rails: pin requirement, size caps, fan-out cap, sys_id validation).
"""

from __future__ import annotations

import base64
import re
import time
from datetime import UTC, datetime
from typing import Any, ClassVar, cast

import httpx

from nautilus.adapters.base import (
    AdapterError,
    ScopeEnforcementError,
    session_token_headers,
)
from nautilus.adapters.rest import (
    _reject_private_ip_literal,  # pyright: ignore[reportPrivateUsage]
)
from nautilus.adapters.schema import AdapterField, AdapterSchema, AdapterTable
from nautilus.config.models import (
    BasicAuth,
    BearerAuth,
    MtlsAuth,
    SourceConfig,
)
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# Default row cap when the intent does not specify a ``LIMIT``.
_DEFAULT_LIMIT: int = 1000

# Attachment-content fetch: when a source is configured on ``sys_attachment``
# and the scope pins ``sys_id``, the binary is downloaded via the Attachment
# API and added to the row as ``content_b64``. Caps keep a pinned query from
# becoming a bulk-download channel.
_ATTACHMENT_TABLE: str = "sys_attachment"
_MAX_ATTACHMENT_BYTES: int = 10 * 1024 * 1024
_MAX_ATTACHMENT_FETCHES: int = 10

# ServiceNow sys_id shape — validated before a response-row value is ever
# interpolated into the Attachment-API request path.
_SYS_ID_PATTERN: re.Pattern[str] = re.compile(r"^[0-9a-f]{32}$")

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

        # #18 security review — the session-provenance token now rides on
        # every request (AC-18.b), so refuse private/loopback/metadata IP
        # literals just like the REST adapter, and pin redirect behaviour
        # explicitly (httpx defaults to no-follow; make it load-bearing).
        _reject_private_ip_literal(config.connection)

        client_kwargs: dict[str, Any] = {
            "base_url": config.connection,
            "auth": _auth_for_config(config),
            "follow_redirects": False,
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
    def _build_sysparm_query(cls, scope: list[ScopeConstraint]) -> str:  # sqlgrep: ignore
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
        del intent  # Phase 2: intent not consumed by SN adapter
        if self._client is None or self._config is None or self._table is None:
            raise AdapterError("ServiceNowAdapter.execute called before connect()")

        sysparm_query = self._build_sysparm_query(scope)  # sqlgrep: ignore
        path = f"/api/now/table/{self._table}"
        # AC-18.b — forward the broker-issued session-provenance token.
        headers = session_token_headers(context)

        started = time.perf_counter()
        params_tuple: tuple[tuple[str, str], ...] = (
            ("sysparm_query", sysparm_query),  # sqlgrep: ignore
            ("sysparm_limit", str(_DEFAULT_LIMIT)),
        )
        query = httpx.QueryParams(params_tuple)
        response: httpx.Response = await self._client.request(
            "GET", path, params=query, headers=headers
        )
        duration_ms = int((time.perf_counter() - started) * 1000)

        response.raise_for_status()
        body: Any = response.json()
        rows: list[dict[str, Any]] = _coerce_rows(body, limit=_DEFAULT_LIMIT)

        if self._table == _ATTACHMENT_TABLE and _scope_pins_sys_id(scope):
            await self._attach_content(self._client, rows, headers)

        return AdapterResult(
            source_id=self._config.id,
            rows=rows,
            duration_ms=duration_ms,
        )

    async def _attach_content(
        self,
        client: httpx.AsyncClient,
        rows: list[dict[str, Any]],
        headers: dict[str, str] | None,
    ) -> None:
        """Download pinned attachment binaries; add ``content_b64`` per row.

        Only reached for ``sys_attachment`` queries whose scope pins
        ``sys_id`` — a broad metadata query must never fan out into bulk
        downloads. Each row's ``sys_id`` is regex-validated before it is
        interpolated into the request path; size is checked twice (metadata
        ``size_bytes`` pre-check, then the downloaded body). Per-row guard
        failures are recorded as ``content_error`` so metadata survives;
        only the fan-out cap is a hard error.
        """
        if len(rows) > _MAX_ATTACHMENT_FETCHES:
            raise AdapterError(
                f"sn-attachment-fetch-cap: {len(rows)} rows pinned, "
                f"cap is {_MAX_ATTACHMENT_FETCHES}"
            )
        for row in rows:
            sys_id = str(row.get("sys_id", ""))
            if not _SYS_ID_PATTERN.match(sys_id):
                row["content_error"] = "sn-invalid-sys-id"
                continue
            try:
                declared = int(str(row.get("size_bytes", "") or "0"))
            except ValueError:
                declared = 0
            if declared > _MAX_ATTACHMENT_BYTES:
                row["content_error"] = "attachment-too-large"
                continue
            response = await client.get(f"/api/now/attachment/{sys_id}/file", headers=headers)
            response.raise_for_status()
            content = response.content
            if len(content) > _MAX_ATTACHMENT_BYTES:
                row["content_error"] = "attachment-too-large"
                continue
            row["content_b64"] = base64.b64encode(content).decode("ascii")

    async def get_schema(self) -> AdapterSchema:
        """Return schema via sys_dictionary table query. AC-21, OQ3."""
        if self._client is None or self._config is None or self._table is None:
            return AdapterSchema.unknown(
                self._config.id if self._config else "servicenow",
                self.source_type,
            )
        try:
            path = "/api/now/table/sys_dictionary"
            params_tuple: tuple[tuple[str, str], ...] = (
                # _table is regex-validated at connect() (^[a-z][a-z0-9_]*$),
                # so interpolation cannot carry sysparm_query metacharacters.
                ("sysparm_query", f"name={self._table}"),  # sqlgrep: ignore
                ("sysparm_fields", "element,internal_type,mandatory"),
                ("sysparm_limit", "1000"),
            )
            query = httpx.QueryParams(params_tuple)
            response: httpx.Response = await self._client.request("GET", path, params=query)
            response.raise_for_status()
            body: Any = response.json()
            rows: list[dict[str, Any]] = _coerce_rows(body, limit=1000)

            fields = tuple(
                AdapterField(
                    name=str(row.get("element", "")),
                    type=str(row.get("internal_type", "string")),
                    nullable=(str(row.get("mandatory", "false")).lower() != "true"),
                )
                for row in rows
                if row.get("element")
            )
            table = AdapterTable(name=self._table, fields=fields)
            return AdapterSchema(
                adapter_id=self._config.id,
                source_type=self.source_type,
                tables=(table,),
                capability_flags={"deterministic": True},
                fetched_at=datetime.now(UTC),
            )
        except Exception:  # noqa: BLE001
            return AdapterSchema.unknown(self._config.id, self.source_type)


def _scope_pins_sys_id(scope: list[ScopeConstraint]) -> bool:
    """True when some constraint pins ``sys_id`` via ``=`` or ``IN``."""
    return any(c.field == "sys_id" and c.operator in ("=", "IN") for c in scope)


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
