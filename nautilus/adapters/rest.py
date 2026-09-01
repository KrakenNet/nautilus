"""REST adapter using ``httpx.AsyncClient`` with SSRF defense.

Implements design §3.11 (``RestAdapter``) and §6 (Scope Enforcement). Scope
values flow through ``httpx.URL`` query parameters only — no user-supplied
value is ever string-interpolated into a URL (NFR-4, AC-9.3). The operator
template mapping comes from AC-9.3: each ``EndpointSpec.operator_templates``
may override the defaults below; unknown operators are rejected. ``NOT IN``
is rejected unless explicitly declared on the endpoint (AC-9.3).

SSRF defense (NFR-17, AC-9.2):

- The ``httpx.AsyncClient`` is constructed with ``follow_redirects=False`` so
  the runtime never chases a redirect silently.
- At ``connect()`` time the base URL's host is resolved and rejected if any
  address it answers with is private, loopback, link-local or multicast. A
  name is resolved, not only an IP literal -- the literal-only version of this
  check was bypassed by ``http://backend``. Resolution is not repeated at dial
  time, so a record that changes between the two lookups is not caught; see
  :func:`nautilus.adapters.base.resolve_base_url`.
- After every response, if ``response.next_request`` is populated (i.e. the
  upstream returned a 3xx redirect) AND the redirect target host differs
  from the configured base-URL host, the adapter raises
  :class:`SSRFBlockedError`. Any 3xx is refused regardless of target: the
  adapter does not follow redirects.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any, ClassVar, cast

import httpx

from nautilus.adapters.base import (
    AdapterError,
    ScopeEnforcementError,
    resolve_base_url,
    session_token_headers,
    validate_field,
    wrap_execute,
)
from nautilus.adapters.schema import AdapterSchema
from nautilus.config.models import (
    BasicAuth,
    BearerAuth,
    EndpointSpec,
    MtlsAuth,
    SourceConfig,
)
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# Default row cap applied when the intent does not specify a ``LIMIT``.
_DEFAULT_LIMIT: int = 1000

# The row cap bounds the rows; it runs after the whole body has been parsed, so
# it bounds nothing an oversized upstream response can do to this process. This
# is the byte ceiling that runs first.
# ponytail: one constant for every REST source. Move it onto SourceConfig if a
# deployment legitimately needs a bigger body from one endpoint.
MAX_RESPONSE_BYTES: int = 8 * 1024 * 1024

# Operator allowlist mirroring :data:`nautilus.adapters.base._OPERATOR_ALLOWLIST`.
# ``NOT IN`` is intentionally NOT in the default template map below; it is
# only accepted when an :class:`EndpointSpec.operator_templates` declares it
# explicitly (AC-9.3).
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


class SSRFBlockedError(AdapterError):
    """Raised when the REST adapter refuses a cross-host redirect or a base URL
    that resolves to an unroutable address (NFR-17, AC-9.2).

    The broker converts this into a ``sources_errored`` entry with
    ``error_type=SSRFBlockedError`` (design §10 error table).
    """


# Builder signature: ``(field, value) -> list[(param_key, param_value)]``. The
# builders emit a list of key/value pairs (not a dict) so operators like ``IN``
# can repeat the same query-parameter key. All values are passed through
# ``httpx.URL``'s param encoder downstream — never string-concatenated into a
# URL (NFR-4).
_BuilderFn = Callable[[str, Any], list[tuple[str, str]]]


def _b_eq(field: str, value: Any) -> list[tuple[str, str]]:
    return [(field, str(value))]


def _b_ne(field: str, value: Any) -> list[tuple[str, str]]:
    return [(f"{field}__ne", str(value))]


def _b_in(field: str, value: Any) -> list[tuple[str, str]]:
    seq = cast(list[Any], value)
    return [(field, str(v)) for v in seq]


def _b_not_in_default(field: str, value: Any) -> list[tuple[str, str]]:
    """Default builder for ``NOT IN`` — fail-closed (AC-9.3).

    ``NOT IN`` has no portable REST-query semantics, so the default
    builder raises :class:`ScopeEnforcementError`. Endpoints that need
    ``NOT IN`` opt in by declaring an
    :attr:`EndpointSpec.operator_templates` entry; the resolver swaps in
    :func:`_b_not_in_rendered` for that endpoint. Kept in
    ``_DEFAULT_BUILDERS`` so the operator-allowlist check has a uniform
    error shape for the un-declared case.
    """
    del field, value
    raise ScopeEnforcementError(
        "Operator 'NOT IN' is not supported by the REST adapter unless "
        "explicitly declared in EndpointSpec.operator_templates (AC-9.3)."
    )


def _b_lt(field: str, value: Any) -> list[tuple[str, str]]:
    return [(f"{field}__lt", str(value))]


def _b_gt(field: str, value: Any) -> list[tuple[str, str]]:
    return [(f"{field}__gt", str(value))]


def _b_lte(field: str, value: Any) -> list[tuple[str, str]]:
    return [(f"{field}__lte", str(value))]


def _b_gte(field: str, value: Any) -> list[tuple[str, str]]:
    return [(f"{field}__gte", str(value))]


def _b_between(field: str, value: Any) -> list[tuple[str, str]]:
    seq: list[Any] = list(cast(list[Any] | tuple[Any, ...], value))
    return [(f"{field}__gte", str(seq[0])), (f"{field}__lte", str(seq[1]))]


def _b_like(field: str, value: Any) -> list[tuple[str, str]]:
    return [(f"{field}__contains", str(value))]


def _b_is_null(field: str, value: Any) -> list[tuple[str, str]]:
    del value
    return [(f"{field}__isnull", "true")]


# Default operator -> builder table. ``NOT IN`` maps to a fail-closed
# default that raises :class:`ScopeEnforcementError`; endpoints that need
# it opt in via :attr:`EndpointSpec.operator_templates`, which the
# resolver substitutes with :func:`_b_not_in_rendered`.
_DEFAULT_BUILDERS: dict[str, _BuilderFn] = {
    "=": _b_eq,
    "!=": _b_ne,
    "IN": _b_in,
    "NOT IN": _b_not_in_default,
    "<": _b_lt,
    ">": _b_gt,
    "<=": _b_lte,
    ">=": _b_gte,
    "BETWEEN": _b_between,
    "LIKE": _b_like,
    "IS NULL": _b_is_null,
}


def _typecheck_value(op: str, value: Any) -> None:
    """Validate ``value`` type for operators that require structure.

    Mirrors the Phase-2 ES/Neo4j adapters so the SQL-injection grep guard
    (Task 3.13) keeps finding a uniform shape across adapters (NFR-4).
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


async def _reject_unroutable_base_url(base_url: str) -> None:
    """Reject a ``base_url`` whose host **resolves to** a private/loopback/
    link-local/multicast address.

    Shared with :class:`~nautilus.adapters.servicenow.ServiceNowAdapter`; it is
    the one place both REST-shaped adapters route through, so the check is
    written once.

    This used to test an IP *literal* only, which made the control trivially
    avoidable by the most ordinary configuration there is: ``http://backend``
    inside a container resolves to an RFC1918 address and was dialled without
    complaint, so every internal service with a DNS name -- including a cloud
    metadata service fronted by a name -- was reachable through a control the
    reference said covered it. The host is now resolved (see
    :func:`~nautilus.adapters.base.resolve_base_url`) and **every** address it
    answers with must be routable.

    Residual, stated rather than implied: resolution here is not the
    resolution httpx does when it dials, so a record that changes between the
    two lookups (DNS rebinding, a short TTL, a changing round-robin set) is
    not caught, and a name that does not resolve at all is accepted -- it
    reaches nothing, and the dial fails with the driver's own DNS error.
    """
    host, addresses = await resolve_base_url(base_url, "RestAdapter")
    for ip in addresses:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            raise SSRFBlockedError(
                f"RestAdapter refuses base_url host '{host}': it resolves to "
                f"private/loopback/link-local address {ip}"
            )


def _auth_for_config(config: SourceConfig) -> httpx.Auth | None:
    """Translate ``SourceConfig.auth`` into an ``httpx.Auth``.

    Bearer auth is surfaced via a tiny ``httpx.Auth`` subclass that injects
    the ``Authorization`` header; httpx has no first-class bearer helper but
    exposes the simple async auth-flow protocol used below. Basic auth maps
    directly to ``httpx.BasicAuth``. ``mtls`` is configured on the client
    transport (``verify``/cert kwargs on ``AsyncClient``) and does not return
    a per-request ``Auth``; ``none`` / missing returns ``None``.
    """
    auth = config.auth
    if isinstance(auth, BasicAuth):
        return httpx.BasicAuth(username=auth.username, password=auth.password)
    if isinstance(auth, BearerAuth):
        return _BearerAuth(token=auth.token)
    return None


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


class RestAdapter:
    """REST adapter backed by ``httpx.AsyncClient`` with SSRF defense.

    Construction is cheap; the actual client is built in :meth:`connect` so
    failures bubble up through the broker's ``sources_errored`` path
    (design §3.5 / FR-18).
    """

    source_type: ClassVar[str] = "rest"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        # ``client`` is optional so unit tests can inject a mocked
        # ``httpx.AsyncClient`` (mirrors the Phase-2 ES/Neo4j adapter shape).
        self._client: httpx.AsyncClient | None = client
        self._config: SourceConfig | None = None
        self._endpoint: EndpointSpec | None = None
        self._base_host: str | None = None
        self._closed: bool = False

    async def connect(self, config: SourceConfig) -> None:
        """Build the ``AsyncClient`` and validate endpoints + base URL.

        Validation order: base-URL sanity first (so a private-IP literal never
        causes us to spin up a client), then endpoint allowlist, then client
        construction. Auth is resolved from the discriminated union; ``mtls``
        is passed through as ``cert`` / ``verify`` kwargs; ``bearer`` / ``basic``
        attach via :func:`_auth_for_config`.
        """
        await _reject_unroutable_base_url(config.connection)
        self._config = config
        self._base_host = httpx.URL(config.connection).host

        # Endpoint allowlist: pick the first declared endpoint as the
        # adapter's call target. Phase-2 REST sources expose a single
        # endpoint per source (design §3.11); multi-endpoint selection is
        # out of scope. ``endpoints is None`` is Phase-1-backward-compat:
        # fall back to base-URL + empty path (NFR-5, AC-1.4).
        if config.endpoints is not None:
            if not config.endpoints:
                raise ScopeEnforcementError(
                    f"RestAdapter source '{config.id}' declares endpoints=[] "
                    "(must list at least one EndpointSpec or omit the field)"
                )
            self._endpoint = config.endpoints[0]
            # Validate declared operator_templates keys against the allowlist
            # so a typo in YAML surfaces at connect() rather than execute().
            for op in self._endpoint.operator_templates:
                if op not in _OPERATOR_ALLOWLIST:
                    raise ScopeEnforcementError(
                        f"EndpointSpec.operator_templates declares unknown "
                        f"operator '{op}' for source '{config.id}'"
                    )

        if self._client is not None:
            return

        client_kwargs: dict[str, Any] = {
            "base_url": config.connection,
            "follow_redirects": False,
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
                f"RestAdapter failed to build client for source '{config.id}': {exc}"
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

    def _resolve_template(self, op: str) -> _BuilderFn:
        """Resolve a builder for ``op``, honoring endpoint-declared overrides.

        Endpoint-declared templates are currently treated as an allowlist
        marker: their presence is sufficient to accept ``NOT IN`` (for which
        we have no safe default rendering), and the string body is exposed as
        a ``{field}__ne_in`` style key derived from the declaration. For
        operators that already have a safe default builder, the default is
        used; endpoint-declared strings are reserved for future per-operator
        overrides and are ignored at encode time. This keeps the encoding
        path free of string interpolation from YAML (NFR-4).
        """
        if op not in _OPERATOR_ALLOWLIST:
            raise ScopeEnforcementError(f"operator not allowed: {op}")
        declared: dict[str, str] = (
            self._endpoint.operator_templates if self._endpoint is not None else {}
        )
        if op == "NOT IN":
            if op not in declared:
                raise ScopeEnforcementError(
                    "Operator 'NOT IN' is not supported by the REST adapter "
                    "unless explicitly declared in EndpointSpec.operator_templates "
                    "(AC-9.3)."
                )
            # Emit a stable ``{field}__nin`` repeated-key form; the declared
            # template body is not consumed (see method docstring).
            return _b_not_in_rendered
        return _DEFAULT_BUILDERS[op]

    def _build_params(self, scope: list[ScopeConstraint]) -> list[tuple[str, str]]:
        """Compose a flat ``[(key, value), ...]`` param list from ``scope``.

        Operator dispatch goes through :meth:`_resolve_template` so this
        method contains no error-message f-strings near the request-building
        call site (NFR-4 / Phase-1 ``test_sql_injection_static`` pattern).
        """
        params: list[tuple[str, str]] = []
        for constraint in scope:
            op = constraint.operator
            field = constraint.field
            validate_field(field)
            value: Any = constraint.value
            _typecheck_value(op, value)
            builder = self._resolve_template(op)
            params.extend(builder(field, value))
        return params

    @wrap_execute
    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Issue the HTTP request and wrap the JSON body as rows.

        After the response arrives, the adapter inspects
        ``response.next_request`` (populated by httpx on 3xx responses when
        ``follow_redirects=False``). If the redirect target host differs from
        the configured base-URL host, :class:`SSRFBlockedError` is raised.
        Any 3xx status code is refused regardless of target — the adapter
        never follows redirects (NFR-17).
        """
        del intent  # Phase 2: intent not consumed by REST adapter
        if self._client is None or self._config is None or self._base_host is None:
            raise AdapterError("RestAdapter.execute called before connect()")

        path = self._endpoint.path if self._endpoint is not None else ""
        method = self._endpoint.method if self._endpoint is not None else "GET"
        params = self._build_params(scope)
        # AC-18.b — forward the broker-issued session-provenance token so
        # downstream services can correlate the call to its session.
        headers = session_token_headers(context)

        started = time.perf_counter()
        # Wrap via ``httpx.QueryParams`` so httpx handles URL-encoding; pass a
        # ``tuple[tuple[str, str], ...]`` because httpx types the ``params=``
        # kwarg with invariant ``Tuple[Tuple[str, PrimitiveData], ...]``
        # (widening to ``PrimitiveData`` needs the tuple form to satisfy the
        # pyright strict invariance check).
        params_tuple: tuple[tuple[str, str], ...] = tuple(params)
        query = httpx.QueryParams(params_tuple)
        async with self._client.stream(method, path, params=query, headers=headers) as response:
            duration_ms = int((time.perf_counter() - started) * 1000)

            _enforce_no_cross_host_redirect(response, self._base_host)

            if response.status_code >= 400:  # noqa: PLR2004 — httpx's own threshold
                # The error path wants the body for its message, and a streamed
                # response has not read one yet.
                await response.aread()
            response.raise_for_status()
            raw = await self._read_bounded(response)
        body: Any = json.loads(raw)
        rows: list[dict[str, Any]] = _coerce_rows(body, limit=_DEFAULT_LIMIT)

        return AdapterResult(
            source_id=self._config.id,
            rows=rows,
            duration_ms=duration_ms,
            truncated=len(rows) >= _DEFAULT_LIMIT,
        )

    async def _read_bounded(self, response: httpx.Response) -> bytes:
        """Read the response body, refusing to allocate past the ceiling.

        Declared ``Content-Length`` is checked first so an oversized answer
        costs nothing; a chunked response without one is bounded as it arrives.
        """
        source_id = self._config.id if self._config is not None else "rest"
        declared = response.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
            raise AdapterError(
                f"source '{source_id}' answered with {declared} bytes, over the "
                f"{MAX_RESPONSE_BYTES}-byte ceiling"
            )
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise AdapterError(
                    f"source '{source_id}' streamed more than the {MAX_RESPONSE_BYTES}-byte ceiling"
                )
            chunks.append(chunk)
        return b"".join(chunks)

    async def get_schema(self) -> AdapterSchema:
        """Return operator-declared schema from adapter config. AC-21, OQ3."""
        if self._config is None:
            return AdapterSchema.unknown("rest", self.source_type)
        # REST adapters declare their schema statically via operator config.
        # No introspection is possible without a live endpoint call.
        return AdapterSchema.unknown(self._config.id, self.source_type)


def _b_not_in_rendered(field: str, value: Any) -> list[tuple[str, str]]:
    """Render an explicitly-declared ``NOT IN`` as a repeated ``__nin`` key.

    Only reachable when ``EndpointSpec.operator_templates`` declares
    ``"NOT IN"``; see :meth:`RestAdapter._resolve_template`.
    """
    seq = cast(list[Any], value)
    return [(f"{field}__nin", str(v)) for v in seq]


def _enforce_no_cross_host_redirect(response: httpx.Response, base_host: str) -> None:
    """Raise :class:`SSRFBlockedError` when the response would redirect away.

    httpx populates ``response.next_request`` only for 3xx responses when
    ``follow_redirects=False`` (our configuration). If the next-request host
    differs from the base-URL host, the adapter refuses to follow and
    surfaces the violation. Same-host redirects are also refused to keep the
    adapter behavior predictable — the operator can widen the allowed paths
    on ``SourceConfig.endpoints`` instead of relying on server-side 3xx.
    """
    next_req = response.next_request
    if next_req is None:
        return
    target_host = next_req.url.host
    if target_host != base_host:
        raise SSRFBlockedError(
            f"Refused redirect from host '{base_host}' to different host "
            f"'{target_host}' (status={response.status_code})"
        )
    # Same-host redirect — still refuse, but with a distinct message so
    # operators can diagnose 3xx loops without confusing them with SSRF.
    raise SSRFBlockedError(
        f"Refused same-host redirect (status={response.status_code}); "
        "configure the endpoint path directly to avoid 3xx responses."
    )


def _coerce_rows(body: Any, limit: int) -> list[dict[str, Any]]:
    """Coerce a REST JSON body into a list of dict rows.

    Accepts the two common shapes: a bare JSON array of objects, or an
    envelope with a ``results``/``data``/``items`` key holding the array.
    Anything else surfaces as a single-row wrapper so the broker still gets
    a typed response rather than a shape assertion.
    """
    if isinstance(body, list):
        arr_list = cast(list[Any], body)
        return [cast(dict[str, Any], item) for item in arr_list[:limit] if isinstance(item, dict)]
    if isinstance(body, dict):
        body_dict = cast(dict[str, Any], body)
        for key in ("results", "data", "items"):
            v = body_dict.get(key)
            if isinstance(v, list):
                arr_v = cast(list[Any], v)
                return [
                    cast(dict[str, Any], item) for item in arr_v[:limit] if isinstance(item, dict)
                ]
        return [body_dict]
    return []


__all__ = ["RestAdapter", "SSRFBlockedError"]
