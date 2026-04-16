"""Task 3.9 unit coverage for :mod:`nautilus.adapters.rest`.

Complements :mod:`tests.unit.adapters.test_rest_smoke` (Task 2.14) with the
five Task 3.9 cases called out by the spec:

(a) **Operator → template drift** — every operator in ``_OPERATOR_ALLOWLIST``
    either has a default builder in ``_DEFAULT_BUILDERS`` or is explicitly
    rejected (``NOT IN``) unless endpoint-declared (NFR-4, AC-9.5).
(b) **Cross-host redirect** — a 3xx response whose ``Location`` points at a
    different host raises :class:`SSRFBlockedError` (NFR-17, AC-9.2).
(c) **Undeclared endpoint path in scope** — a scope constraint whose
    ``field`` cannot pass :func:`nautilus.adapters.base.validate_field`
    (a path-style identifier, standing in for "undeclared endpoint path")
    raises :class:`ScopeEnforcementError`.
(d) **Auth construction** — bearer / basic / mtls / none all construct cleanly.
(e) **End-to-end via** :class:`httpx.MockTransport` — ``GET /widgets?f=x``
    round-trips a filter through the adapter's query-param builder and
    decodes the JSON body into ``AdapterResult.rows``.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from nautilus.adapters.base import ScopeEnforcementError
from nautilus.adapters.rest import (
    _DEFAULT_BUILDERS,  # pyright: ignore[reportPrivateUsage]
    _OPERATOR_ALLOWLIST,  # pyright: ignore[reportPrivateUsage]
    RestAdapter,
    SSRFBlockedError,
    _auth_for_config,  # pyright: ignore[reportPrivateUsage]
    _BearerAuth,  # pyright: ignore[reportPrivateUsage]
)
from nautilus.config.models import (
    BasicAuth,
    BearerAuth,
    EndpointSpec,
    MtlsAuth,
    NoneAuth,
    SourceConfig,
)
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_rest_source(
    *,
    connection: str = "http://api.example.com",
    endpoints: list[EndpointSpec] | None = None,
    auth: Any = None,
) -> SourceConfig:
    if endpoints is None:
        endpoints = [EndpointSpec(path="/widgets", method="GET")]
    return SourceConfig(
        id="rest_src",
        type="rest",
        description="rest source",
        classification="secret",
        data_types=["widget"],
        allowed_purposes=["research"],
        connection=connection,
        endpoints=endpoints,
        auth=auth if auth is not None else NoneAuth(),
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="fetch widgets",
        data_types_needed=["widget"],
        entities=[],
        temporal_scope=None,
        estimated_sensitivity=None,
    )


async def _connected_adapter(
    *,
    transport: httpx.MockTransport,
    endpoints: list[EndpointSpec] | None = None,
    auth: Any = None,
) -> RestAdapter:
    """Build a connected :class:`RestAdapter` with an injected MockTransport client."""
    client = httpx.AsyncClient(base_url="http://api.example.com", transport=transport)
    adapter = RestAdapter(client=client)
    await adapter.connect(_make_rest_source(endpoints=endpoints, auth=auth))
    return adapter


# ---------------------------------------------------------------------------
# (a) Operator → template drift (NFR-4, AC-9.5)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("operator", sorted(_OPERATOR_ALLOWLIST))
def test_operator_template_drift_every_op_mapped_or_explicitly_rejected(operator: str) -> None:
    """Every allowlisted operator has a default builder OR is ``NOT IN``
    (the one operator documented as 'reject unless endpoint-declared').

    Fails loud if an operator lands in ``_OPERATOR_ALLOWLIST`` without a
    corresponding row in ``_DEFAULT_BUILDERS`` — i.e. the REST adapter would
    silently KeyError at runtime instead of returning a scope-enforcement
    error (NFR-4).
    """
    if operator == "NOT IN":
        # Explicitly-rejected operator — the default-builder entry is the
        # stub ``_b_not_in_default`` whose only job is to raise a uniform
        # ScopeEnforcementError (AC-9.3).
        assert operator in _DEFAULT_BUILDERS, (
            "'NOT IN' must still appear in _DEFAULT_BUILDERS as the rejection stub"
        )
        return
    assert operator in _DEFAULT_BUILDERS, (
        f"operator '{operator}' in _OPERATOR_ALLOWLIST but missing from "
        f"_DEFAULT_BUILDERS — template drift (NFR-4, AC-9.5)"
    )


# ---------------------------------------------------------------------------
# (b) Cross-host redirect → SSRFBlockedError (NFR-17, AC-9.2)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_cross_host_redirect_raises_ssrf_blocked() -> None:
    """A 302 whose ``Location`` points at a different host must surface
    :class:`SSRFBlockedError` — the adapter refuses to chase the redirect.
    """

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"Location": "http://attacker.example.net/exfil"},
        )

    adapter = await _connected_adapter(transport=httpx.MockTransport(_handler))
    try:
        with pytest.raises(SSRFBlockedError):
            await adapter.execute(intent=_intent(), scope=[], context={})
    finally:
        await adapter.close()


# ---------------------------------------------------------------------------
# (c) Undeclared endpoint path in scope → ScopeEnforcementError
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_undeclared_path_in_scope_raises_scope_enforcement() -> None:
    """A scope constraint whose ``field`` is a URL-path-shaped identifier
    (the natural way to express an "undeclared endpoint path") fails the
    adapter's :func:`validate_field` regex and surfaces
    :class:`ScopeEnforcementError`.

    The REST adapter exposes a single configured endpoint path per source
    (``EndpointSpec.path``); runtime routing to an alternate path is not
    supported. Attempting to smuggle a path through the scope layer must
    therefore fail closed at the adapter (AC-9.1, NFR-4).
    """

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": []})

    adapter = await _connected_adapter(transport=httpx.MockTransport(_handler))
    try:
        # "/gadgets" is neither a configured endpoint path nor a valid field
        # identifier — it contains a leading slash, which the §6.2 field
        # regex explicitly forbids.
        bad = ScopeConstraint.model_construct(
            source_id="rest_src",
            field="/gadgets",
            operator="=",
            value="any",
        )
        with pytest.raises(ScopeEnforcementError):
            adapter._build_params([bad])  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    finally:
        await adapter.close()


# ---------------------------------------------------------------------------
# (d) Auth modes all construct (bearer / basic / mtls / none)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_auth_bearer_constructs() -> None:
    """``BearerAuth`` resolves to a ``_BearerAuth`` wrapper (custom httpx.Auth)."""
    config = _make_rest_source(auth=BearerAuth(token="tok-xyz"))
    auth = _auth_for_config(config)
    assert isinstance(auth, _BearerAuth)


@pytest.mark.unit
def test_auth_basic_constructs() -> None:
    """``BasicAuth`` resolves to ``httpx.BasicAuth``."""
    config = _make_rest_source(auth=BasicAuth(username="u", password="p"))
    auth = _auth_for_config(config)
    assert isinstance(auth, httpx.BasicAuth)


@pytest.mark.unit
async def test_auth_mtls_constructs() -> None:
    """``MtlsAuth`` does not return a per-request ``Auth`` (returns ``None``);
    mTLS material flows to the ``AsyncClient`` via ``cert`` / ``verify``.
    """
    config = _make_rest_source(
        auth=MtlsAuth(cert_path="/tmp/c.pem", key_path="/tmp/k.pem", ca_path="/tmp/ca.pem"),
    )
    # Per-request auth is None for mTLS (cert/key flow to client construction).
    assert _auth_for_config(config) is None

    # Constructing the adapter with mTLS + an injected MockTransport client
    # verifies the mtls auth kind does not trip connect() validation.
    def _ok(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": []})

    client = httpx.AsyncClient(
        base_url="http://api.example.com",
        transport=httpx.MockTransport(_ok),
    )
    adapter = RestAdapter(client=client)
    await adapter.connect(config)
    try:
        assert adapter._base_host == "api.example.com"  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    finally:
        await adapter.close()


@pytest.mark.unit
def test_auth_none_constructs() -> None:
    """``NoneAuth`` resolves to ``None`` (no per-request auth injected)."""
    config = _make_rest_source(auth=NoneAuth())
    assert _auth_for_config(config) is None


# ---------------------------------------------------------------------------
# (e) httpx.MockTransport end-to-end: GET /widgets?f=x
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_mock_transport_e2e_get_widgets_with_query_param() -> None:
    """End-to-end round-trip through ``httpx.MockTransport``:

    - Adapter is configured with endpoint ``/widgets`` (GET).
    - Scope carries a single ``f = x`` constraint.
    - The outgoing request must target ``/widgets`` with exactly one
      ``f=x`` query-string entry.
    - The 200 JSON body decodes into :class:`AdapterResult` rows.
    """
    captured: dict[str, Any] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["query"] = dict(request.url.params)
        return httpx.Response(200, json=[{"id": 1}])

    adapter = await _connected_adapter(transport=httpx.MockTransport(_handler))
    try:
        result = await adapter.execute(
            intent=_intent(),
            scope=[
                ScopeConstraint(source_id="rest_src", field="f", operator="=", value="x"),
            ],
            context={},
        )
    finally:
        await adapter.close()

    assert captured["method"] == "GET"
    assert captured["path"] == "/widgets"
    assert captured["query"] == {"f": "x"}

    assert isinstance(result, AdapterResult)
    assert result.source_id == "rest_src"
    assert result.rows == [{"id": 1}]
