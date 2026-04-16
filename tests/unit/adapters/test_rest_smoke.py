"""Smoke coverage for :mod:`nautilus.adapters.rest` (Task 2.14 bridge).

Exercises the URL-build / scope-enforcement surface of :class:`RestAdapter`
so the [VERIFY] 2.14 gate clears the 80% branch floor. No live network is
touched — :class:`httpx.MockTransport` stands in for the real upstream and
the SSRF redirect path is triggered via a synthetic 302 response.

Locked behavior:

- ``connect()`` rejects loopback / private IP-literal base URLs with
  :class:`SSRFBlockedError` (NFR-17, AC-9.2) BEFORE building the client.
- ``connect()`` accepts a public-looking hostname base URL + injected
  fake :class:`httpx.AsyncClient`.
- ``connect()`` rejects ``endpoints=[]`` and unknown operator keys in
  ``EndpointSpec.operator_templates`` (AC-9.3).
- Every default operator template dispatches to the expected query-param
  shape; ``NOT IN`` is rejected unless endpoint-declared (AC-9.3).
- A cross-host 3xx redirect raises :class:`SSRFBlockedError`; a same-host
  3xx is also refused with a distinct message.
- ``close()`` is idempotent (FR-17).
- Auth plumbing: ``BearerAuth`` / ``BasicAuth`` / ``NoneAuth`` each produce
  the expected ``httpx.Auth`` (or ``None``).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from nautilus.adapters.base import AdapterError, ScopeEnforcementError
from nautilus.adapters.rest import (
    RestAdapter,
    SSRFBlockedError,
    _auth_for_config,  # pyright: ignore[reportPrivateUsage]
    _BearerAuth,  # pyright: ignore[reportPrivateUsage]
    _coerce_rows,  # pyright: ignore[reportPrivateUsage]
    _reject_private_ip_literal,  # pyright: ignore[reportPrivateUsage]
)
from nautilus.config.models import (
    BasicAuth,
    BearerAuth,
    EndpointSpec,
    NoneAuth,
    SourceConfig,
)
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint


def _make_rest_source(
    connection: str = "http://api.example.com",
    endpoints: list[EndpointSpec] | None = None,
    auth: Any = None,
) -> SourceConfig:
    if endpoints is None:
        endpoints = [EndpointSpec(path="/v1/things", method="GET")]
    return SourceConfig(
        id="rest_src",
        type="rest",
        description="rest source",
        classification="secret",
        data_types=["thing"],
        allowed_purposes=["research"],
        connection=connection,
        endpoints=endpoints,
        auth=auth if auth is not None else NoneAuth(),
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="fetch things",
        data_types_needed=["thing"],
        entities=[],
        temporal_scope=None,
        estimated_sensitivity=None,
    )


async def _connected_adapter(
    *,
    endpoints: list[EndpointSpec] | None = None,
    transport: httpx.MockTransport | None = None,
) -> RestAdapter:
    """Build a connected :class:`RestAdapter` with an injected MockTransport client."""
    if transport is None:

        def _ok_handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": []})

        transport = httpx.MockTransport(_ok_handler)
    client = httpx.AsyncClient(base_url="http://api.example.com", transport=transport)
    adapter = RestAdapter(client=client)
    await adapter.connect(_make_rest_source(endpoints=endpoints))
    return adapter


# ---------------------------------------------------------------------------
# connect() — SSRF / base-URL validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_connect_rejects_loopback_ip() -> None:
    """AC-9.2 — ``http://127.0.0.1`` is refused before the client is built."""
    adapter = RestAdapter(client=MagicMock())
    with pytest.raises(SSRFBlockedError):
        await adapter.connect(_make_rest_source(connection="http://127.0.0.1/"))


@pytest.mark.unit
async def test_connect_rejects_private_rfc1918_ip() -> None:
    """Private RFC1918 IP literals also trip the SSRF guard."""
    adapter = RestAdapter(client=MagicMock())
    with pytest.raises(SSRFBlockedError):
        await adapter.connect(_make_rest_source(connection="http://10.0.0.5/"))


@pytest.mark.unit
async def test_connect_rejects_link_local_metadata_ip() -> None:
    """The AWS/GCP metadata IP must not be reachable through the adapter."""
    adapter = RestAdapter(client=MagicMock())
    with pytest.raises(SSRFBlockedError):
        await adapter.connect(_make_rest_source(connection="http://169.254.169.254/"))


@pytest.mark.unit
def test_reject_private_ip_literal_rejects_empty_host() -> None:
    """An unparseable base URL with empty host raises :class:`ScopeEnforcementError`."""
    with pytest.raises(ScopeEnforcementError):
        _reject_private_ip_literal("http://")


@pytest.mark.unit
def test_reject_private_ip_literal_accepts_hostname() -> None:
    """Hostnames are not resolved at connect time (module docstring)."""
    # Should not raise.
    _reject_private_ip_literal("https://api.example.com/")


@pytest.mark.unit
async def test_connect_accepts_public_hostname_with_injected_client() -> None:
    """Public-looking hostname + injected MockTransport client constructs cleanly."""
    adapter = await _connected_adapter()
    assert adapter._base_host == "api.example.com"  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    await adapter.close()


# ---------------------------------------------------------------------------
# connect() — endpoint allowlist
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_connect_rejects_empty_endpoints_list() -> None:
    """``endpoints=[]`` is a config error, not a Phase-1 fallback."""
    config = _make_rest_source(endpoints=[])
    adapter = RestAdapter(client=MagicMock())
    with pytest.raises(ScopeEnforcementError):
        await adapter.connect(config)


@pytest.mark.unit
async def test_connect_rejects_unknown_operator_template() -> None:
    """Unknown operator keys in ``EndpointSpec.operator_templates`` fail early."""
    bad_endpoint = EndpointSpec(
        path="/v1/things",
        method="GET",
        operator_templates={"DROP TABLE": "boom"},
    )
    adapter = RestAdapter(client=MagicMock())
    with pytest.raises(ScopeEnforcementError):
        await adapter.connect(_make_rest_source(endpoints=[bad_endpoint]))


@pytest.mark.unit
async def test_connect_without_endpoints_is_phase1_compat() -> None:
    """NFR-5: a source without ``endpoints`` falls back to base-URL + empty path."""
    config = SourceConfig(
        id="legacy",
        type="rest",
        description="phase-1 compat source",
        classification="public",
        data_types=["thing"],
        allowed_purposes=["research"],
        connection="http://api.example.com",
        endpoints=None,
        auth=NoneAuth(),
    )
    client = httpx.AsyncClient(base_url="http://api.example.com")
    adapter = RestAdapter(client=client)
    await adapter.connect(config)
    assert adapter._endpoint is None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    await adapter.close()


# ---------------------------------------------------------------------------
# Operator template dispatch
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_build_params_eq() -> None:
    adapter = await _connected_adapter()
    params = adapter._build_params(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        [ScopeConstraint(source_id="rest_src", field="severity", operator="=", value="high")]
    )
    assert params == [("severity", "high")]
    await adapter.close()


@pytest.mark.unit
async def test_build_params_ne() -> None:
    adapter = await _connected_adapter()
    params = adapter._build_params(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        [ScopeConstraint(source_id="rest_src", field="severity", operator="!=", value="low")]
    )
    assert params == [("severity__ne", "low")]
    await adapter.close()


@pytest.mark.unit
async def test_build_params_in_repeats_key() -> None:
    adapter = await _connected_adapter()
    params = adapter._build_params(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        [
            ScopeConstraint(
                source_id="rest_src",
                field="status",
                operator="IN",
                value=["open", "triaged"],
            )
        ]
    )
    assert params == [("status", "open"), ("status", "triaged")]
    await adapter.close()


@pytest.mark.unit
async def test_build_params_not_in_rejected_without_declaration() -> None:
    """``NOT IN`` is not in the default builder table (AC-9.3)."""
    adapter = await _connected_adapter()
    with pytest.raises(ScopeEnforcementError):
        adapter._build_params(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            [
                ScopeConstraint(
                    source_id="rest_src",
                    field="status",
                    operator="NOT IN",
                    value=["closed"],
                )
            ]
        )
    await adapter.close()


@pytest.mark.unit
async def test_build_params_not_in_accepted_when_declared() -> None:
    """An endpoint declaring ``NOT IN`` opts into the ``__nin`` render."""
    endpoint = EndpointSpec(
        path="/v1/things",
        method="GET",
        operator_templates={"NOT IN": "declared"},
    )
    adapter = await _connected_adapter(endpoints=[endpoint])
    params = adapter._build_params(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        [
            ScopeConstraint(
                source_id="rest_src",
                field="status",
                operator="NOT IN",
                value=["closed", "duplicate"],
            )
        ]
    )
    assert params == [("status__nin", "closed"), ("status__nin", "duplicate")]
    await adapter.close()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("op", "suffix"),
    [("<", "__lt"), (">", "__gt"), ("<=", "__lte"), (">=", "__gte")],
)
async def test_build_params_relational(op: str, suffix: str) -> None:
    adapter = await _connected_adapter()
    params = adapter._build_params(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        [ScopeConstraint(source_id="rest_src", field="cvss", operator=op, value=7.0)]  # type: ignore[arg-type]
    )
    assert params == [(f"cvss{suffix}", "7.0")]
    await adapter.close()


@pytest.mark.unit
async def test_build_params_between_emits_two_keys() -> None:
    adapter = await _connected_adapter()
    params = adapter._build_params(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        [
            ScopeConstraint(
                source_id="rest_src",
                field="cvss",
                operator="BETWEEN",
                value=[5.0, 9.0],
            )
        ]
    )
    assert params == [("cvss__gte", "5.0"), ("cvss__lte", "9.0")]
    await adapter.close()


@pytest.mark.unit
async def test_build_params_like_contains() -> None:
    adapter = await _connected_adapter()
    params = adapter._build_params(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        [ScopeConstraint(source_id="rest_src", field="title", operator="LIKE", value="CVE-")]
    )
    assert params == [("title__contains", "CVE-")]
    await adapter.close()


@pytest.mark.unit
async def test_build_params_is_null_emits_true_flag() -> None:
    adapter = await _connected_adapter()
    params = adapter._build_params(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        [
            ScopeConstraint(
                source_id="rest_src",
                field="closed_at",
                operator="IS NULL",
                value=None,
            )
        ]
    )
    assert params == [("closed_at__isnull", "true")]
    await adapter.close()


# ---------------------------------------------------------------------------
# Typecheck guards (mirror ES/Neo4j shape — NFR-4)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_build_params_in_requires_list() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "IN"
    bad.field = "severity"
    bad.value = "scalar"
    with pytest.raises(ScopeEnforcementError):
        adapter._build_params([bad])  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    await adapter.close()


@pytest.mark.unit
async def test_build_params_like_requires_string() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "LIKE"
    bad.field = "title"
    bad.value = 42
    with pytest.raises(ScopeEnforcementError):
        adapter._build_params([bad])  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    await adapter.close()


@pytest.mark.unit
async def test_build_params_between_requires_2_seq() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "BETWEEN"
    bad.field = "cvss"
    bad.value = [1.0]  # length 1
    with pytest.raises(ScopeEnforcementError):
        adapter._build_params([bad])  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    await adapter.close()


@pytest.mark.unit
async def test_build_params_between_rejects_scalar() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "BETWEEN"
    bad.field = "cvss"
    bad.value = 5.0
    with pytest.raises(ScopeEnforcementError):
        adapter._build_params([bad])  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    await adapter.close()


@pytest.mark.unit
async def test_build_params_unknown_operator_raises() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "DROP TABLE"
    bad.field = "severity"
    bad.value = "x"
    with pytest.raises(ScopeEnforcementError):
        adapter._build_params([bad])  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    await adapter.close()


@pytest.mark.unit
async def test_build_params_bad_field_identifier_raises() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "="
    bad.field = "bad field with spaces"
    bad.value = "x"
    with pytest.raises(ScopeEnforcementError):
        adapter._build_params([bad])  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    await adapter.close()


# ---------------------------------------------------------------------------
# execute() — happy path + SSRF redirect guard
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_execute_happy_path_returns_rows() -> None:
    """A 200 with a ``results`` envelope yields an :class:`AdapterResult`."""

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(
            200,
            json={"results": [{"id": 1}, {"id": 2}]},
        )

    transport = httpx.MockTransport(_handler)
    adapter = await _connected_adapter(transport=transport)
    try:
        result = await adapter.execute(
            intent=_intent(),
            scope=[ScopeConstraint(source_id="rest_src", field="id", operator="=", value=1)],
            context={},
        )
        assert isinstance(result, AdapterResult)
        assert result.source_id == "rest_src"
        assert result.rows == [{"id": 1}, {"id": 2}]
    finally:
        await adapter.close()


@pytest.mark.unit
async def test_execute_rejects_cross_host_redirect() -> None:
    """A 302 to a different host raises :class:`SSRFBlockedError`."""

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://evil.example.com/steal"})

    transport = httpx.MockTransport(_handler)
    adapter = await _connected_adapter(transport=transport)
    try:
        with pytest.raises(SSRFBlockedError):
            await adapter.execute(intent=_intent(), scope=[], context={})
    finally:
        await adapter.close()


@pytest.mark.unit
async def test_execute_rejects_same_host_redirect() -> None:
    """Even same-host 3xx is refused (predictable behavior)."""

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://api.example.com/other"})

    transport = httpx.MockTransport(_handler)
    adapter = await _connected_adapter(transport=transport)
    try:
        with pytest.raises(SSRFBlockedError):
            await adapter.execute(intent=_intent(), scope=[], context={})
    finally:
        await adapter.close()


@pytest.mark.unit
async def test_execute_before_connect_raises() -> None:
    adapter = RestAdapter(client=None)
    with pytest.raises(AdapterError):
        await adapter.execute(intent=_intent(), scope=[], context={})


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_close_is_idempotent() -> None:
    """FR-17: second ``close()`` is a no-op."""
    fake_client = MagicMock()
    fake_client.aclose = AsyncMock()
    adapter = RestAdapter(client=fake_client)
    await adapter.connect(_make_rest_source())

    await adapter.close()
    await adapter.close()
    await adapter.close()

    assert fake_client.aclose.await_count == 1


@pytest.mark.unit
async def test_close_without_connect_is_safe() -> None:
    adapter = RestAdapter(client=None)
    await adapter.close()
    await adapter.close()


# ---------------------------------------------------------------------------
# Auth plumbing
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_auth_for_config_bearer_returns_bearer_wrapper() -> None:
    config = _make_rest_source(auth=BearerAuth(token="t-abc"))
    auth = _auth_for_config(config)
    assert isinstance(auth, _BearerAuth)


@pytest.mark.unit
def test_auth_for_config_basic_returns_httpx_basic() -> None:
    config = _make_rest_source(auth=BasicAuth(username="u", password="p"))
    auth = _auth_for_config(config)
    assert isinstance(auth, httpx.BasicAuth)


@pytest.mark.unit
def test_auth_for_config_none_returns_none() -> None:
    config = _make_rest_source(auth=NoneAuth())
    assert _auth_for_config(config) is None


# ---------------------------------------------------------------------------
# _coerce_rows body-shape variants
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_coerce_rows_accepts_bare_list() -> None:
    assert _coerce_rows([{"a": 1}, {"b": 2}], limit=10) == [{"a": 1}, {"b": 2}]


@pytest.mark.unit
def test_coerce_rows_accepts_data_key() -> None:
    assert _coerce_rows({"data": [{"a": 1}]}, limit=10) == [{"a": 1}]


@pytest.mark.unit
def test_coerce_rows_accepts_items_key() -> None:
    assert _coerce_rows({"items": [{"a": 1}]}, limit=10) == [{"a": 1}]


@pytest.mark.unit
def test_coerce_rows_wraps_bare_dict() -> None:
    body = {"single": True}
    assert _coerce_rows(body, limit=10) == [body]


@pytest.mark.unit
def test_coerce_rows_rejects_non_dict_items_in_list() -> None:
    assert _coerce_rows([{"ok": 1}, "bad", 42], limit=10) == [{"ok": 1}]


@pytest.mark.unit
def test_coerce_rows_on_scalar_body_returns_empty() -> None:
    assert _coerce_rows("not a shape", limit=10) == []


@pytest.mark.unit
def test_coerce_rows_honours_limit() -> None:
    rows = [{"i": i} for i in range(5)]
    assert _coerce_rows(rows, limit=2) == [{"i": 0}, {"i": 1}]
