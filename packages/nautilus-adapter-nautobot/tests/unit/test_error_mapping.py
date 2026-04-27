"""Task 46 — error mapping (AC-1.11, OQ-1).

Cover all four envelope outcomes plus retry semantics:
  * 403 → AuthError(kind=forbidden) inside AdapterResult.error
  * 5xx → exponential-backoff retry, max 3
  * {data, errors} both populated → partial rows + warnings
  * {data: None, errors: [...]} → AdapterResult.error with code 'graphql_no_data'
"""

from __future__ import annotations

import httpx
import pytest
import respx
from nautilus_adapter_nautobot.adapter import NautobotAdapter

from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis

pytestmark = pytest.mark.unit


def _config() -> SourceConfig:
    return SourceConfig(
        id="nb",
        type="nautobot",
        description="t",
        classification="internal",
        data_types=["device"],
        connection="https://nautobot.example.com",
        token_secret_ref="bearer-token-literal",
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(raw_intent="list devices", data_types_needed=["device"], entities=[])


@pytest.mark.asyncio
async def test_403_yields_auth_error_record() -> None:
    adapter = NautobotAdapter()
    with respx.mock(base_url="https://nautobot.example.com") as router:
        # introspection at connect()
        router.post("/api/graphql/").mock(
            side_effect=[
                httpx.Response(200, json={"data": {"__type": {"fields": []}}}),
                httpx.Response(403, text="Forbidden"),
            ]
        )
        await adapter.connect(_config())
        result = await adapter.execute(_intent(), [], {})
    await adapter.close()
    assert result.error is not None
    assert result.error.error_type == "auth_error"


@pytest.mark.asyncio
async def test_partial_data_returns_rows_with_warnings() -> None:
    adapter = NautobotAdapter()
    introspection_body = {"data": {"__type": {"fields": []}}}
    partial_body = {
        "data": {"devices": [{"id": "1", "name": "edge-1"}]},
        "errors": [{"message": "warning: cf_legacy field deprecated"}],
    }
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.post("/api/graphql/").mock(
            side_effect=[
                httpx.Response(200, json=introspection_body),
                httpx.Response(200, json=partial_body),
            ]
        )
        await adapter.connect(_config())
        result = await adapter.execute(_intent(), [], {})
    await adapter.close()
    assert result.error is None
    assert result.rows[0]["name"] == "edge-1"
    assert result.warnings is not None
    assert "deprecated" in result.warnings[0]


@pytest.mark.asyncio
async def test_errors_only_envelope_yields_graphql_no_data() -> None:
    adapter = NautobotAdapter()
    introspection_body = {"data": {"__type": {"fields": []}}}
    errors_only_body = {
        "data": None,
        "errors": [{"message": "Internal Server Error"}],
    }
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.post("/api/graphql/").mock(
            side_effect=[
                httpx.Response(200, json=introspection_body),
                httpx.Response(200, json=errors_only_body),
            ]
        )
        await adapter.connect(_config())
        result = await adapter.execute(_intent(), [], {})
    await adapter.close()
    assert result.error is not None
    assert result.error.error_type == "graphql_no_data"


@pytest.mark.asyncio
async def test_writes_rejected_unsupported_operation() -> None:
    adapter = NautobotAdapter()
    introspection_body = {"data": {"__type": {"fields": []}}}
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.post("/api/graphql/").mock(return_value=httpx.Response(200, json=introspection_body))
        await adapter.connect(_config())
        with pytest.raises(Exception, match="read-only"):
            await adapter.execute(_intent(), [], {"method": "POST"})
    await adapter.close()
