"""Task 44 — Nautobot REST fallback paths (AC-1.6, AC-1.10, NFR-SSRF)."""

from __future__ import annotations

import httpx
import pytest
import respx
from nautilus_adapter_nautobot.adapter import NautobotAdapter
from nautilus_adapter_nautobot.errors import NautobotUnsupportedOperation
from nautilus_adapter_nautobot.rest import (
    REST_DEFAULT_LIMIT,
    fetch_paginated,
    reject_writes,
)

from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis

pytestmark = pytest.mark.unit


def _config(url: str = "https://nautobot.example.com") -> SourceConfig:
    return SourceConfig(
        id="nb",
        type="nautobot",
        description="t",
        classification="internal",
        data_types=["device"],
        connection=url,
        token_secret_ref="bearer-token-literal",
    )


def test_reject_writes_blocks_post() -> None:
    with pytest.raises(NautobotUnsupportedOperation, match="read-only"):
        reject_writes("POST")
    with pytest.raises(NautobotUnsupportedOperation):
        reject_writes("PATCH")
    # GET passes silently.
    reject_writes("GET")


@pytest.mark.asyncio
async def test_pagination_iterates_until_short_page() -> None:
    page1 = {"results": [{"id": "1"}, {"id": "2"}]}
    page2 = {"results": []}
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.get("/api/dcim/devices/").mock(
            side_effect=[
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
            ]
        )
        async with httpx.AsyncClient(base_url="https://nautobot.example.com") as client:
            rows = await fetch_paginated(
                client=client,
                path="/api/dcim/devices/",
                token="t",
                base_host="nautobot.example.com",
                limit=2,
            )
    assert [r["id"] for r in rows] == ["1", "2"]


@pytest.mark.asyncio
async def test_pagination_stops_on_short_page_first_call() -> None:
    page = {"results": [{"id": "x"}]}
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.get("/api/dcim/devices/").mock(return_value=httpx.Response(200, json=page))
        async with httpx.AsyncClient(base_url="https://nautobot.example.com") as client:
            rows = await fetch_paginated(
                client=client,
                path="/api/dcim/devices/",
                token="t",
                base_host="nautobot.example.com",
                limit=REST_DEFAULT_LIMIT,
            )
    assert rows == [{"id": "x"}]


@pytest.mark.asyncio
async def test_ssrf_loopback_rejected_at_connect() -> None:
    adapter = NautobotAdapter()
    with pytest.raises(Exception, match="loopback|private"):
        await adapter.connect(_config(url="http://127.0.0.1"))


@pytest.mark.asyncio
async def test_ssrf_metadata_ip_rejected_at_connect() -> None:
    adapter = NautobotAdapter()
    with pytest.raises(Exception, match="link-local|private"):
        await adapter.connect(_config(url="http://169.254.169.254"))


@pytest.mark.asyncio
async def test_rest_fallback_for_ip_to_interface() -> None:
    adapter = NautobotAdapter()
    intro = {"data": {"__type": {"fields": []}}}
    page = {"results": [{"id": "1", "ip_address": {"id": "ipa"}, "interface": {"id": "ifa"}}]}
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.post("/api/graphql/").mock(return_value=httpx.Response(200, json=intro))
        router.get("/api/ipam/ip-address-to-interface/").mock(
            return_value=httpx.Response(200, json=page)
        )
        await adapter.connect(_config())
        intent = IntentAnalysis(
            raw_intent="m2m", data_types_needed=["ip_address_to_interface"], entities=[]
        )
        result = await adapter.execute(intent, [], {})
    await adapter.close()
    assert result.error is None
    assert result.rows[0]["_data_type"] == "ip_address_to_interface"
    assert result.rows[0]["interface"] == {"id": "ifa"}
