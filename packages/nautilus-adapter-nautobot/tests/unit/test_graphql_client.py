"""Task 43 — Nautobot GraphQL client (AC-1.6, AC-1.7)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from nautilus_adapter_nautobot.graphql import (
    DATA_TYPE_QUERIES,
    QUERY_INTERFACES,
    post_graphql,
    split_envelope,
)

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_post_graphql_sends_token_and_returns_envelope() -> None:
    body = {"data": {"devices": [{"id": "1"}]}, "errors": []}
    with respx.mock(base_url="https://nautobot.example.com") as router:
        route = router.post("/api/graphql/").mock(return_value=httpx.Response(200, json=body))
        async with httpx.AsyncClient(base_url="https://nautobot.example.com") as client:
            data, errors = await post_graphql(
                client=client,
                token="abc-123",
                query=DATA_TYPE_QUERIES["device"][0],
                variables={"limit": 100, "offset": 0},
            )
    assert data == {"devices": [{"id": "1"}]}
    assert errors == []
    request = route.calls[0].request
    assert request.headers["Authorization"] == "Token abc-123"
    payload = json.loads(request.read())
    assert payload["variables"] == {"limit": 100, "offset": 0}


@pytest.mark.asyncio
async def test_post_graphql_403_raises_auth_error() -> None:
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.post("/api/graphql/").mock(return_value=httpx.Response(403, text="nope"))
        async with httpx.AsyncClient(base_url="https://nautobot.example.com") as client:
            with pytest.raises(Exception, match="HTTP 403"):
                await post_graphql(client=client, token="abc", query=QUERY_INTERFACES)


def test_split_envelope_handles_partial_data() -> None:
    rows, warnings = split_envelope(
        {"devices": [{"id": "x"}]},
        [{"message": "deprecated field"}],
        response_key="devices",
    )
    assert rows == [{"id": "x"}]
    assert "deprecated" in warnings[0]


def test_split_envelope_raises_on_errors_only() -> None:
    with pytest.raises(Exception, match="errors and no data"):
        split_envelope(None, [{"message": "boom"}], response_key="devices")


def test_v3_filter_uses_type_not_underscore_type() -> None:
    """AC-1.7 — v3 GraphQL polymorphic filter is named ``type``, not ``_type``.

    Match only the standalone polymorphic filter (``_type:`` argument or
    ``_type {`` selection), not unrelated field names like ``device_type``.
    """
    import re

    pattern = re.compile(r"\b_type\s*[:{]")
    for query, _key in DATA_TYPE_QUERIES.values():
        assert not pattern.search(query), f"query references v2 polymorphic _type filter: {query}"
