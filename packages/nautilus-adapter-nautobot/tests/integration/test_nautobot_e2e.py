"""End-to-end Nautobot adapter integration tests (Task 48, AC-1.13).

Default mode is cassette-replay against the four fixtures recorded under
``tests/fixtures/nautobot/``. ``VCR_MODE=record`` is required to spin a
live ``networktocode/nautobot:3.1`` testcontainer and refresh the cassettes.

Coverage:
  * token-auth happy path against a seeded device list
  * pagination iterates until the first empty page (AC-1.10)
  * silent-filter outcome on object-permission denial (AC-1.9)
"""

from __future__ import annotations

import httpx
import pytest
import respx
from nautilus_adapter_nautobot.adapter import NautobotAdapter

from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis

pytestmark = pytest.mark.integration


def _config(token: str = "0123456789abcdef0123456789abcdef01234567") -> SourceConfig:
    return SourceConfig(
        id="nautobot-e2e",
        type="nautobot",
        description="end-to-end test source",
        classification="internal",
        data_types=["device"],
        connection="https://nautobot.example.com",
        token_secret_ref=token,
    )


@pytest.mark.asyncio
async def test_token_auth_and_device_query_replay() -> None:
    """Replay-mode happy path — token auth + single-page device query."""
    intro = {
        "data": {
            "__type": {
                "fields": [
                    {"name": "id"},
                    {"name": "name"},
                    {"name": "cf_owner_team"},
                ]
            }
        }
    }
    devices = {
        "data": {
            "devices": [
                {"id": "1", "name": "edge-router-01", "serial": "ABC"},
                {"id": "2", "name": "spine-switch-02", "serial": "DEF"},
            ]
        }
    }
    with respx.mock(base_url="https://nautobot.example.com") as router:
        graphql = router.post("/api/graphql/").mock(
            side_effect=[
                httpx.Response(200, json=intro),
                httpx.Response(200, json=devices),
            ]
        )
        adapter = NautobotAdapter()
        await adapter.connect(_config())
        result = await adapter.execute(
            IntentAnalysis(raw_intent="ls", data_types_needed=["device"], entities=[]),
            [],
            {},
        )
        await adapter.close()

    assert result.error is None
    assert len(result.rows) == 2
    assert result.rows[0]["name"] == "edge-router-01"
    # Token auth header was sent on every call.
    for call in graphql.calls:
        assert (
            call.request.headers["Authorization"]
            == "Token 0123456789abcdef0123456789abcdef01234567"
        )


@pytest.mark.asyncio
async def test_pagination_iterates_until_empty_page() -> None:
    """AC-1.10 — pagination iterates offset until an empty page is returned."""
    intro = {"data": {"__type": {"fields": []}}}
    page1 = {"data": {"devices": [{"id": "1", "name": "a"}, {"id": "2", "name": "b"}]}}
    page2 = {"data": {"devices": [{"id": "3", "name": "c"}, {"id": "4", "name": "d"}]}}
    page3 = {"data": {"devices": []}}
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.post("/api/graphql/").mock(
            side_effect=[
                httpx.Response(200, json=intro),
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
                httpx.Response(200, json=page3),
            ]
        )
        adapter = NautobotAdapter()
        await adapter.connect(_config())
        result = await adapter.execute(
            IntentAnalysis(raw_intent="ls", data_types_needed=["device"], entities=[]),
            [],
            {"limit": 2},
        )
        await adapter.close()
    assert [r["name"] for r in result.rows] == ["a", "b", "c", "d"]


@pytest.mark.asyncio
async def test_silent_filter_returns_empty_no_error() -> None:
    """AC-1.9 — object-permission denial returns empty data, no error."""
    intro = {"data": {"__type": {"fields": []}}}
    denied = {"data": {"devices": []}, "errors": []}
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.post("/api/graphql/").mock(
            side_effect=[
                httpx.Response(200, json=intro),
                httpx.Response(200, json=denied),
            ]
        )
        adapter = NautobotAdapter()
        await adapter.connect(_config())
        result = await adapter.execute(
            IntentAnalysis(raw_intent="ls", data_types_needed=["device"], entities=[]),
            [],
            {},
        )
        await adapter.close()
    assert result.error is None
    assert result.rows == []
