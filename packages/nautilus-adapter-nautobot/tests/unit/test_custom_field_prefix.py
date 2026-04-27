"""Task 45 — custom-field prefix introspection at connect() (AC-1.8, TD-13)."""

from __future__ import annotations

import httpx
import pytest
import respx
from nautilus_adapter_nautobot.adapter import (
    DEFAULT_CUSTOM_FIELD_PREFIX,
    NautobotAdapter,
)

from nautilus.config.models import SourceConfig

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


def _intro_response(field_names: list[str]) -> dict:
    return {
        "data": {
            "__type": {
                "fields": [{"name": name} for name in field_names],
            }
        }
    }


@pytest.mark.asyncio
async def test_introspection_resolves_cf_prefix() -> None:
    adapter = NautobotAdapter()
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.post("/api/graphql/").mock(
            return_value=httpx.Response(
                200, json=_intro_response(["name", "serial", "cf_owner_team"])
            )
        )
        await adapter.connect(_config())
    assert adapter.custom_field_prefix == "cf_"
    await adapter.close()


@pytest.mark.asyncio
async def test_introspection_falls_back_when_no_cf_field() -> None:
    adapter = NautobotAdapter()
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.post("/api/graphql/").mock(
            return_value=httpx.Response(200, json=_intro_response(["name", "serial"]))
        )
        await adapter.connect(_config())
    assert adapter.custom_field_prefix == DEFAULT_CUSTOM_FIELD_PREFIX
    await adapter.close()


@pytest.mark.asyncio
async def test_introspection_failure_falls_back_to_default() -> None:
    adapter = NautobotAdapter()
    with respx.mock(base_url="https://nautobot.example.com") as router:
        router.post("/api/graphql/").mock(return_value=httpx.Response(500, text="boom"))
        await adapter.connect(_config())  # MUST NOT raise
    assert adapter.custom_field_prefix == DEFAULT_CUSTOM_FIELD_PREFIX
    await adapter.close()
