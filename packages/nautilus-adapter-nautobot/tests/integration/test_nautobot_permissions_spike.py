"""OQ-1 resolution: Nautobot 3.1 returned ``{data: {devices: []}, errors: []}``
on model-level GraphQL denial — the silent-filter behaviour described in
AC-1.9. There is NO HTTP 403 outside the envelope; permission denial is
indistinguishable at transport from a legitimate empty list.

This test pins the observed outcome via the captured cassette at
``tests/fixtures/nautobot/graphql_permission_denied_probe.yaml`` so future
adapter changes that expect a 403 will be caught at CI time.

Re-record with::

    VCR_MODE=record uv run pytest -m nautobot_live \\
        packages/nautilus-adapter-nautobot/tests/integration/test_nautobot_permissions_spike.py
"""

from __future__ import annotations

import httpx
import pytest
import respx
from nautilus_adapter_nautobot.adapter import NautobotAdapter

from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_silent_filter_returns_empty_devices_no_errors() -> None:
    """OQ-1 spike outcome: denial → 200 with empty data, no envelope errors."""
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
        await adapter.connect(
            SourceConfig(
                id="nb-denied",
                type="nautobot",
                description="bot user with object-permission denial",
                classification="internal",
                data_types=["device"],
                connection="https://nautobot.example.com",
                token_secret_ref="denied-bot-token",
            )
        )
        result = await adapter.execute(
            IntentAnalysis(
                raw_intent="list devices",
                data_types_needed=["device"],
                entities=[],
            ),
            [],
            {},
        )
        await adapter.close()

    assert result.error is None
    assert result.rows == []
    # NO 403, NO envelope errors — permission denial silently shrinks the
    # result set. AC-1.9 documents this; adapter callers must use Nautobot
    # audit logs to distinguish denial from "no matching rows".
