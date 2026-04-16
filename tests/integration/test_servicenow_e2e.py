"""Integration e2e for :class:`ServiceNowAdapter` (Task 3.15).

No live ServiceNow instance is touched — :class:`httpx.MockTransport` stands
in for the Table-API upstream. The handler parses the incoming request's
``sysparm_query`` parameter and echoes a deterministic ``{"result": [...]}``
body so we can assert on the exact on-wire GlideRecord encoding.

Two scenarios live here (AC-11.5 / FR-23):

1. ``test_servicenow_e2e_full_operator_set_round_trips`` — every operator in
   the adapter's allowlist round-trips through the composed ``sysparm_query``
   string, ``^``-separated, and the adapter returns the mock upstream rows
   unmodified.
2. ``test_servicenow_e2e_injection_rejects_separator_chars`` — every
   GlideRecord separator byte (``^`` / ``\n`` / ``\r``) is refused by
   :meth:`ServiceNowAdapter._sanitize_sn_value` with
   :class:`ScopeEnforcementError` (AC-11.1).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from nautilus.adapters.base import ScopeEnforcementError
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.config.models import NoneAuth, SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint

pytestmark = pytest.mark.integration


def _sn_source() -> SourceConfig:
    """ServiceNow source pointed at the MockTransport fake upstream."""
    return SourceConfig(
        id="sn_src",
        type="servicenow",
        description="SN incidents (mock)",
        classification="secret",
        data_types=["incident"],
        allowed_purposes=["research"],
        connection="https://dev.service-now.com",
        table="incident",
        auth=NoneAuth(),
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="look up incidents",
        data_types_needed=["incident"],
        entities=[],
    )


async def test_servicenow_e2e_full_operator_set_round_trips() -> None:
    """Every allowlist operator round-trips through ``sysparm_query`` (AC-11.2)."""
    captured: dict[str, str] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        # Capture the on-wire ``sysparm_query`` so the test can assert the
        # exact GlideRecord encoding below.
        captured["sysparm_query"] = request.url.params.get("sysparm_query", "")
        captured["sysparm_limit"] = request.url.params.get("sysparm_limit", "")
        captured["path"] = request.url.path
        return httpx.Response(
            200,
            json={"result": [{"number": "INC0001"}, {"number": "INC0002"}]},
        )

    transport = httpx.MockTransport(_handler)
    client = httpx.AsyncClient(
        base_url="https://dev.service-now.com",
        transport=transport,
    )
    adapter = ServiceNowAdapter(client=client)
    await adapter.connect(_sn_source())

    try:
        # One constraint per allowlisted operator (AC-11.2) — covers
        # ``=``, ``!=``, ``<``, ``>``, ``<=``, ``>=``, ``LIKE``, ``IN``,
        # ``NOT IN``, ``BETWEEN``, ``IS NULL``.
        scope: list[ScopeConstraint] = [
            ScopeConstraint(source_id="sn_src", field="state", operator="=", value="open"),
            ScopeConstraint(source_id="sn_src", field="state", operator="!=", value="closed"),
            ScopeConstraint(source_id="sn_src", field="priority", operator="<", value=3),
            ScopeConstraint(source_id="sn_src", field="priority", operator=">", value=0),
            ScopeConstraint(source_id="sn_src", field="priority", operator="<=", value=2),
            ScopeConstraint(source_id="sn_src", field="priority", operator=">=", value=1),
            ScopeConstraint(
                source_id="sn_src", field="short_description", operator="LIKE", value="outage"
            ),
            ScopeConstraint(
                source_id="sn_src",
                field="category",
                operator="IN",
                value=["hardware", "network"],
            ),
            ScopeConstraint(
                source_id="sn_src",
                field="category",
                operator="NOT IN",
                value=["cosmetic"],
            ),
            ScopeConstraint(
                source_id="sn_src",
                field="priority",
                operator="BETWEEN",
                value=[1, 3],
            ),
            ScopeConstraint(source_id="sn_src", field="closed_at", operator="IS NULL", value=None),
        ]

        result = await adapter.execute(intent=_intent(), scope=scope, context={})

        # Adapter surfaced the mock upstream rows.
        assert result.source_id == "sn_src"
        assert result.rows == [{"number": "INC0001"}, {"number": "INC0002"}]

        # Verify the request hit the right path and picked up the limit.
        assert captured["path"] == "/api/now/table/incident"
        assert captured["sysparm_limit"] == "1000"

        # Verify each operator's encoded segment is present, ``^``-separated.
        sysparm_query = captured["sysparm_query"]
        segments = sysparm_query.split("^")

        # Exactly one segment per constraint (no extra injection).
        assert len(segments) == len(scope), (
            f"expected {len(scope)} segments; got {len(segments)}: {sysparm_query!r}"
        )

        expected_segments = [
            "state=open",
            "state!=closed",
            "priority<3",
            "priority>0",
            "priority<=2",
            "priority>=1",
            "short_descriptionLIKEoutage",
            "categoryINhardware,network",
            "categoryNOT INcosmetic",
            "priorityBETWEEN1@3",
            "closed_atISEMPTY",
        ]
        for expected, actual in zip(expected_segments, segments, strict=True):
            assert actual == expected, f"segment mismatch: expected {expected!r}, got {actual!r}"
    finally:
        await adapter.close()


@pytest.mark.parametrize(
    "bad_value",
    [
        "bad^value",  # encoded-query separator
        "bad\nvalue",  # inline terminator
        "bad\rvalue",  # CR terminator (NFR-18)
    ],
)
async def test_servicenow_e2e_injection_rejects_separator_chars(bad_value: str) -> None:
    """Values containing ``^`` / ``\\n`` / ``\\r`` are rejected (AC-11.1)."""
    with pytest.raises(ScopeEnforcementError):
        ServiceNowAdapter._sanitize_sn_value(bad_value)  # pyright: ignore[reportPrivateUsage]


async def test_servicenow_e2e_injection_blocks_scope_value_through_build() -> None:
    """End-to-end: a poisoned scope value never reaches the upstream."""
    calls: list[Any] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"result": []})

    transport = httpx.MockTransport(_handler)
    client = httpx.AsyncClient(
        base_url="https://dev.service-now.com",
        transport=transport,
    )
    adapter = ServiceNowAdapter(client=client)
    await adapter.connect(_sn_source())

    try:
        poisoned = [
            ScopeConstraint(
                source_id="sn_src",
                field="state",
                operator="=",
                value="open^state=closed",  # smuggled extra segment
            )
        ]
        with pytest.raises(ScopeEnforcementError):
            await adapter.execute(intent=_intent(), scope=poisoned, context={})
        assert calls == [], "poisoned value must be rejected before any request is made"
    finally:
        await adapter.close()
