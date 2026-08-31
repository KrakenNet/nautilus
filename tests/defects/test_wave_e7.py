"""WAVE E7 — three majors about what the response tells the model.

Measured against a real 7B model driving the MCP surface, not inferred from
reading the code.

1. **The purpose vocabulary is a dead end.** ``nautilus_request``'s description
   says purpose "should always be set (e.g. 'support', 'care',
   'threat-analysis')". Those three strings are a hardcoded illustration and
   are almost never valid in a real config. When the model used one,
   ``deny-purpose-mismatch`` fired with the fixed reason "purpose not
   authorized", which never names the purposes that *are* authorized, and
   ``nautilus_sources`` deliberately omits ``allowed_purposes``. So the allowed
   set is obtainable from no tool on the surface::

       6 runs x up to 8 steps -> 0/6 reached the data
       21 of 21 attempts used purpose='support' -- the description's own example

   The model never varied it, because nothing told it the guess was in the
   wrong vocabulary rather than merely unauthorised. It concluded the operator
   had misconfigured the broker.

2. **``outcome`` reports refusals for sources the request never concerned.**
   Every rules-refused source emits a ``denial_record`` whether or not the
   intent had anything to do with it, and ``outcome`` puts denials ahead of
   errors. Two wrong answers follow, both reproduced here:

   - the one relevant source hard-errors, three unrelated sources are denied on
     purpose, and the response says ``denied`` -- so the model reported a
     policy refusal while a database was down;
   - nothing configured can answer at all, and the response still says
     ``denied``, citing sources that have nothing to do with the question.

3. **The description promises scoping that the default ruleset never does.**
   "Nautilus decides which of its configured sources may answer, scopes the
   query, runs it". No built-in rule emits a ``scope_constraint``; only the
   optional packs do. ``scope_restrictions`` is ``{}`` on every default
   request, which is also what an unrestricted-but-successful request looks
   like. Asked for "customer 4471 in eu-central only", the broker returned 1000
   rows for 906 other customers and 0 for 4471, and the model answered with two
   order ids from a 2019 cold-storage archive plus a completeness claim --
   because ``data`` is ``{source_id: rows}`` and nothing in the response says
   what a source *is*.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from nautilus.core.models import BrokerResponse

pytestmark = [pytest.mark.integration]

_AGENTS: dict[str, Any] = {"a1": {"id": "a1", "clearance": "unclassified"}}


def _write(tmp_path: Path, sources: list[dict[str, Any]], **extra: Any) -> str:
    document: dict[str, Any] = {
        "sources": sources,
        "agents": _AGENTS,
        "audit": {"path": str(tmp_path / "audit.jsonl")},
    }
    document.update(extra)
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


async def _ask(config: str, intent: str, purpose: str = "analytics") -> BrokerResponse:
    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(config)
    try:
        return await broker.arequest("a1", intent, {"purpose": purpose, "session_id": "s"})
    finally:
        await broker.aclose()


# The shape the live-fire audit ran against: one source that can answer, one
# that cannot and is also purpose-denied.
_DEAD_POSTGRES: dict[str, Any] = {
    "id": "orders_db",
    "type": "postgres",
    "classification": "unclassified",
    "data_types": ["orders"],
    "connection": "postgresql://x:y@127.0.0.1:55499/none",
    "table": "public.orders",
}
_UNRELATED_DENIED: dict[str, Any] = {
    "id": "marketing_leads",
    "type": "static",
    "classification": "unclassified",
    "data_types": ["leads"],
    "allowed_purposes": ["marketing"],
    "rows": [{"id": 1}],
}


# ---------------------------------------------------------------------------
# 2. A refusal that was not about the request is not a verdict on the request.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e7_an_unreachable_source_is_not_reported_as_denied(tmp_path: Path) -> None:
    """A database that is down is an outage, not a policy verdict.

    Told "denied", an operator goes looking for a rule. The audit measured two
    of four model runs dropping the connection failure from the report
    entirely, because the denial noise came first and the error record sat in a
    later field.
    """
    config = _write(tmp_path, [_DEAD_POSTGRES, _UNRELATED_DENIED])
    response = await _ask(config, "list recent orders")

    assert [e.source_id for e in response.sources_errored] == ["orders_db"], response.model_dump()
    assert response.outcome == "errored", (
        f"outcome={response.outcome!r} for a request whose only relevant source "
        f"failed to connect. The denials are for {response.sources_denied}, which "
        f"the intent never concerned."
    )


@pytest.mark.asyncio
async def test_e7_a_question_nothing_can_answer_is_not_reported_as_denied(
    tmp_path: Path,
) -> None:
    """ "Nothing here holds that" and "you were refused" are different answers.

    Asked for payroll, with no source holding payroll, the model told its user
    their access had been denied — quoting three sources that have nothing to
    do with payroll. It had not been denied anything.
    """
    config = _write(tmp_path, [_DEAD_POSTGRES, _UNRELATED_DENIED])
    response = await _ask(config, "payroll records for everyone in engineering")

    assert response.sources_queried == [], response.model_dump()
    assert response.outcome != "denied", (
        f"outcome={response.outcome!r} for a question no configured source can "
        f"answer; the denials cited are {response.sources_denied}"
    )


@pytest.mark.asyncio
async def test_e7_a_denial_says_whether_it_concerned_the_request(tmp_path: Path) -> None:
    """The model has to be able to tell which refusals were about its question."""
    config = _write(tmp_path, [_DEAD_POSTGRES, _UNRELATED_DENIED])
    response = await _ask(config, "list recent orders")

    by_source = {d.source_id: d for d in response.denial_records}
    assert "marketing_leads" in by_source, response.model_dump()
    assert by_source["marketing_leads"].relevant is False, (
        "the denial for 'marketing_leads' (data_types ['leads']) is reported as "
        "relevant to an intent that needed ['orders']"
    )


@pytest.mark.asyncio
async def test_e7_a_denial_about_the_request_still_denies(tmp_path: Path) -> None:
    """Control: a refusal of the source that *could* have answered is a denial.

    Without this, reporting every denial as irrelevant would also pass — and
    the broker would stop telling callers they were refused.
    """
    config = _write(
        tmp_path,
        [
            {
                "id": "orders_db",
                "type": "static",
                "classification": "unclassified",
                "data_types": ["orders"],
                "allowed_purposes": ["billing-support"],
                "rows": [{"id": 1}],
            },
            _UNRELATED_DENIED,
        ],
    )
    response = await _ask(config, "list recent orders")

    by_source = {d.source_id: d for d in response.denial_records}
    assert by_source["orders_db"].relevant is True, (
        "the denial of the one source that offers 'orders' is reported as "
        "irrelevant to an intent that needed 'orders'"
    )
    assert response.outcome == "denied", (
        f"outcome={response.outcome!r} for a request whose relevant source was refused by policy"
    )


# ---------------------------------------------------------------------------
# 1. The purpose vocabulary has to be reachable.
# ---------------------------------------------------------------------------


def _purpose_config(tmp_path: Path) -> str:
    return _write(
        tmp_path,
        [
            {
                "id": "support_tickets",
                "type": "static",
                "classification": "unclassified",
                "description": "Customer support tickets",
                "data_types": ["tickets"],
                "allowed_purposes": ["billing-support", "incident-response"],
                "rows": [{"id": 1}],
            }
        ],
        api={"keys": ["k"]},
    )


def test_e7_the_source_listing_publishes_allowed_purposes(tmp_path: Path) -> None:
    """A caller cannot pick a valid purpose it is never shown.

    ``allowed_purposes`` is metadata, not a credential — it is already in the
    config the operator wrote, and it is the one field that turns a purpose
    denial from a dead end into a retry.
    """
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    with TestClient(create_app(_purpose_config(tmp_path))) as client:
        listing = client.get("/v1/sources", headers={"X-API-Key": "k"})
    assert listing.status_code == 200, listing.text

    entries = cast("list[dict[str, Any]]", listing.json()["sources"])
    tickets = next(s for s in entries if s["id"] == "support_tickets")
    assert sorted(tickets.get("allowed_purposes") or []) == [
        "billing-support",
        "incident-response",
    ], f"GET /v1/sources published {tickets!r} — the allowed purposes are not in it"


def test_e7_the_mcp_source_listing_publishes_allowed_purposes(tmp_path: Path) -> None:
    """The MCP twin of the pin above — this is the surface the model uses."""
    import asyncio

    from nautilus import Broker
    from nautilus.transport.mcp_server import create_server

    broker = Broker.from_config(_purpose_config(tmp_path))
    try:
        server = create_server(None, existing_broker=broker)
        listed = asyncio.run(server.call_tool("nautilus_sources", {}))
    finally:
        broker.close()

    blob = repr(listed)
    assert "billing-support" in blob and "incident-response" in blob, (
        f"nautilus_sources returned no allowed_purposes, so a model that guesses "
        f"a purpose has no way to learn the real vocabulary:\n{blob[:600]}"
    )


@pytest.mark.asyncio
async def test_e7_a_purpose_denial_names_the_purposes_that_would_work(tmp_path: Path) -> None:
    """ "purpose not authorized" ends the conversation; naming the set continues it."""
    response = await _ask(_purpose_config(tmp_path), "customer support tickets", purpose="support")

    reasons = " | ".join(d.reason for d in response.denial_records)
    assert "billing-support" in reasons, (
        f"the purpose denial does not name a purpose that would work: {reasons!r}"
    )


def test_e7_the_tool_description_does_not_invent_a_purpose_vocabulary() -> None:
    """A wrong concrete example is worse than no example.

    Every one of the 21 measured attempts used ``'support'`` — the
    description's own first illustration — against a config where it is not a
    valid purpose.
    """
    from nautilus.transport.mcp_server import create_server

    description = _request_tool_description(create_server)
    for invented in ("'support'", "'care'", "'threat-analysis'"):
        assert invented not in description, (
            f"the nautilus_request description still offers {invented} as a purpose. "
            f"Point the model at nautilus_sources instead."
        )
    assert "nautilus_sources" in description, (
        "the description names no way to discover the purposes a source accepts"
    )


def _request_tool_description(factory: Any) -> str:
    """The description string a model actually reads for ``nautilus_request``."""
    import asyncio
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    config = _write(
        tmp,
        [
            {
                "id": "s",
                "type": "static",
                "classification": "unclassified",
                "data_types": ["x"],
                "rows": [{"id": 1}],
            }
        ],
    )
    from nautilus import Broker

    broker = Broker.from_config(config)
    try:
        server = factory(None, existing_broker=broker)
        tools = asyncio.run(server.list_tools())
    finally:
        broker.close()
    return next(t.description or "" for t in tools if t.name == "nautilus_request")


# ---------------------------------------------------------------------------
# 3. Do not promise scoping that is not configured.
# ---------------------------------------------------------------------------


def test_e7_the_tool_description_does_not_promise_unconfigured_scoping() -> None:
    """No built-in rule emits a scope constraint, so do not say it does.

    The model believed the promise and answered as if a restriction expressed
    in the intent prose had been pushed into the query. It had not been.
    """
    from nautilus.transport.mcp_server import create_server

    description = _request_tool_description(create_server)
    assert "scopes the query" not in description, (
        "the nautilus_request description still promises 'scopes the query' on a "
        "broker whose loaded rules emit no scope_constraint"
    )


@pytest.mark.asyncio
async def test_e7_the_response_says_what_each_queried_source_is(tmp_path: Path) -> None:
    """Two sources of the same shape must be distinguishable in the reply.

    ``data`` is ``{source_id: rows}`` and ``sources_queried`` is bare ids, so a
    model presented 2019 cold-storage rows as a customer's current orders — the
    archive's own description would have stopped it, and the response never
    carried one.
    """
    config = _write(
        tmp_path,
        [
            {
                "id": "orders_archive",
                "type": "static",
                "classification": "unclassified",
                "description": "Archived orders from 2019-2021, cold storage",
                "data_types": ["orders"],
                "rows": [{"id": 9001}],
            }
        ],
    )
    response = await _ask(config, "list recent orders")

    assert response.sources_queried == ["orders_archive"], response.model_dump()
    info = (response.source_info or {}).get("orders_archive")
    assert info is not None, (
        "the response says nothing about what 'orders_archive' is; "
        f"source_info={response.source_info!r}"
    )
    assert "cold storage" in (info.description or ""), (
        f"source_info carries no usable description: {info!r}"
    )
