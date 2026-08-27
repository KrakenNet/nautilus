"""Journey: the session-aware controls the README calls the key differentiator.

"Unlike stateless policy engines, Nautilus maintains working memory across
requests within a session" -- cumulative exposure, cross-agent handoffs,
escalation detection. Each of those is a promise a user relies on, so each
gets a test that exercises it through the public API against a real backend.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

pytestmark = pytest.mark.journey


AGENTS: dict[str, Any] = {
    "intern": {"id": "intern", "clearance": "unclassified"},
    "analyst": {"id": "analyst", "clearance": "confidential"},
    "chief": {"id": "chief", "clearance": "secret"},
}


def _pii_sources(kinds: tuple[str, ...]) -> list[dict[str, Any]]:
    return [
        {
            "id": f"pii_{kind}",
            "type": "postgres",
            "description": f"{kind} records",
            "classification": "confidential",
            "data_types": ["pii", kind],
            "allowed_purposes": [],
            "connection": "${JOURNEY_PG_DSN}",
            "table": "journey.patients",
        }
        for kind in kinds
    ]


@pytest.fixture
def session_config(pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    return write_config(
        {
            "sources": _pii_sources(("ssn", "dob", "phone", "email")),
            "agents": AGENTS,
        }
    )


# ---------------------------------------------------------------------------
# Cumulative exposure
# ---------------------------------------------------------------------------


def test_sequential_reads_accumulate_in_the_session_ledger(
    session_config: str,
) -> None:
    """ "This agent accessed PII from 3 sources" has to be answerable.

    Sequential requests are the shape the docs teach. (Concurrent requests on
    one session lose entries; that is pinned separately as B3.)
    """
    from nautilus import Broker

    async def _run() -> set[str]:
        broker = Broker.from_config(session_config)
        try:
            for kind in ("ssn", "dob", "phone"):
                await broker.arequest(
                    "analyst", kind, {"purpose": "care", "session_id": "cumulative"}
                )
            store: Any = broker.session_store
            state = (
                await store.aget("cumulative")
                if hasattr(store, "aget")
                else store.get("cumulative")
            )
            return set((state or {}).get("sources_visited", []))
        finally:
            await broker.aclose()

    assert asyncio.run(_run()) == {"pii_ssn", "pii_dob", "pii_phone"}


def test_the_ledger_follows_the_caller_not_the_declared_session(session_config: str) -> None:
    """Cumulative exposure is isolated between callers, not between one caller's sessions.

    A caller picks its own ``session_id``, so a per-session ledger was a
    control the controlled party could reset: three PII reads, then a fresh
    session id, and escalation started over. Exposure now accumulates under an
    internal principal derived from the caller's identity, and a new session id
    inherits it. Isolation still holds where it means something -- between
    different callers.
    """
    from nautilus import Broker
    from nautilus.core.principal import derive_principal_id

    async def _run() -> tuple[set[str], set[str], set[str]]:
        broker = Broker.from_config(session_config)
        try:
            await broker.arequest("analyst", "ssn", {"purpose": "care", "session_id": "alpha"})
            await broker.arequest("analyst", "dob", {"purpose": "care", "session_id": "beta"})
            await broker.arequest("chief", "phone", {"purpose": "care", "session_id": "gamma"})
            store: Any = broker.session_store

            async def _visited(key: str) -> set[str]:
                state = await store.aget(key) if hasattr(store, "aget") else store.get(key)
                return set((state or {}).get("sources_visited", []))

            # ``alpha`` is a session row -- what that one session did. The other
            # two reads are principal ledgers: the accumulation a caller cannot
            # reset by declaring a new session id.
            return (
                await _visited("alpha"),
                await _visited(derive_principal_id("analyst")),
                await _visited(derive_principal_id("chief")),
            )
        finally:
            await broker.aclose()

    alpha, analyst, chief = asyncio.run(_run())
    assert alpha == {"pii_ssn"}
    assert analyst == {"pii_ssn", "pii_dob"}, "a fresh session id reset the same caller's ledger"
    assert chief == {"pii_phone"}, "a different caller inherited someone else's exposure"


# ---------------------------------------------------------------------------
# Cross-agent handoff
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source_agent", "receiving_agent", "classifications", "expected"),
    [
        # "Agent A is passing secret data to Agent B who has unclassified
        # clearance -- deny." (README)
        ("chief", "intern", ["secret"], "deny"),
        ("chief", "analyst", ["secret"], "deny"),
        # Receiving clearance dominates: allowed.
        ("analyst", "chief", ["confidential"], "allow"),
        ("intern", "analyst", ["unclassified"], "allow"),
    ],
)
def test_a_handoff_is_decided_by_the_receiving_clearance(
    session_config: str,
    source_agent: str,
    receiving_agent: str,
    classifications: list[str],
    expected: str,
) -> None:
    """The handoff decision must follow the classification ladder in both directions."""
    from nautilus import Broker

    async def _run() -> Any:
        broker = Broker.from_config(session_config)
        try:
            return await broker.declare_handoff(
                source_agent_id=source_agent,
                receiving_agent_id=receiving_agent,
                session_id="handoff",
                data_classifications=classifications,
            )
        finally:
            await broker.aclose()

    decision = asyncio.run(_run())
    assert decision.action == expected, (
        f"{source_agent} ({AGENTS[source_agent]['clearance']}) -> "
        f"{receiving_agent} ({AGENTS[receiving_agent]['clearance']}) carrying "
        f"{classifications} was {decision.action!r}, expected {expected!r}. "
        f"denials={decision.denial_records}"
    )


def test_a_denied_handoff_records_why(session_config: str) -> None:
    """A denial the caller cannot explain is not an auditable decision."""
    from nautilus import Broker

    async def _run() -> Any:
        broker = Broker.from_config(session_config)
        try:
            return await broker.declare_handoff(
                source_agent_id="chief",
                receiving_agent_id="intern",
                session_id="handoff-why",
                data_classifications=["secret"],
            )
        finally:
            await broker.aclose()

    decision = asyncio.run(_run())
    assert decision.action == "deny"
    assert decision.denial_records, (
        "the handoff was denied with no denial record explaining which rule denied it or why"
    )
    assert decision.handoff_id, "the decision carries no id to audit against"
