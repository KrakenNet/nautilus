"""The agent registry — not the caller — decides clearance and compartments.

Both halves of this file are regressions for privilege escalation:

- ``clearance`` used to be read straight from the caller-supplied ``context``
  dict, so any client could route to a ``secret`` source by declaring
  ``{"clearance": "top-secret"}``. An ``agent_id`` absent from a configured
  registry escalated the same way, since nothing checked it.
- ``compartments`` were never asserted at all. Both the ``agent`` and
  ``source`` facts fell back to the template default ``""``, so the
  ``fathom-dominates`` compartment check compared "" against "" and passed
  for every pair. Compartment isolation was configured but inert.

These are thick unit tests: a real engine over the built-in rules tree.
"""

from __future__ import annotations

import pytest

from nautilus.config.agent_registry import AgentRegistry
from nautilus.config.models import AgentRecord, SourceConfig
from nautilus.core.fathom_router import FathomRouter
from nautilus.core.models import IntentAnalysis, RouteResult
from nautilus.rules import BUILT_IN_RULES_DIR


def _router() -> FathomRouter:
    return FathomRouter(built_in_rules_dir=BUILT_IN_RULES_DIR, user_rules_dirs=[], attestation=None)


def _source(
    sid: str = "vuln-db", classification: str = "secret", compartments: str = ""
) -> SourceConfig:
    return SourceConfig(
        id=sid,
        type="postgres",
        description="d",
        classification=classification,
        data_types=["vulnerability"],
        allowed_purposes=["audit"],
        connection="postgres://localhost/vuln",
        compartments=compartments,
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="find vulnerabilities",
        data_types_needed=["vulnerability"],
        entities=[],
        confidence=0.9,
    )


def _route(
    router: FathomRouter,
    *,
    agent_id: str = "intern",
    context: dict | None = None,
    sources: list[SourceConfig] | None = None,
    registry: AgentRegistry | None = None,
) -> RouteResult:
    return router.route(
        agent_id=agent_id,
        context=context if context is not None else {"clearance": "secret", "purpose": "audit"},
        intent=_intent(),
        sources=sources if sources is not None else [_source()],
        session={},
        agent_registry=registry,
    )


def _registry(**records: dict) -> AgentRegistry:
    return AgentRegistry({k: AgentRecord(id=k, **v) for k, v in records.items()})


def _routed(result: RouteResult) -> set[str]:
    return {rd.source_id for rd in result.routing_decisions}


class TestClearanceComesFromRegistry:
    """A caller cannot name its own clearance when it is registered."""

    def test_context_clearance_cannot_elevate_a_registered_agent(self) -> None:
        registry = _registry(intern={"clearance": "unclassified"})
        result = _route(
            _router(),
            context={"clearance": "top-secret", "purpose": "audit"},
            registry=registry,
        )
        assert _routed(result) == set()
        assert [d.rule_name for d in result.denial_records] == ["default-classification-deny"]

    def test_registered_clearance_still_grants_access_it_should(self) -> None:
        registry = _registry(analyst={"clearance": "secret"})
        result = _route(
            _router(),
            agent_id="analyst",
            context={"clearance": "unclassified", "purpose": "audit"},
            registry=registry,
        )
        assert _routed(result) == {"vuln-db"}

    def test_the_asserted_agent_fact_carries_the_registry_clearance(self) -> None:
        registry = _registry(intern={"clearance": "unclassified"})
        result = _route(
            _router(),
            context={"clearance": "top-secret", "purpose": "audit"},
            registry=registry,
        )
        agent_facts = [f for f in result.input_facts if f.template == "agent"]
        assert [f.slots["clearance"] for f in agent_facts] == ["unclassified"]

    def test_empty_registry_falls_back_to_context(self) -> None:
        """Phase-1 compatibility: with no ``agents:`` declared there is no
        other source of truth, so context still supplies clearance."""
        result = _route(_router(), registry=AgentRegistry({}))
        assert _routed(result) == {"vuln-db"}

    def test_no_registry_argument_falls_back_to_context(self) -> None:
        result = _route(_router(), registry=None)
        assert _routed(result) == {"vuln-db"}


class TestUnknownAgentIsDenied:
    """An id a configured registry does not know is not a routing input."""

    def test_unregistered_agent_is_denied_every_source(self) -> None:
        registry = _registry(intern={"clearance": "unclassified"})
        sources = [_source("vuln-db"), _source("public-db", classification="public")]
        result = _route(
            _router(),
            agent_id="ghost-agent",
            context={"clearance": "top-secret", "purpose": "audit"},
            sources=sources,
            registry=registry,
        )
        assert _routed(result) == set()
        assert {d.source_id for d in result.denial_records} == {"vuln-db", "public-db"}
        assert {d.rule_name for d in result.denial_records} == {"unknown-agent"}

    def test_unknown_agent_asserts_no_facts(self) -> None:
        """The short-circuit runs before working memory is populated, so an
        unknown caller's attributes never reach the engine at all."""
        registry = _registry(intern={"clearance": "unclassified"})
        result = _route(_router(), agent_id="ghost-agent", registry=registry)
        assert result.input_facts == []


class TestCompartmentIsolation:
    """``compartments`` reach working memory on both the agent and the source."""

    def test_agent_without_the_compartment_is_denied(self) -> None:
        registry = _registry(analyst={"clearance": "secret", "compartments": ["alpha"]})
        result = _route(
            _router(),
            agent_id="analyst",
            sources=[_source(compartments="bravo")],
            registry=registry,
        )
        assert _routed(result) == set()
        assert [d.rule_name for d in result.denial_records] == ["default-classification-deny"]

    def test_agent_holding_the_compartment_is_routed(self) -> None:
        registry = _registry(analyst={"clearance": "secret", "compartments": ["alpha", "bravo"]})
        result = _route(
            _router(),
            agent_id="analyst",
            sources=[_source(compartments="bravo")],
            registry=registry,
        )
        assert _routed(result) == {"vuln-db"}

    def test_uncompartmented_source_is_reachable_without_compartments(self) -> None:
        registry = _registry(analyst={"clearance": "secret"})
        result = _route(_router(), agent_id="analyst", registry=registry)
        assert _routed(result) == {"vuln-db"}

    @pytest.mark.parametrize(
        "template,slot,expected",
        [("agent", "compartments", "alpha|bravo"), ("source", "compartments", "bravo")],
    )
    def test_compartments_are_actually_asserted(
        self, template: str, slot: str, expected: str
    ) -> None:
        registry = _registry(analyst={"clearance": "secret", "compartments": ["alpha", "bravo"]})
        result = _route(
            _router(),
            agent_id="analyst",
            sources=[_source(compartments="bravo")],
            registry=registry,
        )
        facts = [f for f in result.input_facts if f.template == template]
        assert [f.slots[slot] for f in facts] == [expected]
