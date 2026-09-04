"""The escalation packs have a consumer (UPSTREAM.md:240).

``_assert_escalation_rules`` pushed one ``escalation_rule`` fact per loaded
pack entry on every ``route()`` call, and ``grep -rn "template: escalation_rule"
nautilus/rules/`` matched nothing outside the template declaration. The
declarative pack format, the built-in ``pii-aggregation-confidential`` entry
and the ``contains-all`` external registered for it were all inert: the facts
were asserted and no rule could ever match them.

``rules/escalation.yaml`` consumes them. Because the trigger is a *combination*
of PII data types, no single request can reach it — the rule is only reachable
through the cumulative session exposure the store accumulates across requests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from nautilus.config.escalation import load_escalation_packs
from nautilus.config.models import SourceConfig
from nautilus.core.fathom_router import FathomRouter
from nautilus.core.models import InputFact, IntentAnalysis, RouteResult
from nautilus.rules import BUILT_IN_RULES_DIR

pytestmark = pytest.mark.unit

RULE_NAME = "session-exposure-escalation-deny"
FULL_TRIGGER = ["email", "phone", "dob", "ssn"]


def _router(user_rules_dirs: list[Path] | None = None) -> FathomRouter:
    return FathomRouter(
        built_in_rules_dir=BUILT_IN_RULES_DIR, user_rules_dirs=user_rules_dirs or []
    )


def _source(classification: str = "unclassified") -> SourceConfig:
    return SourceConfig(
        id="s1",
        type="rest",
        description="d",
        classification=classification,
        data_types=["pii"],
        allowed_purposes=["analytics"],
        connection="https://example.invalid",
    )


def _route(router: FathomRouter, clearance: str, seen: list[str]) -> RouteResult:
    return router.route(
        agent_id="a1",
        context={"clearance": clearance, "purpose": "analytics"},
        intent=IntentAnalysis(raw_intent="r", data_types_needed=["pii"], entities=[]),
        sources=[_source()],
        session={"session_id": "s1", "data_types_seen": seen},
    )


def _denials(result: RouteResult) -> set[str]:
    return {d.rule_name for d in result.denial_records}


class TestTheBuiltInPackIsWhatDrivesIt:
    def test_the_pack_still_ships_the_trigger_this_test_uses(self) -> None:
        # If the pack changes, the scenarios below stop meaning anything.
        rules = load_escalation_packs([BUILT_IN_RULES_DIR / "escalation"])
        entry = next(r for r in rules if r.id == "pii-aggregation-confidential")
        assert entry.trigger_combination.split() == FULL_TRIGGER
        assert (entry.resulting_level, entry.action) == ("confidential", "escalate")


class TestEscalationDeniesOnlyWhenTheBarIsNotCleared:
    def test_the_full_trigger_denies_an_under_cleared_agent(self) -> None:
        result = _route(_router(), "cui", FULL_TRIGGER)
        assert _denials(result) == {RULE_NAME}
        assert result.routing_decisions == []
        assert any(t.endswith(f"::{RULE_NAME}") for t in result.rule_trace)

    @pytest.mark.parametrize("clearance", ["confidential", "secret", "top-secret"])
    def test_an_agent_who_clears_the_escalated_level_still_routes(self, clearance: str) -> None:
        # `escalate` raises the bar; it does not deny outright.
        result = _route(_router(), clearance, FULL_TRIGGER)
        assert _denials(result) == set()
        assert [r.source_id for r in result.routing_decisions] == ["s1"]

    @pytest.mark.parametrize("seen", [[], ["email"], ["email", "phone"], ["email", "phone", "dob"]])
    def test_a_partial_trigger_does_not_escalate(self, seen: list[str]) -> None:
        # `contains-all` is set containment: three of four is not the trigger.
        result = _route(_router(), "cui", seen)
        assert _denials(result) == set()
        assert [r.source_id for r in result.routing_decisions] == ["s1"]

    def test_extra_exposure_beyond_the_trigger_still_escalates(self) -> None:
        result = _route(_router(), "cui", [*FULL_TRIGGER, "address"])
        assert _denials(result) == {RULE_NAME}

    def test_a_session_with_no_exposure_is_unaffected(self) -> None:
        # NFR-5: a Phase-1 session dict carries none of the multislots.
        result = _router().route(
            agent_id="a1",
            context={"clearance": "cui", "purpose": "analytics"},
            intent=IntentAnalysis(raw_intent="r", data_types_needed=["pii"], entities=[]),
            sources=[_source()],
            session={},
        )
        assert _denials(result) == set()


class TestOnlyEscalateEntriesEscalate:
    """A pack author adding a `deny` or `notify` entry must not inherit this."""

    @staticmethod
    def _facts(action: str) -> list[InputFact]:
        return [
            InputFact(
                template="escalation_rule",
                slots={
                    "id": "probe",
                    "trigger_combination": " ".join(FULL_TRIGGER),
                    "resulting_level": "confidential",
                    "action": action,
                },
            ),
            InputFact(
                template="session",
                slots={"id": "s1", "data_types_seen": " ".join(FULL_TRIGGER)},
            ),
            InputFact(
                template="agent",
                slots={"id": "a1", "clearance": "cui", "purpose": "analytics"},
            ),
            InputFact(
                template="source",
                slots={
                    "id": "s1",
                    "type": "rest",
                    "classification": "unclassified",
                    "data_types": "pii",
                    "allowed_purposes": "analytics",
                },
            ),
        ]

    def test_an_escalate_entry_fires(self) -> None:
        assert _denials(_router().replay(self._facts("escalate"))) == {RULE_NAME}

    @pytest.mark.parametrize("action", ["deny", "notify"])
    def test_a_non_escalate_entry_does_not(self, action: str) -> None:
        assert _denials(_router().replay(self._facts(action))) == set()


class TestSessionExposureFactsAreMatchable:
    """The per-value view the operator guide promises rules can use.

    ``_assert_session`` emits one ``session_exposure`` fact per element so a
    rule can pattern-match an individual value, which the encoded multislot
    on the ``session`` fact cannot express. No built-in rule needs that view;
    this pins that the surface works, so the facts are an extension point
    rather than unmatched overhead.
    """

    _RULE = """module: nautilus-routing
ruleset: session-exposure-probe
version: "1.0"
rules:
  - name: session-exposure-probe-deny
    description: "Deny when a named source has already been visited this session."
    salience: 180
    when:
      - template: session_exposure
        conditions:
          - slot: category
            bind: ?category
          - slot: value
            bind: ?value
          - test: '(eq ?category "sources_visited")'
      - template: source
        conditions:
          - slot: id
            bind: ?sid
          - test: "(eq ?sid ?value)"
    then:
      action: deny
      reason: "already visited this session"
      assert:
        - template: denial_record
          slots:
            source_id: "?sid"
            reason: "already visited this session"
            rule_name: "session-exposure-probe-deny"
"""

    @pytest.fixture()
    def router(self, tmp_path: Path) -> FathomRouter:
        (tmp_path / "probe.yaml").write_text(self._RULE, encoding="utf-8")
        return _router([tmp_path])

    def _route_with(self, router: FathomRouter, session: dict[str, Any]) -> RouteResult:
        return router.route(
            agent_id="a1",
            context={"clearance": "secret", "purpose": "analytics"},
            intent=IntentAnalysis(raw_intent="r", data_types_needed=["pii"], entities=[]),
            sources=[_source()],
            session=session,
        )

    def test_a_rule_matches_one_exposure_value(self, router: FathomRouter) -> None:
        result = self._route_with(router, {"session_id": "s1", "sources_visited": ["s1"]})
        assert _denials(result) == {"session-exposure-probe-deny"}

    def test_it_does_not_match_a_different_value(self, router: FathomRouter) -> None:
        result = self._route_with(router, {"session_id": "s1", "sources_visited": ["other"]})
        assert _denials(result) == set()
