"""Unit tests for :class:`FathomRouter` (Task 3.5).

These are "thick unit" tests — they construct a real :class:`fathom.Engine`
against the Nautilus built-in rules tree and exercise the actual policy
engine rather than deeply mocking it. Case (b) uses ``monkeypatch`` to spy
on ``Engine.assert_fact`` while still letting the real engine run, which
lets us assert the fact-assertion order without sacrificing realism.

Covers:

- (a) Templates registered on engine construction (AC-3.1).
- (b) Facts asserted in the correct order: agent → intent → source(s)
  → session (AC-3.2).
- (c) 3-source scenario: exactly 3 ``routing_decision`` facts round-trip
  back as ``RoutingDecision`` entries (AC-3.3, FR-6).
- (d) ``rule_trace`` non-empty passthrough from ``EvaluationResult``
  into ``RouteResult`` (AC-3.4, FR-7).
- (e) Denial removes the denied source from ``routing_decisions`` while
  recording the :class:`DenialRecord` (AC-3.5).
- (f) Determinism — identical input produces an identical ``rule_trace``
  across repeated ``route()`` calls on the same engine (NFR-14).
"""

from __future__ import annotations

from typing import Any

import pytest

from nautilus.config.models import SourceConfig
from nautilus.core.fathom_router import FathomRouter
from nautilus.core.models import IntentAnalysis, RouteResult
from nautilus.rules import BUILT_IN_RULES_DIR

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_router() -> FathomRouter:
    return FathomRouter(
        built_in_rules_dir=BUILT_IN_RULES_DIR,
        user_rules_dirs=[],
        attestation=None,
    )


def _three_sources() -> list[SourceConfig]:
    return [
        SourceConfig(
            id="vuln-db",
            type="postgres",
            description="vulnerability database",
            classification="secret",
            data_types=["vulnerability", "cve"],
            allowed_purposes=["audit", "research"],
            connection="postgres://localhost/vuln",
        ),
        SourceConfig(
            id="asset-db",
            type="postgres",
            description="asset inventory",
            classification="secret",
            data_types=["asset", "host"],
            allowed_purposes=["audit", "research"],
            connection="postgres://localhost/asset",
        ),
        SourceConfig(
            id="log-db",
            type="postgres",
            description="event logs",
            classification="secret",
            data_types=["log", "event"],
            allowed_purposes=["audit", "research"],
            connection="postgres://localhost/logs",
        ),
    ]


def _intent_all_three() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="show vulns, assets, and logs",
        data_types_needed=["vulnerability", "asset", "log"],
        entities=[],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_templates_registered_on_construction() -> None:
    """(a) AC-3.1 — templates appear in ``engine.template_registry`` after construction."""
    router = _make_router()
    try:
        registry = router.engine.template_registry
        expected = {
            "agent",
            "intent",
            "source",
            "session",
            "routing_decision",
            "scope_constraint",
            "denial_record",
        }
        assert expected.issubset(set(registry.keys())), (
            f"missing templates: expected superset of {expected}, got {set(registry.keys())!r}"
        )
    finally:
        router.close()


@pytest.mark.unit
def test_facts_asserted_in_correct_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """(b) AC-3.2 — ``assert_fact`` invoked in order: agent, intent, source(s), session."""
    router = _make_router()
    try:
        calls: list[tuple[str, dict[str, Any]]] = []
        real_assert_fact = router.engine.assert_fact

        def spy(template: str, data: dict[str, Any]) -> None:
            calls.append((template, dict(data)))
            real_assert_fact(template, data)

        monkeypatch.setattr(router.engine, "assert_fact", spy)

        sources = _three_sources()
        router.route(
            agent_id="agent-1",
            context={"clearance": "secret", "purpose": "audit"},
            intent=_intent_all_three(),
            sources=sources,
            session={"id": "sess-1", "pii_sources_accessed": 0},
        )

        templates_in_order = [t for (t, _) in calls]
        # Expected: agent, intent, source×3, session, then escalation_rule
        # entries for each default pack rule (design §3.4 — one per request).
        assert templates_in_order[:6] == [
            "agent",
            "intent",
            "source",
            "source",
            "source",
            "session",
        ], f"unexpected fact order: {templates_in_order!r}"
        # Any remaining calls after the core six must be escalation_rule facts
        # (the default pack ships with the pii-aggregation rule, Task 1.9).
        assert all(t == "escalation_rule" for t in templates_in_order[6:]), (
            f"unexpected trailing facts: {templates_in_order[6:]!r}"
        )

        # And the source facts carry the registered source ids, preserving input order.
        source_ids = [data["id"] for (tpl, data) in calls if tpl == "source"]
        assert source_ids == [s.id for s in sources]
    finally:
        router.close()


@pytest.mark.unit
def test_three_source_scenario_round_trips_three_routing_decisions() -> None:
    """(c) AC-3.3 / FR-6 — 3 matching sources yield 3 ``routing_decision`` facts."""
    router = _make_router()
    try:
        sources = _three_sources()
        result = router.route(
            agent_id="agent-1",
            context={"clearance": "secret", "purpose": "audit"},
            intent=_intent_all_three(),
            sources=sources,
            session={"id": "sess-1", "pii_sources_accessed": 0},
        )

        assert isinstance(result, RouteResult)
        assert len(result.routing_decisions) == 3, (
            f"expected 3 routing_decisions, got {result.routing_decisions!r}"
        )
        assert {rd.source_id for rd in result.routing_decisions} == {s.id for s in sources}
        # No denials in this scenario.
        assert result.denial_records == []
    finally:
        router.close()


@pytest.mark.unit
def test_rule_trace_non_empty_passthrough() -> None:
    """(d) AC-3.4 / FR-7 — ``rule_trace`` is a non-empty list of strings."""
    router = _make_router()
    try:
        result = router.route(
            agent_id="agent-1",
            context={"clearance": "secret", "purpose": "audit"},
            intent=_intent_all_three(),
            sources=_three_sources(),
            session={"id": "sess-1", "pii_sources_accessed": 0},
        )

        assert isinstance(result.rule_trace, list)
        assert len(result.rule_trace) > 0, (
            f"expected non-empty rule_trace, got {result.rule_trace!r}"
        )
        assert all(isinstance(entry, str) for entry in result.rule_trace), (
            f"rule_trace entries must be str, got {result.rule_trace!r}"
        )
    finally:
        router.close()


@pytest.mark.unit
def test_denial_removes_source_from_route_set() -> None:
    """(e) AC-3.5 — a denied source is excluded from ``routing_decisions``
    while surfacing in ``denial_records``.

    ``deny-purpose-mismatch`` (denial.yaml) fires when the agent purpose is
    not in the source's ``allowed_purposes`` — we craft one source that
    allows only ``"audit"`` and request with purpose ``"research"``.
    """
    router = _make_router()
    try:
        sources = [
            SourceConfig(
                id="allowed-db",
                type="postgres",
                description="allows research",
                classification="secret",
                data_types=["vulnerability"],
                allowed_purposes=["audit", "research"],
                connection="postgres://localhost/allowed",
            ),
            SourceConfig(
                id="denied-db",
                type="postgres",
                description="audit only — denies research",
                classification="secret",
                data_types=["vulnerability"],
                allowed_purposes=["audit"],  # ← 'research' not allowed
                connection="postgres://localhost/denied",
            ),
        ]
        intent = IntentAnalysis(
            raw_intent="research vulns",
            data_types_needed=["vulnerability"],
            entities=[],
        )

        result = router.route(
            agent_id="agent-1",
            context={"clearance": "secret", "purpose": "research"},
            intent=intent,
            sources=sources,
            session={"id": "sess-1", "pii_sources_accessed": 0},
        )

        routed_ids = {rd.source_id for rd in result.routing_decisions}
        denied_ids = {d.source_id for d in result.denial_records}

        assert "denied-db" in denied_ids, f"expected 'denied-db' in denials, got {denied_ids!r}"
        assert "denied-db" not in routed_ids, (
            f"denied source must not appear in routing_decisions, got {routed_ids!r}"
        )
        assert "allowed-db" in routed_ids, (
            f"expected 'allowed-db' to remain routed, got {routed_ids!r}"
        )

        # The denial record carries the firing rule name (AC-3.5).
        denial = next(d for d in result.denial_records if d.source_id == "denied-db")
        assert denial.rule_name == "deny-purpose-mismatch"
    finally:
        router.close()


@pytest.mark.unit
def test_rule_trace_determinism_same_input_same_trace() -> None:
    """(f) NFR-14 — identical input produces identical ``rule_trace`` across calls.

    We reuse a single router/engine and call ``route()`` twice with exactly
    the same inputs. ``route()`` calls ``clear_facts()`` at the top of each
    pass, so the second call starts from a clean slate and must produce an
    identical ``rule_trace`` list (order-sensitive equality).
    """
    router = _make_router()
    try:
        sources = _three_sources()
        intent = _intent_all_three()
        kwargs: dict[str, Any] = {
            "agent_id": "agent-1",
            "context": {"clearance": "secret", "purpose": "audit"},
            "intent": intent,
            "sources": sources,
            "session": {"id": "sess-1", "pii_sources_accessed": 0},
        }

        first = router.route(**kwargs)
        second = router.route(**kwargs)

        assert first.rule_trace == second.rule_trace, (
            f"rule_trace drift: first={first.rule_trace!r} second={second.rule_trace!r}"
        )
        # And the derived routing decisions should also be stable.
        assert [rd.source_id for rd in first.routing_decisions] == [
            rd.source_id for rd in second.routing_decisions
        ]
    finally:
        router.close()
