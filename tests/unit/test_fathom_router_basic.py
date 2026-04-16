"""Basic unit test for :class:`FathomRouter` (Task 1.13).

This is a "thick unit" — it constructs a real :class:`fathom.Engine` against
the Nautilus built-in rules tree and exercises the actual policy engine.
We do NOT mock fathom; the routing rule (``match-sources-by-data-type``) is
the System-Under-Test together with the router's multislot encoding and
template readback.

Done-when (per tasks.md Task 1.13):
    a) ``SourceRegistry`` built with exactly 2 ``SourceConfig`` entries whose
       ``data_types`` overlap the fake ``IntentAnalysis.data_types_needed``.
    b) ``FathomRouter.route(...)`` returns a ``RouteResult`` whose
       ``routing_decisions`` has exactly 2 entries with ``source_id`` values
       set-equal to the 2 registered source ids.
    c) ``rule_trace`` is a non-empty list.
"""

from __future__ import annotations

import pytest

from nautilus.config.models import SourceConfig
from nautilus.config.registry import SourceRegistry
from nautilus.core.fathom_router import FathomRouter, RouteResult
from nautilus.core.models import IntentAnalysis
from nautilus.rules import BUILT_IN_RULES_DIR


@pytest.mark.unit
def test_route_emits_one_routing_decision_per_overlapping_source() -> None:
    # (a) Build a SourceRegistry with 2 SourceConfigs whose data_types
    # overlap the intent's data_types_needed.
    intent = IntentAnalysis(
        raw_intent="show me vulnerabilities and assets",
        data_types_needed=["vulnerability", "asset"],
        entities=[],
    )

    sources = [
        SourceConfig(
            id="vuln-db",
            type="postgres",
            description="vulnerability database",
            classification="secret",
            data_types=["vulnerability", "cve"],  # overlaps "vulnerability"
            allowed_purposes=["audit", "research"],
            connection="postgres://localhost/vuln",
        ),
        SourceConfig(
            id="asset-db",
            type="postgres",
            description="asset inventory",
            classification="secret",
            data_types=["asset", "host"],  # overlaps "asset"
            allowed_purposes=["audit", "research"],
            connection="postgres://localhost/asset",
        ),
    ]
    registry = SourceRegistry(sources)
    assert len(registry) == 2
    registered_ids = {s.id for s in registry}
    assert registered_ids == {"vuln-db", "asset-db"}

    # Both sources' data_types overlap the requested data_types_needed.
    needed = set(intent.data_types_needed)
    for s in registry:
        assert set(s.data_types) & needed, (
            f"test setup error: {s.id} data_types do not overlap intent"
        )

    # (b)+(c) Construct the router against the real Nautilus rules tree
    # and exercise route().
    router = FathomRouter(
        built_in_rules_dir=BUILT_IN_RULES_DIR,
        user_rules_dirs=[],
        attestation=None,
    )
    try:
        result = router.route(
            agent_id="agent-1",
            context={"clearance": "secret", "purpose": "audit"},
            intent=intent,
            sources=list(registry),
            session={"id": "sess-1", "pii_sources_accessed": 0},
        )

        assert isinstance(result, RouteResult)
        assert len(result.routing_decisions) == 2, (
            f"expected 2 routing_decisions, got {result.routing_decisions!r}"
        )
        assert {rd.source_id for rd in result.routing_decisions} == registered_ids

        # (c) rule_trace is a non-empty list.
        assert isinstance(result.rule_trace, list)
        assert len(result.rule_trace) > 0, (
            f"expected non-empty rule_trace, got {result.rule_trace!r}"
        )

        # No denial fired (purpose 'audit' is in allowed_purposes for both).
        assert result.denial_records == []
    finally:
        router.close()
