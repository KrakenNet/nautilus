"""``AuditEntry.input_facts`` records enough to reproduce a routing decision.

Before this, the only record of engine input was ``facts_asserted_summary`` —
``template -> count``. That says how many facts a request produced and nothing
about what they were, so no consumer could re-derive a decision from an audit
entry. The RKM sandbox's replay validator depended on exactly that and could
not have worked.

The bar here is sufficiency, not shape: assert the recorded facts into a fresh
engine, evaluate, and require the decision to come back identical. Asserting
that the field is merely *populated* would pass on a record that omitted half
the slots.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest

from nautilus.config.models import SourceConfig
from nautilus.core.fathom_router import FathomRouter
from nautilus.core.models import InputFact, IntentAnalysis, RouteResult
from nautilus.rules import BUILT_IN_RULES_DIR

CLASSIFICATIONS = ["unclassified", "confidential", "secret", "top-secret"]
CLEARANCES = ["public", "confidential", "secret", "top-secret"]
PURPOSES = ["audit", "research", "treatment"]
DATA_TYPES = [["pii"], ["vulnerability"], ["pii", "phi"]]


def _router() -> FathomRouter:
    return FathomRouter(built_in_rules_dir=BUILT_IN_RULES_DIR, user_rules_dirs=[])


def _outcome(result: RouteResult) -> dict[str, Any]:
    """Decision-relevant projection, normalised for comparison."""
    return {
        "routing": sorted((r.source_id, r.reason) for r in result.routing_decisions),
        "denials": sorted((d.source_id, d.reason, d.rule_name) for d in result.denial_records),
        "scopes": sorted(
            (c.source_id, c.field, str(c.operator), str(c.value))
            for group in result.scope_constraints.values()
            for c in group
        ),
        "trace": sorted(result.rule_trace),
    }


def _route(
    router: FathomRouter, clearance: str, purpose: str, classification: str, data_types: list[str]
) -> RouteResult:
    return router.route(
        agent_id="agent-1",
        context={"clearance": clearance, "purpose": purpose},
        intent=IntentAnalysis(raw_intent="r", data_types_needed=data_types, entities=[]),
        sources=[
            SourceConfig(
                id="src",
                type="rest",
                description="d",
                classification=classification,
                data_types=data_types,
                allowed_purposes=["audit"],
                connection="memory://",
            )
        ],
        session={"session_id": "s1", "data_types_seen": data_types},
    )


CORPUS = list(itertools.product(CLASSIFICATIONS, CLEARANCES, PURPOSES, DATA_TYPES))


class TestInputFactsSufficiency:
    """Recorded facts alone reproduce the decision."""

    def test_every_asserted_fact_is_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Every ``assert_fact`` call reaches ``input_facts``.

        Compared against a spy on the engine rather than against
        ``facts_asserted_summary``: both of those are now derived from the same
        list, so checking one against the other would prove nothing. The spy is
        an independent record of what the engine was actually told.
        """
        from fathom import Engine

        seen: list[str] = []
        real = Engine.assert_fact

        def spy(self: Any, template: str, slots: dict[str, Any]) -> Any:
            seen.append(template)
            return real(self, template, slots)

        monkeypatch.setattr(Engine, "assert_fact", spy)
        result = _route(_router(), "secret", "audit", "confidential", ["pii", "phi"])

        expected: dict[str, int] = {}
        for template in seen:
            expected[template] = expected.get(template, 0) + 1
        recorded: dict[str, int] = {}
        for fact in result.input_facts:
            recorded[fact.template] = recorded.get(fact.template, 0) + 1

        assert recorded == expected, (
            f"input_facts {recorded} does not match what the engine was asserted {expected}"
        )
        assert result.facts_asserted_summary == expected, (
            "facts_asserted_summary must be derived from the facts actually "
            "asserted, not hand-maintained"
        )

    def test_summary_counts_escalation_rules(self) -> None:
        """The summary previously hardcoded five templates and omitted this one."""
        result = _route(_router(), "secret", "audit", "confidential", ["pii"])
        assert result.facts_asserted_summary.get("escalation_rule"), (
            "escalation_rule facts are asserted on every request but missing "
            f"from the summary: {result.facts_asserted_summary}"
        )

    @pytest.mark.parametrize(
        "classification,clearance,purpose,data_types",
        CORPUS,
        ids=[f"{c}-{cl}-{p}-{'+'.join(d)}" for c, cl, p, d in CORPUS],
    )
    def test_replay_reproduces_decision(
        self, classification: str, clearance: str, purpose: str, data_types: list[str]
    ) -> None:
        live = _route(_router(), clearance, purpose, classification, data_types)
        replayed = _router().replay(live.input_facts)
        assert _outcome(replayed) == _outcome(live)

    def test_replay_uses_only_the_record(self) -> None:
        """Dropping a recorded fact changes the outcome.

        A replay that ignored its argument, or that reached back into the
        original request, would still agree here — this is the control that
        rules both out.
        """
        live = _route(_router(), "public", "audit", "secret", ["pii"])
        assert live.denial_records, "fixture must produce a denial to be discriminating"

        without_agent = [f for f in live.input_facts if f.template != "agent"]
        replayed = _router().replay(without_agent)
        assert _outcome(replayed) != _outcome(live), (
            "replay reproduced the decision without the agent fact, so it is not "
            "reading from the record"
        )

    def test_slot_values_survive_the_round_trip(self) -> None:
        """Facts are recorded post-encoding, so a replay needs no re-encoding."""
        live = _route(_router(), "secret", "audit", "confidential", ["pii", "phi"])
        source = next(f for f in live.input_facts if f.template == "source")
        assert source.slots["data_types"] == "pii phi", (
            f"multislot not recorded in its encoded form: {source.slots['data_types']!r}"
        )


class TestAuditEntryCarriesInputFacts:
    """The field survives the on-disk round trip it exists for."""

    @staticmethod
    def _emit_and_read(tmp_path: Any, input_facts: list[InputFact] | None) -> Any:
        """Write one entry through the real logger and decode it back off disk."""
        import json

        from fathom.audit import AuditRecord, FileSink

        from nautilus.audit.logger import AuditLogger, decode_nautilus_entry

        path = tmp_path / "audit.jsonl"
        AuditLogger(FileSink(path)).emit(_minimal_entry(input_facts))
        line = path.read_text(encoding="utf-8").strip()
        return decode_nautilus_entry(AuditRecord.model_validate(json.loads(line)))

    def test_input_facts_survive_the_jsonl_round_trip(self, tmp_path: Any) -> None:
        live = _route(_router(), "secret", "audit", "confidential", ["pii"])
        decoded = self._emit_and_read(tmp_path, live.input_facts)
        assert decoded.input_facts == live.input_facts

    def test_decoded_facts_still_replay(self, tmp_path: Any) -> None:
        """The bar: a decision is reproducible from the audit line alone.

        Everything upstream can be correct and this still fail if the JSONL
        loses slot fidelity, so the replay is re-run against what came back
        off disk rather than against the in-memory record.
        """
        live = _route(_router(), "public", "audit", "secret", ["pii"])
        decoded = self._emit_and_read(tmp_path, live.input_facts)
        assert decoded.input_facts is not None
        replayed = _router().replay(decoded.input_facts)
        assert _outcome(replayed) == _outcome(live)

    def test_absent_input_facts_still_decode(self, tmp_path: Any) -> None:
        """NFR-5: entries with no input_facts round-trip unchanged."""
        assert self._emit_and_read(tmp_path, None).input_facts is None


def _minimal_entry(input_facts: list[InputFact] | None) -> Any:
    from nautilus.audit.logger import AuditLogger
    from nautilus.core.models import AuditEntry

    return AuditEntry(
        timestamp=AuditLogger.utcnow(),
        request_id="r1",
        agent_id="agent-1",
        facts_asserted_summary={},
        denial_records=[],
        error_records=[],
        rule_trace=[],
        sources_queried=[],
        sources_denied=[],
        sources_errored=[],
        duration_ms=1,
        input_facts=input_facts or None,
    )
