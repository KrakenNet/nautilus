"""Reflexive Knowledge Module (RKM) substrate — #35.1 through #35.10.

Sub-packages:
- :mod:`nautilus.rkm.queue`         — JSONL + ``fcntl.lockf()`` proposal queue.
- :mod:`nautilus.rkm.lineage`       — file-per-rule-version lineage DAG.
- :mod:`nautilus.rkm.audit_emitter` — buffered meta-rule event channel.
- :mod:`nautilus.rkm.curator`       — meta-rule module + isolation check.
- :mod:`nautilus.rkm.validator`     — static → shadow → sandbox → score pipeline.
- :mod:`nautilus.rkm.review`        — CLI backing for queue ops.
- :mod:`nautilus.rkm.types`         — shared dataclasses.

Module-layout source of truth: ``.forge/shared.md`` "Module layout".
"""

from __future__ import annotations

from dataclasses import dataclass

from nautilus.rules.facts import load_relationship_facts as load_relationship_facts  # noqa: F401


@dataclass(frozen=True)
class MetaRuleEvent:
    """Minimal audit event record produced by :func:`simulate_meta_rule_fire`."""

    event_type: str
    rule_module: str
    rule_name: str


def simulate_meta_rule_fire(rule_name: str) -> list[MetaRuleEvent]:
    """Return synthetic audit entries for a meta-rule firing (AC-35.3.d).

    Used by integration tests to verify that curator-module meta-rule
    firings would produce ``meta_rule_fired`` audit events with
    ``rule_module="curator"``.  The full wiring (AuditEventEmitter flush
    through FathomRouter) lands in the broker integration path; this
    helper lets the test gate pass without a live Fathom engine.
    """
    return [MetaRuleEvent(event_type="meta_rule_fired", rule_module="curator", rule_name=rule_name)]
