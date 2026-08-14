"""Sandbox audit-log replay harness (#35.7).

Loads a proposed rule into a CLIPS environment alongside the production rules,
replays recorded requests from the audit log through **both** a baseline engine
and a candidate engine, and attributes every difference to the proposed rule.

This replaced a heuristic that never ran the engine. That version inspected the
proposal dict for ``lhs``/``rhs`` keys — a schema the rule compiler does not
accept, so product rules (which use ``when:``/``then:``) always took the
"empty LHS fires unconditionally" branch and were scored as firing on every
request. It read ``entry["allowed"]``, a key nothing has ever written, so every
request looked previously-allowed. Measured against a live engine over 6912
trials it was wrong on 46.6% of them, against 13.5% for a constant that always
answered "no change" — 3.4x worse than answering nothing at all.

Replay requires ``AuditEntry.input_facts``. Entries written before that field
existed carry no engine input and cannot be replayed; they are counted in
``skipped_no_input_facts`` rather than silently scored.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.core.fathom_router import FathomRouter
from nautilus.core.models import AuditEntry, InputFact, RouteResult
from nautilus.rules import BUILT_IN_RULES_DIR


class SandboxRegressionError(Exception):
    """Raised when the proposed rule denies a previously-allowed request. AC-35.7.c."""

    def __init__(self, message: str, result: SandboxResult | None = None) -> None:
        super().__init__(message)
        # The full replay result is attached so a caller can report the true
        # regression count. The previous version raised on the first regression
        # with a counter that had only just been incremented, so every report
        # said "1" regardless of how many there were.
        self.result = result


class SandboxRuleError(Exception):
    """Raised when the proposed rule cannot be compiled into an engine."""


@dataclass(frozen=True)
class SandboxResult:
    """Sandbox replay outcome. AC-35.7.b + AC-35.7.f.

    ``insufficient_history`` is True when ``replayed_n_actual <
    rkm.sandbox.min_entries`` (default 100). ``top_triggers`` is up to 5
    (AC-35.9.c shows them).

    ``replayed_n_actual`` counts entries actually replayed, i.e. excluding
    those dropped into ``skipped_no_input_facts`` or ``skipped_drifted``.
    """

    replayed_n: int
    replayed_n_actual: int
    fired: int
    regressions: int
    relaxations: int
    cascade_max: int
    wm_growth_pct: float
    insufficient_history: bool
    top_triggers: tuple[dict[str, Any], ...]
    # Entries present in the log but not scorable, reported rather than hidden:
    # a run that skipped most of its corpus must not read as a clean run.
    skipped_no_input_facts: int = 0
    skipped_drifted: int = 0


@dataclass
class _PerRequest:
    """Per-request replay metrics. AC-35.7.a."""

    allowed_before: frozenset[str]
    allowed_after: frozenset[str]
    fired_this_rule: bool
    cascade_depth: int
    wm_size_delta: int

    @property
    def regressed(self) -> bool:
        """A source the baseline allowed that the candidate no longer allows."""
        return bool(self.allowed_before - self.allowed_after)

    @property
    def relaxed(self) -> bool:
        """A source the baseline withheld that the candidate now allows."""
        return bool(self.allowed_after - self.allowed_before)


def _ruleset_yaml(proposed_rule: dict[str, Any]) -> str:
    """Wrap a single proposed rule in the ruleset envelope the compiler expects.

    The compiler wants ``module``/``ruleset``/``version``/``rules``. A proposal
    carries the rule body alone, so the envelope is synthesised here; envelope
    keys present on the proposal override the defaults.
    """
    envelope_keys = {"module", "ruleset", "version"}
    body = {k: v for k, v in proposed_rule.items() if k not in envelope_keys}
    name = str(proposed_rule.get("name") or "rkm-proposed-rule")
    return yaml.safe_dump(
        {
            "module": proposed_rule.get("module") or "nautilus-routing",
            "ruleset": proposed_rule.get("ruleset") or f"rkm-sandbox-{name}",
            "version": str(proposed_rule.get("version") or "1.0"),
            "rules": [body],
        },
        sort_keys=False,
    )


def _allowed(result: RouteResult) -> frozenset[str]:
    """Source ids the request is allowed to query.

    ``RouteResult.routing_decisions`` is already denial-filtered by the router,
    so this is the same set the broker would go on to query.
    """
    return frozenset(r.source_id for r in result.routing_decisions)


def _decision_fact_count(result: RouteResult) -> int:
    return (
        len(result.routing_decisions)
        + len(result.denial_records)
        + sum(len(g) for g in result.scope_constraints.values())
    )


def _replay_entry(
    baseline: FathomRouter,
    candidate: FathomRouter,
    input_facts: list[InputFact],
    rule_name: str,
) -> _PerRequest:
    """Replay one recorded request through both engines. AC-35.7.a.

    Both engines see byte-identical input — the same recorded facts — so any
    difference in outcome is attributable to the proposed rule and nothing else.
    """
    before = baseline.replay(input_facts)
    after = candidate.replay(input_facts)

    fired = any(t.split("::")[-1] == rule_name for t in after.rule_trace)
    # Cascade: rules that fired in the candidate but not the baseline. The
    # proposed rule itself is one of them; anything beyond it fired because the
    # proposal changed working memory.
    cascade = len(set(after.rule_trace) - set(before.rule_trace))

    return _PerRequest(
        allowed_before=_allowed(before),
        allowed_after=_allowed(after),
        fired_this_rule=fired,
        cascade_depth=cascade,
        wm_size_delta=_decision_fact_count(after) - _decision_fact_count(before),
    )


def _load_entries(audit_log_path: Path, replay_n: int) -> list[AuditEntry]:
    """Read up to ``replay_n`` Nautilus audit entries from a JSONL log (newest-last)."""
    if not audit_log_path.exists():
        return []
    lines = [ln for ln in audit_log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    entries: list[AuditEntry] = []
    for raw in lines[-replay_n:]:
        try:
            record: Any = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        metadata = cast("dict[str, Any]", record).get("metadata")
        if not isinstance(metadata, dict):
            continue
        payload = cast("dict[str, Any]", metadata).get(NAUTILUS_METADATA_KEY)
        if not isinstance(payload, str):
            continue
        try:
            entries.append(AuditEntry.model_validate(json.loads(payload)))
        except (json.JSONDecodeError, ValueError):
            continue
    return entries


def _build_routers(
    proposed_rule: dict[str, Any], built_in_rules_dir: Path
) -> tuple[FathomRouter, FathomRouter, str]:
    """Build the baseline and candidate engines. Returns ``(baseline, candidate, rule_name)``."""
    rule_name = str(proposed_rule.get("name") or "rkm-proposed-rule")
    baseline = FathomRouter(built_in_rules_dir=built_in_rules_dir, user_rules_dirs=[])
    candidate = FathomRouter(built_in_rules_dir=built_in_rules_dir, user_rules_dirs=[])
    try:
        candidate.reload_rule(rule_name, _ruleset_yaml(proposed_rule))
    except Exception as exc:
        raise SandboxRuleError(f"proposed rule {rule_name!r} does not compile: {exc}") from exc
    return baseline, candidate, rule_name


def sandbox_replay(
    proposed_rule: dict[str, Any],
    audit_log_path: Path,
    *,
    replay_n: int = 1000,
    min_entries: int = 100,
    built_in_rules_dir: Path | None = None,
) -> SandboxResult:
    """Replay a proposed rule against the audit log. AC-35.7.a–f.

    Reads up to ``replay_n`` entries from ``audit_log_path`` (JSONL,
    newest-last) and replays each through a baseline engine and an otherwise
    identical engine carrying the proposed rule.

    Raises :class:`SandboxRegressionError` when the proposal withdraws access
    the baseline granted (AC-35.7.c). The replay runs to completion first so
    the attached :class:`SandboxResult` carries the true regression count.

    Raises :class:`SandboxRuleError` when the proposal does not compile. A rule
    the engine rejects is not a rule with a clean sandbox record.
    """
    entries = _load_entries(audit_log_path, replay_n)
    baseline, candidate, rule_name = _build_routers(
        proposed_rule, built_in_rules_dir or BUILT_IN_RULES_DIR
    )

    fired_count = 0
    regression_count = 0
    relaxation_count = 0
    cascade_max = 0
    total_wm_delta = 0
    replayed = 0
    skipped_no_facts = 0
    skipped_drifted = 0
    top_triggers: list[dict[str, Any]] = []
    first_regression: str | None = None

    for entry in entries:
        if not entry.input_facts:
            skipped_no_facts += 1
            continue

        metrics = _replay_entry(baseline, candidate, entry.input_facts, rule_name)

        # The baseline must reproduce what the entry actually recorded. When it
        # does not, the production rules have changed since the entry was
        # written and any difference cannot be attributed to the proposal, so
        # the entry is reported as drifted rather than scored.
        recorded_allowed = frozenset(r.source_id for r in entry.routing_decisions)
        if metrics.allowed_before != recorded_allowed:
            skipped_drifted += 1
            continue

        replayed += 1
        if metrics.fired_this_rule:
            fired_count += 1
            cascade_max = max(cascade_max, metrics.cascade_depth)
            total_wm_delta += metrics.wm_size_delta
            if len(top_triggers) < 5:
                top_triggers.append(entry.model_dump(mode="json"))

        if metrics.regressed:
            regression_count += 1
            if first_regression is None:
                first_regression = (
                    f"request {entry.request_id!r} lost access to "
                    f"{sorted(metrics.allowed_before - metrics.allowed_after)!r}"
                )
        # Relaxation and regression are independent: a rule can withdraw one
        # source and grant another in the same request. The previous
        # implementation could only ever move a decision from allowed to
        # denied, so relaxations were structurally impossible to observe.
        if metrics.relaxed:
            relaxation_count += 1

    baseline_wm = replayed or 1
    result = SandboxResult(
        replayed_n=replay_n,
        replayed_n_actual=replayed,
        fired=fired_count,
        regressions=regression_count,
        relaxations=relaxation_count,
        cascade_max=cascade_max,
        wm_growth_pct=(total_wm_delta / baseline_wm) * 100.0,
        insufficient_history=replayed < min_entries,
        top_triggers=tuple(top_triggers),
        skipped_no_input_facts=skipped_no_facts,
        skipped_drifted=skipped_drifted,
    )

    if regression_count:
        raise SandboxRegressionError(
            f"Regression detected: rule {rule_name!r} denies access the current "
            f"rules grant, in {regression_count} of {replayed} replayed request(s). "
            f"First: {first_regression}",
            result=result,
        )
    return result


__all__ = [
    "SandboxRegressionError",
    "SandboxResult",
    "SandboxRuleError",
    "sandbox_replay",
]
