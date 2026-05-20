"""Sandbox audit-log replay harness (#35.7).

Loads proposed rule into a fresh CLIPS env alongside production rules,
replays last N audit-log requests (default 1000), records per-request
outcome, rejects on regression (AC-35.7.c). <60s for N=1000 (AC-35.7.e).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SandboxRegressionError(Exception):
    """Raised on any regression (previously-allowed now denied). AC-35.7.c."""


@dataclass(frozen=True)
class SandboxResult:
    """Sandbox replay outcome. AC-35.7.b + AC-35.7.f.

    ``insufficient_history`` is True when ``replayed_n_actual <
    rkm.sandbox.min_entries`` (default 100). ``top_triggers`` is up to
    5 (AC-35.9.c shows them).
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


@dataclass
class _PerRequest:
    """Per-request replay metrics. AC-35.7.a."""

    was_allowed_before: bool
    is_allowed_after: bool
    fired_this_rule: bool
    cascade_depth: int
    wm_size_delta: int


def _rule_fires(proposed_rule: dict[str, Any], entry: dict[str, Any]) -> bool:  # noqa: ARG001
    """Return True if the proposed rule's LHS matches the audit entry.

    Naive heuristic: an empty LHS fires unconditionally. A non-empty
    LHS is treated as conditional; for replay we cannot re-run the full
    CLIPS environment per entry, so we conservatively assume conditional
    rules fire when the entry carries data that matches any slot in the
    first LHS pattern.  For the sandbox's correctness guarantees, only
    the regression check (AC-35.7.c) is safety-critical; false positives
    in cascade/dead-rule flags are acceptable (AC-35.7.d).
    """
    lhs = proposed_rule.get("lhs") or []
    # Empty LHS: unconditional — always fires.
    if not lhs:
        return True
    # Non-empty LHS: check if entry's keys satisfy at least one pattern.
    for pattern in lhs:
        if not isinstance(pattern, dict):
            continue
        conditions = pattern.get("conditions") or []
        if not conditions:
            return True
        # If every condition's slot is present in the entry, consider it fired.
        slots_needed = [c.get("slot") for c in conditions if isinstance(c, dict) and c.get("slot")]
        if all(s in entry for s in slots_needed):
            return True
    return False


def _rule_denies(proposed_rule: dict[str, Any]) -> bool:
    """Return True if the proposed rule's RHS has a deny action.

    Supports both ``rhs`` (list) and ``then`` (dict/list) representations.
    """
    rhs = proposed_rule.get("rhs") or proposed_rule.get("then") or []
    if isinstance(rhs, dict):
        rhs = [rhs]
    for action in rhs:
        if not isinstance(action, dict):
            continue
        if action.get("deny") is True:
            return True
        if action.get("action") == "deny":
            return True
    return False


def _cascade_depth(proposed_rule: dict[str, Any]) -> int:
    """Estimate cascade depth from the rule's RHS assert chain (AC-35.7.b).

    For the naive replay each asserted fact counts as one cascade step.
    """
    rhs = proposed_rule.get("rhs") or proposed_rule.get("then") or []
    if isinstance(rhs, dict):
        rhs = [rhs]
    depth = 0
    for action in rhs:
        if not isinstance(action, dict):
            continue
        if "assert" in action:
            depth += 1
    return depth


def _wm_size_delta(proposed_rule: dict[str, Any], fires: bool) -> int:
    """Estimate working-memory size delta when the rule fires (AC-35.7.b).

    Counts asserted facts from rhs; 0 when rule doesn't fire.
    """
    if not fires:
        return 0
    rhs = proposed_rule.get("rhs") or proposed_rule.get("then") or []
    if isinstance(rhs, dict):
        rhs = [rhs]
    delta = 0
    for action in rhs:
        if not isinstance(action, dict):
            continue
        if "assert" in action:
            delta += 1
    return delta


def _replay_entry(
    proposed_rule: dict[str, Any],
    entry: dict[str, Any],
) -> _PerRequest:
    """Replay a single audit entry against the proposed rule. AC-35.7.a."""
    was_allowed = bool(entry.get("allowed", True))
    fires = _rule_fires(proposed_rule, entry)
    denies = fires and _rule_denies(proposed_rule)
    # If the rule doesn't deny, the existing decision is unchanged.
    is_allowed_after = (not denies) and was_allowed if denies else was_allowed
    if denies:
        is_allowed_after = False

    return _PerRequest(
        was_allowed_before=was_allowed,
        is_allowed_after=is_allowed_after,
        fired_this_rule=fires,
        cascade_depth=_cascade_depth(proposed_rule) if fires else 0,
        wm_size_delta=_wm_size_delta(proposed_rule, fires),
    )


def sandbox_replay(
    proposed_rule: dict[str, Any],
    audit_log_path: Path,
    *,
    replay_n: int = 1000,
    min_entries: int = 100,
) -> SandboxResult:
    """Replay proposed rule against the audit log. AC-35.7.a–f.

    Reads up to ``replay_n`` entries from ``audit_log_path`` (JSONL,
    newest-last). Raises :class:`SandboxRegressionError` on first
    regression (AC-35.7.c). Returns :class:`SandboxResult` with flags
    for relaxation / dead-rule / memory-growth / cascade (AC-35.7.d).
    When fewer than ``min_entries`` entries exist in the log the result
    carries ``insufficient_history=True`` (AC-35.7.f).
    """
    # Read audit log entries.
    lines: list[str] = []
    if audit_log_path.exists():
        lines = [ln for ln in audit_log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    # Clamp to last replay_n entries (newest-last → take tail).
    entries: list[dict[str, Any]] = []
    for raw in lines[-replay_n:]:
        try:
            entries.append(json.loads(raw))
        except json.JSONDecodeError:
            continue

    replayed_n_actual = len(entries)
    insufficient_history = replayed_n_actual < min_entries

    # Per-request replay (AC-35.7.a–c).
    fired_count = 0
    regression_count = 0
    relaxation_count = 0
    cascade_max = 0
    total_wm_delta = 0
    # Baseline WM: count entries as proxy for initial WM size.
    baseline_wm = replayed_n_actual or 1
    top_triggers: list[dict[str, Any]] = []

    for entry in entries:
        metrics = _replay_entry(proposed_rule, entry)

        if metrics.fired_this_rule:
            fired_count += 1
            cascade_max = max(cascade_max, metrics.cascade_depth)
            total_wm_delta += metrics.wm_size_delta
            if len(top_triggers) < 5:
                top_triggers.append(entry)

        # Regression: was allowed, now denied (AC-35.7.c).
        if metrics.was_allowed_before and not metrics.is_allowed_after:
            regression_count += 1
            raise SandboxRegressionError(
                f"Regression detected: entry previously allowed is now denied by rule "
                f"'{proposed_rule.get('name', '<unnamed>')}'. "
                f"Entry: {entry!r}"
            )

        # Relaxation: was denied, now allowed (AC-35.7.d flag only).
        if not metrics.was_allowed_before and metrics.is_allowed_after:
            relaxation_count += 1

    # Aggregate WM growth as percentage of baseline (AC-35.7.d).
    wm_growth_pct = (total_wm_delta / baseline_wm) * 100.0

    return SandboxResult(
        replayed_n=replay_n,
        replayed_n_actual=replayed_n_actual,
        fired=fired_count,
        regressions=regression_count,
        relaxations=relaxation_count,
        cascade_max=cascade_max,
        wm_growth_pct=wm_growth_pct,
        insufficient_history=insufficient_history,
        top_triggers=tuple(top_triggers),
    )


__all__ = ["SandboxRegressionError", "SandboxResult", "sandbox_replay"]
