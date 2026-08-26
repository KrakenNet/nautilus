"""Shadow / subsumption check (#35.6).

Conservative: false-positives OK, false-negatives on the fixture suite
(>=20 hand-curated pairs under ``tests/fixtures/rkm/shadow-pairs/``) fail
the build. AC-35.6.a-c.

Heuristic algorithm (parse-time, no CLIPS engine needed):
- **subsumed_by**: existing rule E subsumes proposed P if E.lhs matches a
  superset of facts (E is more general: fewer slot constraints). If
  salience(E) >= salience(P), E fires on everything P would fire on.
- **shadows**: same LHS (equal conditions), salience(E) > salience(P) =>
  P never fires (E always fires first).
- **salience_inverts**: E is strictly more general than P but
  salience(P) > salience(E) => the narrower rule fires first, preventing
  the broader rule from ever asserting its (possibly more important) RHS.

Key data model (YAML rule dict)::

    name: str
    salience: int        (optional, default 0)
    lhs: list of dicts
      - template: str
        slots: dict[str, str]   (empty = any value for that slot)
    rhs: list of dicts   (not used in heuristic)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, cast


@dataclass(frozen=True)
class ShadowFlag:
    """One subsumption / shadow / salience-inversion relation. AC-35.6.a."""

    existing_rule: str
    relation: Literal["shadows", "subsumed_by", "salience_inverts"]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _salience(rule: dict[str, Any]) -> int:
    """Return rule salience (default 0)."""
    return int(rule.get("salience", 0))


def _lhs_conditions(rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a normalised LHS condition list.

    Product rules are written with ``when:`` — a list of
    ``{template, conditions: [{slot, bind} | {test}]}``. This module was written
    against an ``lhs:`` schema with ``{template, slots: {...}}``, which the rule
    compiler does not accept, so every real rule normalised to an empty LHS and
    no rule could ever be flagged.

    ``when:`` patterns normalise to ``{slot: value-constraint}`` plus any
    ``test`` expressions verbatim. The value constraint is the ``expression:``
    verbatim, or ``""`` for a bare ``bind:`` -- binding a slot to a variable
    constrains which slots the rule cares about, not which values it accepts,
    and two rules binding ``?sid`` and ``?id`` to the same slot constrain
    identically.

    Dropping the expression made every rule constraining a slot look like every
    other rule constraining that slot, so a dispatch table over disjoint values
    of one slot reported each rule as shadowing its siblings.
    """
    lhs: list[dict[str, Any]] = rule.get("lhs") or []
    if lhs:
        return lhs

    normalised: list[dict[str, Any]] = []
    patterns: list[Any] = rule.get("when") or []
    for raw_pattern in patterns:
        if not isinstance(raw_pattern, dict):
            continue
        pattern = cast("dict[str, Any]", raw_pattern)
        slots: dict[str, Any] = {}
        conditions: list[Any] = pattern.get("conditions") or []
        for raw_cond in conditions:
            if not isinstance(raw_cond, dict):
                continue
            cond = cast("dict[str, Any]", raw_cond)
            if cond.get("slot") is not None:
                slots[str(cond["slot"])] = str(cond.get("expression") or "")
            elif cond.get("test") is not None:
                slots[f"test:{cond['test']}"] = ""
        normalised.append({"template": str(pattern.get("template", "")), "slots": slots})
    return normalised


def _condition_key(cond: dict[str, Any]) -> tuple[str, frozenset[tuple[str, str]]]:
    """Canonical hashable key for a LHS condition."""
    template = str(cond.get("template", ""))
    raw_slots: dict[str, Any] = cond.get("slots") or {}
    slots: frozenset[tuple[str, str]] = frozenset((str(k), str(v)) for k, v in raw_slots.items())
    return (template, slots)


def _condition_is_more_general(general_cond: dict[str, Any], specific_cond: dict[str, Any]) -> bool:
    """True if ``general_cond`` matches a superset of facts vs ``specific_cond``.

    Same template, general constrains a subset of the slots, and wherever it
    constrains a *value* that constraint is identical. A general condition that
    only binds a slot the specific one pins to a value is broader; two
    conditions pinning the same slot to different values are disjoint, and
    neither is more general than the other.
    """
    if general_cond.get("template") != specific_cond.get("template"):
        return False
    gen_raw: dict[str, Any] = general_cond.get("slots") or {}
    spec_raw: dict[str, Any] = specific_cond.get("slots") or {}
    for slot, constraint in gen_raw.items():
        if slot not in spec_raw:
            return False
        if constraint and constraint != spec_raw[slot]:
            return False
    return True


def _lhs_subsumes(general_lhs: list[dict[str, Any]], specific_lhs: list[dict[str, Any]]) -> bool:
    """True if every condition in ``general_lhs`` is covered by ``specific_lhs``.

    Conservative: requires an injective matching from general conditions to
    specific conditions where each general condition is at least as broad as
    the paired specific condition.

    An empty general_lhs subsumes everything (matches any fact set).
    """
    if not general_lhs:
        return True
    used: set[int] = set()
    for gen_cond in general_lhs:
        matched = False
        for i, spec_cond in enumerate(specific_lhs):
            if i in used:
                continue
            if _condition_is_more_general(gen_cond, spec_cond):
                used.add(i)
                matched = True
                break
        if not matched:
            return False
    return True


def _lhs_equal(lhs_a: list[dict[str, Any]], lhs_b: list[dict[str, Any]]) -> bool:
    """True if both LHS condition sets are semantically equal."""
    if len(lhs_a) != len(lhs_b):
        return False
    keys_a = sorted(_condition_key(c) for c in lhs_a)
    keys_b = sorted(_condition_key(c) for c in lhs_b)
    return keys_a == keys_b


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def shadow_check(proposed: dict[str, Any], ruleset: list[dict[str, Any]]) -> tuple[ShadowFlag, ...]:
    """Return shadow / subsumption flags for ``proposed`` against ``ruleset``.

    AC-35.6.a-c. Conservative heuristic -- false positives acceptable;
    false negatives on the fixture suite fail the build.

    For each existing rule E, checks in priority order:

    1. Shadowing: E.lhs == proposed.lhs and salience(E) > salience(proposed)
       => E shadows proposed (proposed never fires).
    2. E strictly subsumes proposed (E more general) and
       salience(E) >= salience(proposed) => proposed is subsumed_by E.
    3. E strictly subsumes proposed and salience(proposed) > salience(E)
       => salience_inverts (narrower fires before broader).
    4. proposed strictly subsumes E (proposed more general) and
       salience(proposed) >= salience(E) => proposed dominates E,
       flagged as subsumed_by (proposed is the shadow of E).
    """
    flags: list[ShadowFlag] = []
    prop_lhs = _lhs_conditions(proposed)
    prop_sal = _salience(proposed)

    for existing in ruleset:
        ex_name = str(existing.get("name", ""))
        ex_lhs = _lhs_conditions(existing)
        ex_sal = _salience(existing)

        # 1. Shadowing: equal LHS, existing has strictly higher salience
        if _lhs_equal(prop_lhs, ex_lhs) and ex_sal > prop_sal:
            flags.append(ShadowFlag(existing_rule=ex_name, relation="shadows"))
            continue

        ex_subsumes_prop = _lhs_subsumes(ex_lhs, prop_lhs)
        prop_subsumes_ex = _lhs_subsumes(prop_lhs, ex_lhs)

        if ex_subsumes_prop and not prop_subsumes_ex:
            # existing is strictly more general than proposed
            if ex_sal >= prop_sal:
                # 2. existing fires on everything proposed fires on, at >= salience
                flags.append(ShadowFlag(existing_rule=ex_name, relation="subsumed_by"))
            else:
                # 3. existing is broader but lower salience -> inversion
                flags.append(ShadowFlag(existing_rule=ex_name, relation="salience_inverts"))
        elif prop_subsumes_ex and not ex_subsumes_prop and prop_sal >= ex_sal:
            # proposed is strictly more general and higher/equal salience
            # 4. proposed dominates existing (proposed shadows existing)
            flags.append(ShadowFlag(existing_rule=ex_name, relation="subsumed_by"))

    return tuple(flags)


__all__ = ["ShadowFlag", "shadow_check"]
