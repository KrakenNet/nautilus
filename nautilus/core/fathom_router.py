"""``FathomRouter`` — thin wrapper around ``fathom.Engine`` (design §3.4).

Owns:
- Engine construction with built-in templates/module/rules + ``overlaps`` /
  ``not-in-list`` / ``contains-all`` Python externals (registered BEFORE
  ``load_rules`` per the Task 1.12 SPIKE finding — CLIPS ``build`` errors
  with ``EXPRNPSR3`` if a rule LHS references an unknown function name).
- User-rule loading after defaults so user rules can override salience.
- Escalation-pack loading (design §3.4): YAML → :class:`EscalationRule`
  models cached on the router and re-asserted per request.
- Per-request fact assertion with multislot list-to-string encoding
  (design §5.4) and template readback for ``routing_decision`` /
  ``scope_constraint`` / ``denial_record``.
- Removal of denied sources from the routing set (design §5.4 last line).

``RouteResult`` was defined inline here for Phase 1; Task 2.1 promoted it to
``nautilus/core/models.py`` as a Pydantic model. It is re-exported from this
module for back-compat so existing ``from nautilus.core.fathom_router import
RouteResult`` imports keep working.
"""

from __future__ import annotations

import contextlib
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fathom import Engine

from nautilus.config.agent_registry import AgentRegistry
from nautilus.config.escalation import EscalationRule, load_escalation_packs
from nautilus.config.models import SourceConfig
from nautilus.core import ConsistencyError, PolicyEngineError
from nautilus.core.clips_encoding import encode_multislot
from nautilus.core.models import (
    DenialRecord,
    IntentAnalysis,
    RouteResult,
    RoutingDecision,
    ScopeConstraint,
)
from nautilus.rkm.curator.isolation import assert_module_isolation
from nautilus.rules import load_built_in_modules
from nautilus.rules.functions import (
    register_contains_all,
    register_not_in_list,
    register_overlaps,
)

if TYPE_CHECKING:
    pass


# The three session multislots re-asserted as one ``session_exposure`` fact per
# element (design §3.3, AC-2.3, FR-5). The tuple order is irrelevant to the
# engine but kept stable so snapshot tests are deterministic.
_SESSION_EXPOSURE_MULTISLOTS: tuple[str, ...] = (
    "data_types_seen",
    "sources_visited",
    "pii_sources_accessed_list",
)


def _coerce_multislot(raw: Any) -> list[str]:
    """Normalize stored-session multislot into a ``list[str]``.

    Accepts:
    - ``None`` / missing key → ``[]``.
    - ``list`` (the :class:`PostgresSessionStore` JSONB-array path) → stringified elements.
    - ``str`` (the in-memory or pre-encoded path) → split on whitespace; empty string → ``[]``.

    Any other type degrades to ``[]`` rather than raising — this helper runs
    on the request hot-path and a malformed session row should not take down
    the whole request (the audit trail surfaces zero exposure facts, which
    is the same as a fresh session).
    """
    if raw is None:
        return []
    if isinstance(raw, list):
        items: list[Any] = list(raw)  # type: ignore[arg-type]
        return [str(v) for v in items if str(v)]
    if isinstance(raw, str):
        return [tok for tok in raw.split() if tok]
    return []


class FathomRouter:
    """Wraps ``fathom.Engine`` with Nautilus templates, rules, and externals.

    Construction loads, in order: built-in templates → built-in modules →
    ``overlaps`` + ``not-in-list`` + ``contains-all`` externals → built-in
    functions → built-in rules → user rules (one ``load_rules`` call per
    directory). Order is load-bearing; see Task 1.12 SPIKE notes in
    ``tests/integration/test_fathom_smoke.py``.

    Escalation packs (design §3.4) are loaded once at construction from
    ``<built_in_rules_dir>/escalation`` and re-asserted as ``escalation_rule``
    facts on every ``route()`` call (facts are cleared per request).
    """

    def __init__(
        self,
        built_in_rules_dir: Path,
        user_rules_dirs: list[Path],
        attestation: Any | None = None,  # AttestationService | None — typed loosely; jwt optional
        check_consistency: bool = True,
    ) -> None:
        self._built_in_rules_dir = Path(built_in_rules_dir)
        self._user_rules_dirs = [Path(d) for d in user_rules_dirs]
        self._attestation = attestation
        # #27 — post-run consistency checks; on by default, disabled via
        # ``rules.consistency_checks: false`` for performance-sensitive
        # deployments.
        self._check_consistency_enabled = check_consistency
        try:
            self._engine: Engine = Engine()
            self._engine.load_templates(str(self._built_in_rules_dir / "templates"))
            load_built_in_modules(self._engine)
            register_overlaps(self._engine)
            register_not_in_list(self._engine)
            register_contains_all(self._engine)
            self._engine.load_functions(str(self._built_in_rules_dir / "functions"))
            self._engine.load_rules(str(self._built_in_rules_dir / "rules"))
            # Curator module — pattern-tracker meta-rules (AC-35.3.a).
            # assert_module_isolation runs parse-time YAML static analysis
            # before loading so routing-template violations are caught early.
            _meta_dir = self._built_in_rules_dir / "meta"
            _pattern_tracker = _meta_dir / "pattern-tracker.yaml"
            assert_module_isolation(_pattern_tracker)
            self._engine.load_rules(str(_meta_dir))
            for user_dir in self._user_rules_dirs:
                self._engine.load_rules(str(user_dir))
            # Escalation packs are YAML → EscalationRule models loaded once;
            # _assert_escalation_rules re-pushes them as facts per request
            # (engine.clear_facts() wipes facts each route() call).
            self._escalation_rules: list[EscalationRule] = load_escalation_packs(
                [self._built_in_rules_dir / "escalation"]
            )
        except Exception as exc:  # noqa: BLE001 — re-wrap as PolicyEngineError per design §3.4
            raise PolicyEngineError(f"Fathom engine construction failed: {exc}") from exc

    @property
    def engine(self) -> Engine:
        """Underlying ``fathom.Engine`` (read-only handle for diagnostics)."""
        return self._engine

    def route(
        self,
        agent_id: str,
        context: dict[str, Any],
        intent: IntentAnalysis,
        sources: list[SourceConfig],
        session: dict[str, Any],
        agent_registry: AgentRegistry | None = None,
    ) -> RouteResult:
        """Run one routing pass; return populated :class:`RouteResult`.

        Steps (design §5.4, §3.3):
        1. ``clear_facts()``
        2. assert ``agent``, ``intent``, each ``source``, ``session`` +
           ``session_exposure`` (one fact per multislot element — FR-5, AC-2.3),
           and ``escalation_rule`` packs.
        3. ``evaluate()``
        4. read ``routing_decision`` / ``scope_constraint`` / ``denial_record``
        5. drop any denied source from ``routing_decisions``

        ``agent_registry`` is accepted additively for forward-compat with the
        Phase-2 ``agent``-fact enrichment path; it is currently unused because
        the Phase-1 ``agent`` fact is already materialized from ``context``
        (``clearance``/``purpose``). Phase-1 callers that pass no registry
        continue to work unchanged.
        """
        # The registry is accepted for signature parity with design §2.2; the
        # Phase-2 agent-enrichment rules land in a later task.
        del agent_registry
        try:
            self._engine.clear_facts()

            agent_fact = {
                "id": agent_id,
                "clearance": str(context.get("clearance", "")),
                "purpose": str(context.get("purpose", "")),
            }
            self._engine.assert_fact("agent", agent_fact)

            intent_fact = {
                "raw": intent.raw_intent,
                "data_types_needed": encode_multislot(intent.data_types_needed),
                "entities": encode_multislot(intent.entities),
            }
            self._engine.assert_fact("intent", intent_fact)

            for source in sources:
                source_fact = {
                    "id": source.id,
                    "type": source.type,
                    "classification": source.classification,
                    "data_types": encode_multislot(source.data_types),
                    "allowed_purposes": encode_multislot(source.allowed_purposes),
                }
                self._engine.assert_fact("source", source_fact)

            exposure_count = self._assert_session(session)

            self._assert_escalation_rules(self._escalation_rules)

            result = self._engine.evaluate()

            raw_routing = self._engine.query("routing_decision")
            raw_scopes = self._engine.query("scope_constraint")
            raw_denials = self._engine.query("denial_record")

            denials = [
                DenialRecord(
                    source_id=str(d["source_id"]),
                    reason=str(d["reason"]),
                    rule_name=str(d["rule_name"]),
                )
                for d in raw_denials
            ]
            denied_ids = {d.source_id for d in denials}

            routing = [
                RoutingDecision(
                    source_id=str(r["source_id"]),
                    reason=str(r["reason"]),
                )
                for r in raw_routing
                if str(r["source_id"]) not in denied_ids
            ]

            scopes_by_source: dict[str, list[ScopeConstraint]] = {}
            for s in raw_scopes:
                sid = str(s["source_id"])
                # Pass through the optional temporal slots when a rule
                # populated them — downstream ``build_scope_payload``
                # flips to ``scope_hash_version == "v2"`` whenever any
                # constraint carries a non-empty ``expires_at`` /
                # ``valid_from`` (FR-19, D-7).
                _expires_at = s.get("expires_at") if hasattr(s, "get") else None
                _valid_from = s.get("valid_from") if hasattr(s, "get") else None
                scopes_by_source.setdefault(sid, []).append(
                    ScopeConstraint(
                        source_id=sid,
                        field=str(s["field"]),
                        operator=s["operator"],  # validated by Pydantic Literal
                        value=s["value"],
                        expires_at=str(_expires_at) if _expires_at else None,
                        valid_from=str(_valid_from) if _valid_from else None,
                    )
                )

            # #27 — post-run consistency checks (roadmap §05:432). Raw
            # routing ids (pre-denial-filter) are the reference set: a
            # scope on a routed-then-denied source is consistent rule
            # behavior (deny wins), a scope on a never-routed source is not.
            if self._check_consistency_enabled:
                self._run_consistency_checks(
                    agent_fact=agent_fact,
                    declared_source_ids={s.id for s in sources},
                    routed_source_ids={str(r["source_id"]) for r in raw_routing},
                    scopes_by_source=scopes_by_source,
                    denials=denials,
                    expected_exposure_count=exposure_count,
                )

            duration_us = int(getattr(result, "duration_us", 0) or 0)
            rule_trace = list(getattr(result, "rule_trace", []) or [])

            facts_summary = {
                "agent": 1,
                "intent": 1,
                "source": len(sources),
                "session": 1,
                "session_exposure": exposure_count,
            }

            return RouteResult(
                routing_decisions=routing,
                scope_constraints=scopes_by_source,
                denial_records=denials,
                rule_trace=rule_trace,
                duration_us=duration_us,
                facts_asserted_summary=facts_summary,
            )
        except PolicyEngineError:
            raise
        except Exception as exc:  # noqa: BLE001 — wrap any engine error
            raise PolicyEngineError(
                f"FathomRouter.route() failed for agent_id={agent_id!r}: {exc}"
            ) from exc

    def _run_consistency_checks(
        self,
        *,
        agent_fact: dict[str, str],
        declared_source_ids: set[str],
        routed_source_ids: set[str],
        scopes_by_source: dict[str, list[ScopeConstraint]],
        denials: list[DenialRecord],
        expected_exposure_count: int,
    ) -> None:
        """Assert post-run engine output is internally consistent (#27).

        Mitigates the design §4-ops failure mode: a meta-rule or manual
        rule asserts facts that trigger an unexpected retraction cascade,
        leaving working memory inconsistent. Each check raises
        :class:`ConsistencyError` (a :class:`PolicyEngineError` subclass,
        so the broker fails closed and audits) with the check name.

        Checks:
        - ``routing_unknown_source`` — every ``routing_decision``
          references a source declared in the registry.
        - ``scope_without_routing`` — every ``scope_constraint``
          references a ``routing_decision`` for the same source.
        - ``denial_unknown_source`` — every ``denial_record`` references
          a declared source.
        - ``denial_missing_linkage`` — every ``denial_record`` carries a
          non-empty ``reason`` and ``rule_name``.
        - ``agent_fact_integrity`` — exactly one ``agent`` fact survives
          evaluation, with the asserted id/clearance/purpose slots intact.
        - ``session_exposure_count`` — the ``session_exposure`` fact count
          matches what :meth:`_assert_session` asserted (no surprise
          retractions or injections).
        """
        unknown_routed = routed_source_ids - declared_source_ids
        if unknown_routed:
            raise ConsistencyError(
                "routing_unknown_source",
                f"routing_decision references undeclared source(s) {sorted(unknown_routed)!r}",
            )

        unscoped = set(scopes_by_source) - routed_source_ids
        if unscoped:
            raise ConsistencyError(
                "scope_without_routing",
                f"scope_constraint without a routing_decision for source(s) {sorted(unscoped)!r}",
            )

        for denial in denials:
            if denial.source_id not in declared_source_ids:
                raise ConsistencyError(
                    "denial_unknown_source",
                    f"denial_record references undeclared source {denial.source_id!r}",
                )
            if not denial.reason.strip() or not denial.rule_name.strip():
                raise ConsistencyError(
                    "denial_missing_linkage",
                    f"denial_record for source {denial.source_id!r} is missing "
                    f"reason/rule_name linkage (reason={denial.reason!r}, "
                    f"rule_name={denial.rule_name!r})",
                )

        agent_facts = self._engine.query("agent")
        if len(agent_facts) != 1:
            raise ConsistencyError(
                "agent_fact_integrity",
                f"expected exactly 1 agent fact after evaluation, found {len(agent_facts)}",
            )
        surviving = agent_facts[0]
        for slot in ("id", "clearance", "purpose"):
            asserted = agent_fact[slot]
            actual = str(surviving.get(slot, ""))
            if actual != asserted:
                raise ConsistencyError(
                    "agent_fact_integrity",
                    f"agent fact slot {slot!r} mutated during evaluation: "
                    f"asserted {asserted!r}, found {actual!r}",
                )

        exposure_facts = self._engine.query("session_exposure")
        if len(exposure_facts) != expected_exposure_count:
            raise ConsistencyError(
                "session_exposure_count",
                f"expected {expected_exposure_count} session_exposure fact(s) "
                f"after evaluation, found {len(exposure_facts)} "
                "(unexpected retraction cascade or injection)",
            )

    def _assert_session(self, session: dict[str, Any]) -> int:
        """Assert one ``session`` fact + one ``session_exposure`` per multislot element.

        Design §3.3 / FR-5 / AC-2.3: the persistent :class:`SessionStore`
        keeps ``data_types_seen`` / ``sources_visited`` / ``pii_sources_accessed_list``
        as JSONB arrays; the broker hands them back here as Python lists (or
        pre-encoded space-separated strings for the Phase-1 in-memory store).
        We (1) encode each multislot onto the ``session`` template's
        string-slot and (2) emit one ``session_exposure`` fact per element
        so rules can pattern-match individual values.

        A Phase-1 session dict without any of the three multislot keys yields
        ZERO ``session_exposure`` facts — preserving NFR-5 backwards
        compatibility for the MVP e2e test.

        Returns the number of ``session_exposure`` facts asserted so callers
        can fold it into :attr:`RouteResult.facts_asserted_summary`.
        """
        session_id = str(session.get("id") or session.get("session_id") or "")
        session_fact: dict[str, Any] = {
            "id": session_id,
            "pii_sources_accessed": int(session.get("pii_sources_accessed", 0)),
            "purpose_start_ts": float(session.get("purpose_start_ts", 0.0)),
            "purpose_ttl_seconds": float(session.get("purpose_ttl_seconds", 0.0)),
        }
        by_slot: dict[str, list[str]] = {}
        for slot in _SESSION_EXPOSURE_MULTISLOTS:
            values = _coerce_multislot(session.get(slot))
            by_slot[slot] = values
            session_fact[slot] = encode_multislot(values)
        self._engine.assert_fact("session", session_fact)

        exposure_count = 0
        for category, values in by_slot.items():
            for value in values:
                self._engine.assert_fact(
                    "session_exposure",
                    {
                        "session_id": session_id,
                        "category": category,
                        "value": value,
                    },
                )
                exposure_count += 1
        return exposure_count

    def _assert_escalation_rules(self, rules: list[EscalationRule]) -> None:
        """Assert one ``escalation_rule`` fact per loaded :class:`EscalationRule`.

        Called from :meth:`route` after ``clear_facts()`` so the declarative
        packs are visible to every evaluation. ``trigger_combination`` is
        already a space-separated CLIPS-safe multislot string on the Pydantic
        model, so no re-encoding is needed (design §3.4).
        """
        for rule in rules:
            self._engine.assert_fact(
                "escalation_rule",
                {
                    "id": rule.id,
                    "trigger_combination": rule.trigger_combination,
                    "resulting_level": rule.resulting_level,
                    "action": rule.action,
                },
            )

    def reload_rule(self, rule_name: str, rule_yaml: str) -> None:
        """Load/reload a single rule into the active CLIPS environment.

        Writes ``rule_yaml`` to a temp file then calls ``engine.load_rules``.
        Raises :class:`~nautilus.core.PolicyEngineError` if the engine rejects
        the rule (caller should mark proposal ``promotion_failed`` and re-raise).
        """
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".yaml",
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp.write(rule_yaml)
                tmp_path = tmp.name
            self._engine.load_rules(tmp_path)
        except PolicyEngineError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise PolicyEngineError(
                f"FathomRouter.reload_rule() failed for rule_name={rule_name!r}: {exc}"
            ) from exc
        finally:
            import os as _os

            with contextlib.suppress(OSError):
                _os.unlink(tmp_path)  # type: ignore[possibly-undefined]

    def close(self) -> None:
        """No-op for the Phase 1 in-process Engine (kept for Protocol parity)."""
        return None


__all__ = ["FathomRouter", "RouteResult"]
