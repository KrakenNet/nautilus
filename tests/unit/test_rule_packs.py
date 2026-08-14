"""Unit tests for NIST and HIPAA rule pack YAML validation."""

import glob
import os
from typing import Any, cast

import pytest
import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
NIST_DIR = os.path.join(ROOT, "nautilus", "rule_packs", "data_routing_nist")
HIPAA_DIR = os.path.join(ROOT, "nautilus", "rule_packs", "data_routing_hipaa")

# Entry-point names from the ``fathom.packs`` group in pyproject.toml. Packs are
# loaded by name, not by path; the *_DIR constants above are only for the
# static YAML checks.
NIST_PACK = "data-routing-nist"
HIPAA_PACK = "data-routing-hipaa"

# Named explicitly rather than re-derived from the pack YAML: a test that reads
# the same files it is checking cannot detect a pack that fails to load.
PACK_RULE_NAMES = {
    NIST_PACK: {"ac-6-least-privilege", "ac-16-unbound-security-attributes"},
    HIPAA_PACK: {"minimum-necessary-phi-scope", "deny-phi-outside-tpo"},
}

# Expected salience band per asserted fact template. Keyed on what a rule
# ASSERTS, not on ``then.action``: every shipped scope rule declares
# ``action: route``, so an action-keyed lookup finds no band and checks
# nothing. The ordering these bands encode is load-bearing — denial must
# outrank scoping, or a source that is about to be denied gets scoped first.
SALIENCE_BANDS = {
    "denial_record": (170, 190),
    "scope_constraint": (130, 150),
    "escalation_request": (110, 120),
}


def _discover_yaml(base_dir: str) -> list[str]:
    """Return all .yaml files under *base_dir* using glob.glob."""
    pattern = os.path.join(base_dir, "**", "*.yaml")
    return sorted(glob.glob(pattern, recursive=True))


# ---------------------------------------------------------------------------
# NIST pack YAML parsing
# ---------------------------------------------------------------------------


class TestNISTPack:
    """All NIST rule-pack YAML files parse correctly."""

    nist_files = _discover_yaml(NIST_DIR)

    @pytest.mark.parametrize("path", nist_files, ids=[os.path.basename(p) for p in nist_files])
    def test_yaml_parses(self, path: str) -> None:
        with open(path) as f:
            data = yaml.safe_load(f)
        assert data is not None, f"Empty or unparseable YAML: {path}"
        assert isinstance(data, dict), f"Expected mapping at top level: {path}"


# ---------------------------------------------------------------------------
# HIPAA pack YAML parsing
# ---------------------------------------------------------------------------


class TestHIPAAPack:
    """All HIPAA rule-pack YAML files parse correctly."""

    hipaa_files = _discover_yaml(HIPAA_DIR)

    @pytest.mark.parametrize("path", hipaa_files, ids=[os.path.basename(p) for p in hipaa_files])
    def test_yaml_parses(self, path: str) -> None:
        with open(path) as f:
            data = yaml.safe_load(f)
        assert data is not None, f"Empty or unparseable YAML: {path}"
        assert isinstance(data, dict), f"Expected mapping at top level: {path}"


# ---------------------------------------------------------------------------
# Compliance disclaimer in README.md
# ---------------------------------------------------------------------------


class TestComplianceDisclaimer:
    """Both packs contain a compliance disclaimer in README.md."""

    @pytest.mark.parametrize(
        "pack_dir,pack_name",
        [
            (NIST_DIR, "NIST"),
            (HIPAA_DIR, "HIPAA"),
        ],
    )
    def test_readme_has_compliance_disclaimer(self, pack_dir: str, pack_name: str) -> None:
        readme = os.path.join(pack_dir, "README.md")
        assert os.path.isfile(readme), f"{pack_name} README.md missing"
        with open(readme) as f:
            content = f.read()
        assert "compliance disclaimer" in content.lower(), (
            f"{pack_name} README.md lacks compliance disclaimer"
        )


# ---------------------------------------------------------------------------
# Salience band validation
# ---------------------------------------------------------------------------


def _pack_rules() -> list[tuple[str, dict[str, Any]]]:
    """Every rule in every pack, as ``(basename, rule)``.

    Discovery is over RULES, not over files that happen to carry a
    ``salience:`` line: keying the parametrisation on the value under test
    means deleting that line deletes its own guard.
    """
    result: list[tuple[str, dict[str, Any]]] = []
    for pack_dir, _pack_name in [(NIST_DIR, "NIST"), (HIPAA_DIR, "HIPAA")]:
        rules_dir = os.path.join(pack_dir, "rules")
        for path in _discover_yaml(rules_dir):
            with open(path) as f:
                data = yaml.safe_load(f)
            for rule in cast("list[dict[str, Any]]", (data or {}).get("rules", [])):
                result.append((os.path.basename(path), rule))
    return result


class TestSalienceBands:
    """Salience values fall within the band for what the rule asserts."""

    _rules = _pack_rules()

    def test_the_packs_actually_ship_rules(self) -> None:
        # Guards the parametrisation below: an empty discovery would make
        # every case vanish silently.
        assert len(self._rules) == 4

    @pytest.mark.parametrize(
        "basename,rule",
        _rules,
        ids=[f"{name}:{rule.get('name')}" for name, rule in _rules],
    )
    def test_salience_within_band(self, basename: str, rule: dict[str, Any]) -> None:
        salience = rule.get("salience")
        assert isinstance(salience, int), (
            f"rule {rule.get('name')!r} in {basename} declares no salience; "
            "it would run at the CLIPS default and interleave arbitrarily"
        )

        asserted = [
            entry.get("template")
            for entry in cast("list[dict[str, Any]]", (rule.get("then") or {}).get("assert", []))
        ]
        bands = {SALIENCE_BANDS[t] for t in asserted if t in SALIENCE_BANDS}
        assert bands, (
            f"rule {rule.get('name')!r} in {basename} asserts {asserted}, none of which "
            f"has a documented salience band ({sorted(SALIENCE_BANDS)}) — extend "
            "SALIENCE_BANDS deliberately rather than leaving the rule unchecked"
        )
        assert len(bands) == 1, (
            f"rule {rule.get('name')!r} in {basename} asserts templates from "
            f"different salience bands: {asserted}"
        )

        lo, hi = bands.pop()
        assert lo <= salience <= hi, (
            f"salience {salience} outside band {lo}-{hi} for {asserted} "
            f"in {basename} (rule {rule.get('name')!r})"
        )


# ---------------------------------------------------------------------------
# Engine loading — the packs must actually load and fire
# ---------------------------------------------------------------------------
#
# Everything above validates YAML *shape* with yaml.safe_load and never
# constructs an Engine, so it stayed green while both shipped packs were
# unloadable. These tests build a real engine.


# Per-rule triggering requests. Each entry is the minimal request that should
# put its rule in the trace; see the pack READMEs for the control each maps to.
TRIGGERS = {
    # confidential-or-above source -> purpose scope constraint
    "ac-6-least-privilege": {
        "clearance": "secret",
        "purpose": "analytics",
        "classification": "confidential",
        "data_types": ["pii"],
        "allowed_purposes": ["analytics"],
    },
    # source with no classification label at all
    "ac-16-unbound-security-attributes": {
        "clearance": "secret",
        "purpose": "analytics",
        "classification": "",
        "data_types": ["pii"],
        "allowed_purposes": ["analytics"],
    },
    # PHI source -> minimum-necessary scope constraint
    "minimum-necessary-phi-scope": {
        "clearance": "secret",
        "purpose": "treatment",
        "classification": "confidential",
        "data_types": ["phi"],
        "allowed_purposes": ["treatment"],
    },
    # PHI requested for a purpose outside treatment/payment/operations
    "deny-phi-outside-tpo": {
        "clearance": "secret",
        "purpose": "analytics",
        "classification": "confidential",
        "data_types": ["phi"],
        "allowed_purposes": ["analytics"],
    },
}


def _route(
    router: Any,
    clearance: str,
    purpose: str,
    classification: str,
    data_types: list[str],
    allowed_purposes: list[str],
) -> Any:
    """Route a single-source request built from a TRIGGERS entry."""
    from nautilus.config.models import SourceConfig
    from nautilus.core.models import IntentAnalysis

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
                allowed_purposes=allowed_purposes,
                connection="memory://",
            )
        ],
        session={"session_id": "s1"},
    )


class TestPacksLoadIntoEngine:
    """Each shipped rule pack loads into a real Fathom engine and fires."""

    @pytest.mark.parametrize(
        "pack_name",
        [NIST_PACK, HIPAA_PACK],
    )
    def test_pack_loads(self, pack_name: str) -> None:
        """The declared entry point resolves and the pack compiles into CLIPS."""
        from nautilus.core.fathom_router import FathomRouter
        from nautilus.rules import BUILT_IN_RULES_DIR

        router = FathomRouter(
            built_in_rules_dir=BUILT_IN_RULES_DIR,
            user_rules_dirs=[],
            rule_packs=[pack_name],
        )
        loaded = {r.split("::")[-1] for r in router.engine.rule_registry}
        assert PACK_RULE_NAMES[pack_name] <= loaded, (
            f"{pack_name} rules missing from engine: {PACK_RULE_NAMES[pack_name] - loaded}"
        )

    @pytest.mark.parametrize(
        "pack_name,rule_name",
        [(pack, rule) for pack, rules in PACK_RULE_NAMES.items() for rule in sorted(rules)],
    )
    def test_pack_rule_fires(self, pack_name: str, rule_name: str) -> None:
        """Every declared pack rule fires on the scenario it exists to catch.

        Asserting that *some* rule fires is not enough: a rule that can never
        fire is indistinguishable from no rule, and one live sibling would hide
        it. Each rule gets its own triggering request.
        """
        from nautilus.core.fathom_router import FathomRouter
        from nautilus.rules import BUILT_IN_RULES_DIR

        router = FathomRouter(
            built_in_rules_dir=BUILT_IN_RULES_DIR,
            user_rules_dirs=[],
            rule_packs=[pack_name],
        )
        result = _route(router, **TRIGGERS[rule_name])
        fired = {t.split("::")[-1] for t in result.rule_trace}
        assert rule_name in fired, (
            f"{rule_name} never fired on its own trigger; rule_trace={result.rule_trace}"
        )


# ---------------------------------------------------------------------------
# nautilus.yaml wiring
# ---------------------------------------------------------------------------
#
# docs/reference/rule-packs.md told users to load packs with a ``rules.packs``
# key in nautilus.yaml. That key did not exist on RulesConfig and nothing read
# it, so the documented configuration parsed and then silently did nothing.


class TestRulePacksConfigWiring:
    """``rules.packs`` in nautilus.yaml reaches the engine."""

    def test_packs_key_parses(self) -> None:
        from nautilus.config.models import RulesConfig

        assert RulesConfig().packs == []
        assert RulesConfig(packs=[NIST_PACK]).packs == [NIST_PACK]

    def test_configured_pack_loads_into_broker_engine(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from nautilus import Broker

        monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
        monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")

        fixture = os.path.join(ROOT, "tests", "fixtures", "nautilus.yaml")
        with open(fixture) as f:
            config = yaml.safe_load(f)
        config["rules"]["packs"] = [NIST_PACK]
        config["audit"]["path"] = str(tmp_path / "audit.jsonl")
        cfg_path = tmp_path / "nautilus.yaml"
        cfg_path.write_text(yaml.safe_dump(config))

        broker = Broker.from_config(cfg_path)
        try:
            loaded = {r.split("::")[-1] for r in broker._router.engine.rule_registry}
        finally:
            broker.close()
        assert PACK_RULE_NAMES[NIST_PACK] <= loaded, (
            f"rules.packs did not reach the engine; missing {PACK_RULE_NAMES[NIST_PACK] - loaded}"
        )
