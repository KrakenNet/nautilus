"""Integration: relationship-fact templates + manual authoring (#35.2)."""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def test_ac_35_2_a_templates_yaml_exists() -> None:
    """``rkm.yaml`` MUST exist under ``nautilus/rules/templates/``."""
    from nautilus.rules import BUILT_IN_RULES_DIR

    template = BUILT_IN_RULES_DIR / "templates" / "rkm.yaml"
    assert template.is_file()


def test_ac_35_2_b_manual_relationship_yaml_loader_returns_facts(
    tmp_path: Path,
) -> None:
    """The facts loader picks up YAMLs under ``facts/relationships/*.yaml``."""
    pytest.importorskip("nautilus.rkm")
    # Placeholder — real loader lives in nautilus.rkm and is scaffolded in
    # Phase C. For now, the AC asserts the contract.
    facts_dir = tmp_path / "relationships"
    facts_dir.mkdir()
    sample = facts_dir / "sample.yaml"
    sample.write_text(
        "source_relationship:\n"
        "  - source_a: postgres-1\n"
        "    source_b: pgvector-1\n"
        "    relationship_type: overlaps\n"
        "    confidence: 0.9\n"
    )
    # The loader symbol below is intentionally not yet implemented; the
    # test fails (ImportError or NotImplementedError) until Phase C lands.
    from nautilus.rkm import load_relationship_facts  # type: ignore[attr-defined]

    facts = load_relationship_facts(facts_dir)
    assert len(facts) == 1


def test_ac_35_2_e_invalid_relationship_type_raises(tmp_path: Path) -> None:
    facts_dir = tmp_path / "relationships"
    facts_dir.mkdir()
    bad = facts_dir / "bad.yaml"
    bad.write_text(
        "source_relationship:\n"
        "  - source_a: a\n"
        "    source_b: b\n"
        "    relationship_type: nonsense_value\n"
        "    confidence: 0.5\n"
    )
    from nautilus.rkm import load_relationship_facts  # type: ignore[attr-defined]

    with pytest.raises(ValueError, match="relationship_type"):
        load_relationship_facts(facts_dir)
