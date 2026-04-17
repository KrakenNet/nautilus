"""Unit tests for NIST and HIPAA rule pack YAML validation."""

import glob
import os
import re
from typing import Any, cast

import pytest
import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
NIST_DIR = os.path.join(ROOT, "rule-packs", "data-routing-nist")
HIPAA_DIR = os.path.join(ROOT, "rule-packs", "data-routing-hipaa")

# Expected salience bands by action type
SALIENCE_BANDS = {
    "deny": (170, 190),
    "scope_constraint": (130, 150),
    "constrain": (130, 150),
    "escalate": (110, 120),
}


def _discover_yaml(base_dir: str) -> list[str]:
    """Return all .yaml files under *base_dir* using glob.glob."""
    pattern = os.path.join(base_dir, "**", "*.yaml")
    return sorted(glob.glob(pattern, recursive=True))


def _collect_salience_values(data: dict[str, Any]) -> list[int]:
    """Extract all salience integer values from a parsed YAML document."""
    values: list[int] = []
    sal = data.get("salience")
    if isinstance(sal, int):
        values.append(sal)
    rules: list[Any] = data.get("rules", [])
    for rule_obj in rules:
        if isinstance(rule_obj, dict):
            rule_sal = cast(dict[str, Any], rule_obj).get("salience")
            if isinstance(rule_sal, int):
                values.append(rule_sal)
    return values


def _parse_salience_band(band_str: str) -> tuple[int, int] | None:
    """Parse a salience_band string like '170-190' into (lo, hi)."""
    m = re.match(r"(\d+)\s*-\s*(\d+)", str(band_str))
    if m:
        return int(m.group(1)), int(m.group(2))
    return None


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


def _rule_files_with_salience() -> list[tuple[str, str]]:
    """Collect (path, pack_name) for rule files that contain salience values."""
    result: list[tuple[str, str]] = []
    for pack_dir, pack_name in [(NIST_DIR, "NIST"), (HIPAA_DIR, "HIPAA")]:
        rules_dir = os.path.join(pack_dir, "rules")
        for path in _discover_yaml(rules_dir):
            with open(path) as f:
                data = yaml.safe_load(f)
            if data and _collect_salience_values(data):
                result.append((path, pack_name))
    return result


class TestSalienceBands:
    """Salience values fall within expected bands based on action type."""

    _rule_files = _rule_files_with_salience()

    @pytest.mark.parametrize(
        "path,pack_name",
        _rule_files,
        ids=[os.path.basename(p) for p, _ in _rule_files],
    )
    def test_salience_within_band(self, path: str, pack_name: str) -> None:
        with open(path) as f:
            data = yaml.safe_load(f)

        salience_values = _collect_salience_values(data)
        assert salience_values, f"No salience values found in {path}"

        # Determine expected band from salience_band field, action field,
        # or infer from the known non-overlapping salience ranges.
        band = None
        band_str = data.get("salience_band")
        if band_str:
            band = _parse_salience_band(band_str)

        if band is None:
            action = data.get("action", "")
            band = SALIENCE_BANDS.get(action)

        if band is not None:
            lo, hi = band
            for val in salience_values:
                assert lo <= val <= hi, (
                    f"Salience {val} outside expected band {lo}-{hi} in {os.path.basename(path)}"
                )
        else:
            # No explicit band or action — verify each value falls in a
            # known band (deny 170-190, scope_constraint 130-150,
            # escalate 110-120).
            all_bands = [(170, 190), (130, 150), (110, 120)]
            for val in salience_values:
                in_band = any(lo <= val <= hi for lo, hi in all_bands)
                assert in_band, (
                    f"Salience {val} in {os.path.basename(path)} does not "
                    f"fall within any known band: {all_bands}"
                )
