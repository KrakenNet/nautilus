"""Unit tests for :mod:`nautilus.rkm.validator.static` (#35.5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from nautilus.rkm.validator.static import validate_static

pytestmark = pytest.mark.unit


def test_ac_35_5_a_valid_rule_returns_ok_true(tmp_path: Path) -> None:
    yaml_path = tmp_path / "ok.yaml"
    yaml_path.write_text(
        "rules:\n  - name: noop\n    module: suggestions\n    lhs: []\n    rhs: []\n"
    )
    result = validate_static(yaml_path)
    assert result.ok is True
    assert result.errors == ()


def test_ac_35_5_b_unknown_template_is_rejected(tmp_path: Path) -> None:
    yaml_path = tmp_path / "bad.yaml"
    yaml_path.write_text(
        "rules:\n"
        "  - name: bad\n"
        "    module: suggestions\n"
        "    lhs:\n"
        "      - template: definitely_not_a_template\n"
        "    rhs: []\n"
    )
    result = validate_static(yaml_path)
    assert result.ok is False
    assert len(result.errors) >= 1


def test_ac_35_5_d_errors_carry_file_line_and_hint(tmp_path: Path) -> None:
    yaml_path = tmp_path / "bad.yaml"
    yaml_path.write_text(
        "rules:\n"
        "  - name: bad\n"
        "    module: suggestions\n"
        "    lhs:\n"
        "      - template: definitely_not_a_template\n"
        "    rhs: []\n"
    )
    result = validate_static(yaml_path)
    assert result.ok is False
    err = result.errors[0]
    assert err.file == str(yaml_path)
    assert err.line >= 1
    assert err.message
