"""Unit tests for :class:`CostCapConfig` wiring (Task 17, AC-2.1 / AC-2.2 / AC-2.3).

Pins the Phase-2 cost-cap surface on :mod:`nautilus.config.models`:

* (a) :class:`CostCapConfig` defaults — every axis is ``None`` (disabled) and
  ``enforcement`` defaults to ``"hard"`` (AC-2.1).
* (b) :class:`NautilusConfig.cost_caps` global default + :class:`SourceConfig`
  per-source override are both present and default to ``None`` (AC-2.2).
* (c) Round-trip a YAML-shaped dict through
  ``NautilusConfig.model_validate(...).model_dump(mode="json", exclude_none=True)``
  and assert byte-identical equivalence with the input (AC-2.3). This locks
  the contract Task 18 (`_enforce_cost_caps`) reads from.

Merge logic (per-source override wins over global default) is deliberately
**out of scope** here — Task 18 lands `_enforce_cost_caps`; this file only
pins the raw config-model surface.
"""

from __future__ import annotations

import pytest

from nautilus.config.models import CostCapConfig, NautilusConfig, SourceConfig

pytestmark = pytest.mark.unit


def _minimal_source_dict(**overrides: object) -> dict[str, object]:
    """A single-source ``sources[0]`` entry so tests can focus on cost-cap fields."""
    base: dict[str, object] = {
        "id": "nvd_db",
        "type": "postgres",
        "description": "NVD mirror",
        "classification": "unclassified",
        "data_types": ["cve"],
        "connection": "postgresql://pg/db",
        "table": "vulns",
    }
    base.update(overrides)
    return base


def test_cost_cap_config_defaults() -> None:
    """(a) AC-2.1: every axis defaults to ``None``; enforcement defaults to ``hard``."""
    caps = CostCapConfig()

    assert caps.max_tokens is None
    assert caps.max_duration_seconds is None
    assert caps.max_tool_calls is None
    assert caps.enforcement == "hard"


def test_cost_cap_config_enforcement_literal_rejects_other_values() -> None:
    """(a) AC-2.1: ``enforcement`` is ``Literal["hard", "soft"]`` — nothing else."""
    # Positive: both literals accepted.
    assert CostCapConfig(enforcement="hard").enforcement == "hard"
    assert CostCapConfig(enforcement="soft").enforcement == "soft"

    # Negative: arbitrary strings are rejected by pydantic.
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        CostCapConfig(enforcement="warn")  # type: ignore[arg-type]


def test_nautilus_config_cost_caps_default_is_none() -> None:
    """(b) AC-2.2: ``NautilusConfig.cost_caps`` defaults to ``None`` (no global cap)."""
    cfg = NautilusConfig(sources=[SourceConfig(**_minimal_source_dict())])  # type: ignore[arg-type]

    assert cfg.cost_caps is None


def test_source_config_cost_caps_default_is_none() -> None:
    """(b) AC-2.2: ``SourceConfig.cost_caps`` defaults to ``None`` (no override)."""
    src = SourceConfig(**_minimal_source_dict())  # type: ignore[arg-type]

    assert src.cost_caps is None


def test_cost_caps_round_trip_byte_identical() -> None:
    """(c) AC-2.3: YAML-shaped dict → ``model_validate`` → ``model_dump`` is byte-identical.

    The input mirrors a minimal ``nautilus.yaml`` with a global ``cost_caps``
    block and one source carrying its own override (per-source wins is a
    Task-18 concern; this test only pins the raw structure survives the
    round-trip so ``_enforce_cost_caps`` can read from a stable contract).
    """
    input_dict: dict[str, object] = {
        "sources": [
            _minimal_source_dict(
                id="nvd_db",
                cost_caps={
                    "max_tokens": 2000,
                    "enforcement": "soft",
                },
            ),
            _minimal_source_dict(
                id="cve_mirror",
                # no per-source override — falls back to global at enforcement time
            ),
        ],
        "cost_caps": {
            "max_tokens": 4000,
            "max_duration_seconds": 30,
            "max_tool_calls": 10,
            "enforcement": "hard",
        },
    }

    cfg = NautilusConfig.model_validate(input_dict)
    dumped = cfg.model_dump(mode="json", exclude_none=True)

    # The global cost_caps block survives intact.
    assert dumped["cost_caps"] == {
        "max_tokens": 4000,
        "max_duration_seconds": 30,
        "max_tool_calls": 10,
        "enforcement": "hard",
    }

    # The per-source override survives (only non-None keys round-trip, but
    # `enforcement` has a non-None default of "hard" inside CostCapConfig, so
    # for the override source we explicitly set enforcement="soft").
    dumped_sources = dumped["sources"]
    assert isinstance(dumped_sources, list)
    by_id: dict[str, dict[str, object]] = {
        s["id"]: s
        for s in dumped_sources  # type: ignore[index]
    }
    assert by_id["nvd_db"]["cost_caps"] == {
        "max_tokens": 2000,
        "enforcement": "soft",
    }
    # The source without an override does not carry a cost_caps key after
    # exclude_none — effective caps resolution happens in `_enforce_cost_caps`.
    assert "cost_caps" not in by_id["cve_mirror"]


def test_cost_caps_partial_axes_round_trip() -> None:
    """AC-2.1: only setting one axis (e.g. ``max_tokens``) must round-trip cleanly."""
    input_dict: dict[str, object] = {
        "sources": [_minimal_source_dict()],
        "cost_caps": {"max_tokens": 1000},
    }

    cfg = NautilusConfig.model_validate(input_dict)
    assert cfg.cost_caps is not None
    assert cfg.cost_caps.max_tokens == 1000
    assert cfg.cost_caps.max_duration_seconds is None
    assert cfg.cost_caps.max_tool_calls is None
    # Default enforcement is "hard" — it surfaces in the dump even though the
    # input omitted it (that is the documented default; see AC-2.1).
    assert cfg.cost_caps.enforcement == "hard"

    dumped = cfg.model_dump(mode="json", exclude_none=True)
    assert dumped["cost_caps"] == {"max_tokens": 1000, "enforcement": "hard"}
