"""Unit tests for :class:`IngestIntegrityConfig` (Task 25, AC-4.2 / AC-4.3 / OQ-3).

Pins the Phase-5 ingest-integrity config surface:

* (a) Default values — only ``schema`` is required; every other field has a
  documented default (``on_schema_violation="quarantine"``,
  ``baseline_window="7d"``, ``anomaly_sigma=3.0``,
  ``on_publisher_schema_change="pause"``, ``corroboration_callback=None``,
  and — per OQ-3 — ``baseline_retention="90d"``).
* (b) Round-trip via ``model_validate(...).model_dump(by_alias=True)`` is
  byte-identical to the input so YAML loaded as a dict survives a full
  Pydantic cycle (Task 30's orchestrator relies on this).
* (c) ``baseline_window`` accepts ``humanfriendly``-style strings
  (``"7d"``, ``"24h"``, ``"30m"``) as plain ``str`` — parsing is a
  consumer concern (Task 27's :class:`BaselineTracker`), so malformed
  durations don't raise here.
* (d) :class:`SourceConfig.ingest_integrity` defaults to ``None`` and
  round-trips as a nested block when populated (NFR-BC).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nautilus.config.models import SourceConfig
from nautilus.ingest.config import IngestIntegrityConfig

pytestmark = pytest.mark.unit


def _minimal_source_dict(**overrides: object) -> dict[str, object]:
    """A single-source ``sources[0]`` entry so tests can focus on ingest_integrity fields."""
    base: dict[str, object] = {
        "id": "nautobot",
        "type": "rest",
        "description": "Nautobot GraphQL",
        "classification": "unclassified",
        "data_types": ["device"],
        "connection": "https://nautobot.example.com",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# (a) Default values.
# ---------------------------------------------------------------------------


def test_defaults_only_schema_required() -> None:
    """AC-4.2/AC-4.3/OQ-3: only ``schema`` is required; every other field has a default."""
    cfg = IngestIntegrityConfig.model_validate({"schema": "/etc/nautilus/schemas/n.json"})

    assert cfg.schema_ == "/etc/nautilus/schemas/n.json"
    assert cfg.on_schema_violation == "quarantine"
    assert cfg.baseline_window == "7d"
    assert cfg.anomaly_sigma == 3.0
    assert cfg.on_publisher_schema_change == "pause"
    assert cfg.corroboration_callback is None
    # OQ-3: default rolling retention is 90 days.
    assert cfg.baseline_retention == "90d"


def test_schema_field_is_required() -> None:
    """``schema`` is the single required field — no default."""
    with pytest.raises(ValidationError):
        IngestIntegrityConfig.model_validate({})  # type: ignore[arg-type]


def test_on_schema_violation_literal_rejects_other_values() -> None:
    """AC-4.2: ``on_schema_violation`` is a closed literal set."""
    for ok in ("quarantine", "reject", "pass-through"):
        cfg = IngestIntegrityConfig.model_validate({"schema": "/p", "on_schema_violation": ok})
        assert cfg.on_schema_violation == ok

    with pytest.raises(ValidationError):
        IngestIntegrityConfig.model_validate(
            {"schema": "/p", "on_schema_violation": "drop"},
        )


def test_on_publisher_schema_change_literal_rejects_other_values() -> None:
    """AC-4.3: ``on_publisher_schema_change`` is a closed literal set."""
    for ok in ("pause", "warn"):
        cfg = IngestIntegrityConfig.model_validate(
            {"schema": "/p", "on_publisher_schema_change": ok},
        )
        assert cfg.on_publisher_schema_change == ok

    with pytest.raises(ValidationError):
        IngestIntegrityConfig.model_validate(
            {"schema": "/p", "on_publisher_schema_change": "ignore"},
        )


# ---------------------------------------------------------------------------
# (b) Round-trip fidelity.
# ---------------------------------------------------------------------------


def test_round_trip_byte_identical_with_all_fields() -> None:
    """YAML-shaped dict → ``model_validate`` → ``model_dump(by_alias=True)`` is byte-identical."""
    input_dict: dict[str, object] = {
        "schema": "vault://kv/nautobot/schema",
        "on_schema_violation": "reject",
        "baseline_window": "24h",
        "anomaly_sigma": 2.5,
        "on_publisher_schema_change": "warn",
        "baseline_retention": "30d",
    }

    cfg = IngestIntegrityConfig.model_validate(input_dict)
    dumped = cfg.model_dump(mode="json", by_alias=True)

    assert dumped == {
        "schema": "vault://kv/nautobot/schema",
        "on_schema_violation": "reject",
        "baseline_window": "24h",
        "anomaly_sigma": 2.5,
        "on_publisher_schema_change": "warn",
        "baseline_retention": "30d",
    }


def test_round_trip_defaults_surface_on_dump() -> None:
    """Defaults surface in the dump so ops YAML is self-describing after validation."""
    cfg = IngestIntegrityConfig.model_validate({"schema": "env://NAUT_SCHEMA"})
    dumped = cfg.model_dump(mode="json", by_alias=True)

    # Callable default is excluded (not serialisable); every other field surfaces.
    assert dumped == {
        "schema": "env://NAUT_SCHEMA",
        "on_schema_violation": "quarantine",
        "baseline_window": "7d",
        "anomaly_sigma": 3.0,
        "on_publisher_schema_change": "pause",
        "baseline_retention": "90d",
    }


def test_corroboration_callback_is_excluded_from_dump() -> None:
    """Callables aren't JSON-serialisable — exclude from ``model_dump`` output."""

    def cb(rows: list[dict[str, object]]) -> list[dict[str, object]]:
        return rows

    cfg = IngestIntegrityConfig(schema_="/p", corroboration_callback=cb)
    dumped = cfg.model_dump(mode="json", by_alias=True)

    assert "corroboration_callback" not in dumped
    # But the attribute is retained in-memory for the orchestrator to call.
    assert cfg.corroboration_callback is cb


# ---------------------------------------------------------------------------
# (c) baseline_window humanfriendly-style strings.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("window", ["7d", "24h", "30m", "14d", "1h", "90s"])
def test_baseline_window_accepts_humanfriendly_strings(window: str) -> None:
    """``baseline_window`` stores the raw string; parsing is a consumer concern."""
    cfg = IngestIntegrityConfig.model_validate({"schema": "/p", "baseline_window": window})
    assert cfg.baseline_window == window


def test_baseline_window_does_not_parse_at_model_level() -> None:
    """The model treats ``baseline_window`` as opaque ``str`` — no validation here.

    Parsing (and rejecting malformed durations) is
    :class:`~nautilus.ingest.baseline.BaselineTracker`'s job (Task 27). Keeping
    the model agnostic means YAML round-trips byte-identically and ops-time
    errors surface at the site they're acted on, not at config load.
    """
    # A nonsense string still validates at the model level.
    cfg = IngestIntegrityConfig.model_validate(
        {"schema": "/p", "baseline_window": "not-a-duration"}
    )
    assert cfg.baseline_window == "not-a-duration"


# ---------------------------------------------------------------------------
# (d) SourceConfig.ingest_integrity wiring.
# ---------------------------------------------------------------------------


def test_source_config_ingest_integrity_default_is_none() -> None:
    """NFR-BC: existing YAML without ``ingest_integrity`` continues to load."""
    src = SourceConfig(**_minimal_source_dict())  # type: ignore[arg-type]
    assert src.ingest_integrity is None


def test_source_config_ingest_integrity_round_trip() -> None:
    """``SourceConfig`` round-trips with a nested ``ingest_integrity`` block."""
    input_dict = _minimal_source_dict(
        ingest_integrity={
            "schema": "/etc/nautilus/nautobot.json",
            "on_schema_violation": "reject",
            "anomaly_sigma": 4.0,
        },
    )

    src = SourceConfig.model_validate(input_dict)
    assert src.ingest_integrity is not None
    assert src.ingest_integrity.schema_ == "/etc/nautilus/nautobot.json"
    assert src.ingest_integrity.on_schema_violation == "reject"
    assert src.ingest_integrity.anomaly_sigma == 4.0
    # Defaults fill in for unspecified fields.
    assert src.ingest_integrity.baseline_retention == "90d"

    dumped = src.model_dump(mode="json", by_alias=True, exclude_none=True)
    assert dumped["ingest_integrity"]["schema"] == "/etc/nautilus/nautobot.json"
    assert dumped["ingest_integrity"]["on_schema_violation"] == "reject"
    assert dumped["ingest_integrity"]["baseline_retention"] == "90d"
