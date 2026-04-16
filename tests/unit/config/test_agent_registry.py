"""Unit tests for :mod:`nautilus.config.agent_registry` (Task 3.1).

Covers the :class:`AgentRegistry` contract (FR-9, AC-4.2, design §3.5):

* (a) ``get`` returns the matching :class:`AgentRecord`.
* (b) ``get`` on an unknown id raises :class:`UnknownAgentError`.
* (c) Iteration order mirrors the declaration order of the underlying
  YAML mapping (insertion order, preserved by ``dict`` since 3.7).
* (d) NFR-5 — a Phase-1 ``nautilus.yaml`` that omits the ``agents:``
  section still loads; the resulting registry is empty.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nautilus.config.agent_registry import AgentRegistry, UnknownAgentError
from nautilus.config.loader import load_config
from nautilus.config.models import AgentRecord

pytestmark = pytest.mark.unit


def _make_record(
    agent_id: str,
    clearance: str = "unclassified",
    compartments: list[str] | None = None,
    default_purpose: str | None = None,
) -> AgentRecord:
    return AgentRecord(
        id=agent_id,
        clearance=clearance,
        compartments=compartments or [],
        default_purpose=default_purpose,
    )


def test_get_returns_matching_record() -> None:
    """(a) ``AgentRegistry.get`` returns the record for a registered id."""
    analyst = _make_record("analyst-1", clearance="cui", default_purpose="triage")
    registry = AgentRegistry({"analyst-1": analyst})

    got = registry.get("analyst-1")

    assert got is analyst
    assert got.id == "analyst-1"
    assert got.clearance == "cui"
    assert got.default_purpose == "triage"


def test_get_unknown_id_raises_unknown_agent_error() -> None:
    """(b) AC-4.2 — unregistered agent ids raise :class:`UnknownAgentError`."""
    registry = AgentRegistry({"analyst-1": _make_record("analyst-1")})

    with pytest.raises(UnknownAgentError) as excinfo:
        registry.get("ghost")

    assert "ghost" in str(excinfo.value)


def test_iteration_preserves_yaml_declaration_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(c) Iteration walks agents in the order they appeared in YAML.

    YAML + :mod:`yaml.safe_load` preserves mapping key order; the registry
    is constructed from that dict and must expose the same order. Four
    entries are used so an accidental alphabetical sort would be caught.
    """
    monkeypatch.setenv("TEST_PG_DSN", "postgresql://pg/db")

    yaml_body = """\
sources:
  - id: nvd_db
    type: postgres
    description: "NVD mirror"
    classification: unclassified
    data_types: [cve]
    connection: ${TEST_PG_DSN}
    table: vulns

agents:
  zulu:
    id: zulu
    clearance: cui
  alpha:
    id: alpha
    clearance: unclassified
  mike:
    id: mike
    clearance: secret
  bravo:
    id: bravo
    clearance: unclassified
"""
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml_body, encoding="utf-8")

    config = load_config(path)
    registry = AgentRegistry(config.agents)

    ids_in_order = [record.id for record in registry]

    assert ids_in_order == ["zulu", "alpha", "mike", "bravo"]
    # Sanity: not alphabetical.
    assert ids_in_order != sorted(ids_in_order)


def test_phase1_yaml_without_agents_section_yields_empty_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """(d) NFR-5 — Phase-1 fixture omits ``agents:``; registry is empty."""
    # Phase-1 fixture requires these env vars for its sources.
    monkeypatch.setenv("TEST_PG_DSN", "postgresql://pg/db")
    monkeypatch.setenv("TEST_PGV_DSN", "postgresql://pgv/db")

    fixture_path = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"
    assert fixture_path.is_file(), f"Phase-1 fixture missing at {fixture_path}"

    config = load_config(fixture_path)
    registry = AgentRegistry(config.agents)

    assert len(registry) == 0
    assert list(registry) == []
    with pytest.raises(UnknownAgentError):
        registry.get("any-id")
