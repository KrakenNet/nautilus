"""Unit tests for Phase-2 additions to :mod:`nautilus.config.loader` (Task 3.1).

Complements ``tests/unit/test_config_loader.py`` (Phase-1 contract) with
cases specific to the Phase-2 surface (design §3.5, §3.11, §3.14,
FR-24, NFR-5, AC-1.4):

* (a) ``${VAR}`` interpolation walks into ``api.keys`` entries — the
  interpolator descends into *every* string leaf, not just the
  pydantic-backed ones.
* (b) Missing env var referenced by ``attestation.sink.url`` raises
  :class:`ConfigError` (FR-2 carries over to Phase-2 subsections).
* (c) All four new adapter types (``elasticsearch``, ``rest``, ``neo4j``,
  ``servicenow``) are accepted by the loader + :class:`SourceConfig`.
* (d) The Phase-1 fixture (``tests/fixtures/nautilus.yaml``) still loads
  without modification (NFR-5 backwards-compat).
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from nautilus.config.loader import ConfigError, load_config
from nautilus.config.models import (
    NautilusConfig,
    SourceConfig,
)

pytestmark = pytest.mark.unit


def _write_yaml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "nautilus.yaml"
    path.write_text(dedent(body), encoding="utf-8")
    return path


def _minimal_sources_block() -> str:
    """A single-source ``sources:`` block so tests can focus on Phase-2 fields."""
    return """\
    sources:
      - id: nvd_db
        type: postgres
        description: "NVD mirror"
        classification: unclassified
        data_types: [cve]
        connection: ${TEST_PG_DSN}
        table: vulns
    """


def test_env_interpolation_in_api_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """(a) ``${VAR}`` under ``api.keys`` is walked by the interpolator.

    ``api.keys`` is not yet a pydantic-backed field on :class:`ApiConfig`
    (extras are dropped on validate). The observable proof that
    interpolation happened is simply that ``load_config`` succeeds when
    the referenced env vars are set; if the walker skipped ``api.keys``
    the value would remain as the literal ``${VAR}`` pattern — and since
    we *also* verify the negative case (missing var) still raises for a
    pydantic-backed field in :func:`test_missing_env_in_attestation_sink_url_raises`,
    the pair pins both directions.
    """
    monkeypatch.setenv("TEST_PG_DSN", "postgresql://pg/db")
    monkeypatch.setenv("API_KEY_PRIMARY", "sk-primary-abc")
    monkeypatch.setenv("API_KEY_SECONDARY", "sk-secondary-xyz")

    body = (
        _minimal_sources_block()
        + """
    api:
      host: 127.0.0.1
      port: 8080
      keys:
        - ${API_KEY_PRIMARY}
        - ${API_KEY_SECONDARY}
    """
    )
    path = _write_yaml(tmp_path, body)

    config = load_config(path)

    assert isinstance(config, NautilusConfig)
    assert config.api.host == "127.0.0.1"
    assert config.api.port == 8080

    # Negative half of the contract: a missing env var under api.keys
    # must also raise, proving the walker did reach the leaves.
    monkeypatch.delenv("API_KEY_PRIMARY", raising=False)
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "API_KEY_PRIMARY" in str(excinfo.value)


def test_missing_env_in_attestation_sink_url_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(b) A missing ``${VAR}`` inside ``attestation.sink.url`` raises ConfigError."""
    monkeypatch.setenv("TEST_PG_DSN", "postgresql://pg/db")
    # The sink URL references ATTESTATION_URL which is unset.
    monkeypatch.delenv("ATTESTATION_URL", raising=False)

    body = (
        _minimal_sources_block()
        + """
    attestation:
      enabled: true
      sink:
        type: http
        url: ${ATTESTATION_URL}/ingest
    """
    )
    path = _write_yaml(tmp_path, body)

    with pytest.raises(ConfigError) as excinfo:
        load_config(path)

    assert "ATTESTATION_URL" in str(excinfo.value)


def test_four_new_phase2_adapter_types_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(c) The loader accepts all 4 Phase-2 adapter types (design §3.5)."""
    monkeypatch.setenv("ES_URL", "https://es.example:9200")
    monkeypatch.setenv("REST_URL", "https://rest.example")
    monkeypatch.setenv("NEO4J_URL", "bolt://neo4j.example:7687")
    monkeypatch.setenv("SNOW_URL", "https://instance.service-now.com")

    body = """\
    sources:
      - id: es_threat_intel
        type: elasticsearch
        description: "ES threat intel index"
        classification: cui
        data_types: [ioc]
        connection: ${ES_URL}
        index: threat-intel

      - id: rest_cmdb
        type: rest
        description: "REST CMDB"
        classification: cui
        data_types: [asset]
        connection: ${REST_URL}

      - id: neo4j_graph
        type: neo4j
        description: "Neo4j relationship graph"
        classification: unclassified
        data_types: [relationship]
        connection: ${NEO4J_URL}
        label: Host

      - id: snow_inc
        type: servicenow
        description: "ServiceNow incidents"
        classification: cui
        data_types: [incident]
        connection: ${SNOW_URL}
    """
    path = _write_yaml(tmp_path, body)

    config = load_config(path)

    assert isinstance(config, NautilusConfig)
    by_id: dict[str, SourceConfig] = {s.id: s for s in config.sources}
    assert by_id["es_threat_intel"].type == "elasticsearch"
    assert by_id["es_threat_intel"].index == "threat-intel"
    assert by_id["rest_cmdb"].type == "rest"
    assert by_id["rest_cmdb"].connection == "https://rest.example"
    assert by_id["neo4j_graph"].type == "neo4j"
    assert by_id["neo4j_graph"].label == "Host"
    assert by_id["snow_inc"].type == "servicenow"
    # All four kinds were accepted.
    assert {s.type for s in config.sources} == {
        "elasticsearch",
        "rest",
        "neo4j",
        "servicenow",
    }


def test_phase1_fixture_still_loads_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """(d) NFR-5 — the Phase-1 ``tests/fixtures/nautilus.yaml`` still loads."""
    monkeypatch.setenv("TEST_PG_DSN", "postgresql://pg/db")
    monkeypatch.setenv("TEST_PGV_DSN", "postgresql://pgv/db")

    fixture_path = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"
    assert fixture_path.is_file(), f"Phase-1 fixture missing at {fixture_path}"

    config = load_config(fixture_path)

    assert isinstance(config, NautilusConfig)
    assert [s.id for s in config.sources] == ["nvd_db", "internal_vulns"]
    # Phase-1 fixture declares no agents; the default is an empty dict.
    assert config.agents == {}
    # Phase-2 subsections get their pydantic defaults.
    assert config.api.host == "127.0.0.1"
    assert config.session_store.backend == "memory"
