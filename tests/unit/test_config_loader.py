"""Unit tests for :mod:`nautilus.config.loader` (Task 3.1).

Covers the configuration loader contract called out in the spec:

* AC-1.1 — A valid YAML config produces a :class:`NautilusConfig`.
* AC-1.2 — ``${VAR}`` substitution happens in ``connection`` strings.
* AC-1.3 — Load-time validation failures raise :class:`ConfigError`.
* NFR-5  — Missing env-var errors cite both the variable name *and* the
  offending ``source.id`` so operators can fix configs blind.
* FR-1 / FR-2 — Source inventory is realised from YAML with env interpolation.

These tests are deliberately narrow: the :class:`SourceRegistry` duplicate-id
path is covered by ``test_source_registry.py`` (Task 3.2). The loader itself
also raises on duplicate ids (design §3.2), so that case is asserted here to
keep the two layers honest.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from nautilus.config.loader import ConfigError, load_config
from nautilus.config.models import NautilusConfig, SourceConfig

pytestmark = pytest.mark.unit


def _write_yaml(tmp_path: Path, body: str) -> Path:
    """Write ``body`` (dedented) to ``tmp_path/nautilus.yaml`` and return the path."""
    path = tmp_path / "nautilus.yaml"
    path.write_text(dedent(body), encoding="utf-8")
    return path


def _valid_yaml_body() -> str:
    """Baseline two-source YAML used by most cases.

    Mirrors the shape of ``tests/fixtures/nautilus.yaml`` but keeps the env-var
    surface minimal so each test can pinpoint failure modes.
    """
    return """\
    sources:
      - id: nvd_db
        type: postgres
        description: "NVD mirror"
        classification: unclassified
        data_types: [cve, vulnerability]
        allowed_purposes: [threat-analysis]
        connection: ${TEST_PG_DSN}
        table: vulns

      - id: internal_vulns
        type: pgvector
        description: "Internal embeddings"
        classification: cui
        data_types: [vulnerability]
        connection: ${TEST_PGV_DSN}
        table: vuln_embeddings
        embedding_column: embedding
        metadata_column: metadata
    """


def test_valid_yaml_produces_nautilus_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(a) AC-1.1 — a well-formed YAML materialises into a :class:`NautilusConfig`."""
    monkeypatch.setenv("TEST_PG_DSN", "postgresql://pg/db")
    monkeypatch.setenv("TEST_PGV_DSN", "postgresql://pgv/db")

    path = _write_yaml(tmp_path, _valid_yaml_body())

    config = load_config(path)

    assert isinstance(config, NautilusConfig)
    assert [s.id for s in config.sources] == ["nvd_db", "internal_vulns"]
    assert all(isinstance(s, SourceConfig) for s in config.sources)


def test_missing_env_var_raises_with_var_and_source_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(b) NFR-5 — missing env-var error names both the variable and the source id."""
    # Ensure the referenced var is unambiguously absent.
    monkeypatch.delenv("TEST_PG_DSN", raising=False)
    monkeypatch.setenv("TEST_PGV_DSN", "postgresql://pgv/db")

    path = _write_yaml(tmp_path, _valid_yaml_body())

    with pytest.raises(ConfigError) as excinfo:
        load_config(path)

    message = str(excinfo.value)
    assert "TEST_PG_DSN" in message, message
    assert "nvd_db" in message, message


def test_unknown_source_type_raises_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(c) AC-1.3 — an unsupported ``type`` is rejected at load time."""
    monkeypatch.setenv("TEST_PG_DSN", "postgresql://pg/db")

    body = """\
    sources:
      - id: weird_source
        type: mysql
        description: "not supported"
        classification: unclassified
        data_types: [cve]
        connection: ${TEST_PG_DSN}
    """
    path = _write_yaml(tmp_path, body)

    with pytest.raises(ConfigError) as excinfo:
        load_config(path)

    message = str(excinfo.value)
    assert "mysql" in message, message
    assert "weird_source" in message, message


def test_duplicate_source_id_raises_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(d) AC-1.3 — duplicate ids surface at load time (also enforced by registry)."""
    monkeypatch.setenv("TEST_PG_DSN", "postgresql://pg/db")

    body = """\
    sources:
      - id: nvd_db
        type: postgres
        description: "first"
        classification: unclassified
        data_types: [cve]
        connection: ${TEST_PG_DSN}
        table: vulns

      - id: nvd_db
        type: postgres
        description: "dup"
        classification: unclassified
        data_types: [cve]
        connection: ${TEST_PG_DSN}
        table: vulns2
    """
    path = _write_yaml(tmp_path, body)

    with pytest.raises(ConfigError) as excinfo:
        load_config(path)

    message = str(excinfo.value)
    assert "nvd_db" in message, message
    assert "duplicate" in message.lower(), message


def test_env_interpolation_in_connection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """(e) AC-1.2 / FR-2 — ``${VAR}`` inside ``connection`` is substituted."""
    expected_dsn = "postgresql://user:secret@db.example:5432/nvd"
    monkeypatch.setenv("TEST_PG_DSN", expected_dsn)
    monkeypatch.setenv("TEST_PGV_DSN", "postgresql://pgv/db")

    path = _write_yaml(tmp_path, _valid_yaml_body())

    config = load_config(path)

    nvd = next(s for s in config.sources if s.id == "nvd_db")
    assert nvd.connection == expected_dsn
    # And the raw ${...} marker must not leak through.
    assert "${" not in nvd.connection


def test_allowed_purposes_optional_defaults_to_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(f) ``allowed_purposes`` is optional; omission yields ``None`` (design §4.1)."""
    monkeypatch.setenv("TEST_PG_DSN", "postgresql://pg/db")

    body = """\
    sources:
      - id: nvd_db
        type: postgres
        description: "no purposes listed"
        classification: unclassified
        data_types: [cve]
        connection: ${TEST_PG_DSN}
        table: vulns
    """
    path = _write_yaml(tmp_path, body)

    config = load_config(path)

    (only,) = config.sources
    assert only.allowed_purposes is None
