"""Unit tests for :class:`nautilus.config.registry.SourceRegistry` (Task 3.2).

Covers AC-1.4 / design §3.2:

* The registry surfaces every field from the originating YAML dict unchanged
  (snapshot equality), so downstream adapters can rely on a 1:1 mapping.
* ``.get("unknown")`` raises :class:`KeyError` for ids the config did not
  declare — never returns ``None`` or a default.
* ``len(registry)`` equals the number of configured sources.

Companion to ``test_config_loader.py`` (Task 3.1): the loader-level duplicate
id path lives there; the registry-level duplicate guard (design §3.2) is
asserted here to keep both layers honest.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
import yaml

from nautilus.config.loader import ConfigError
from nautilus.config.models import SourceConfig
from nautilus.config.registry import SourceRegistry

pytestmark = pytest.mark.unit


def _yaml_body() -> str:
    """Two-source YAML exercising both ``postgres`` and ``pgvector`` shapes.

    The bodies here must stay in sync with :class:`SourceConfig` — in
    particular every optional field that AC-1.4 promises to surface (e.g.
    ``allowed_purposes``, ``distance_operator``, ``top_k``) appears on at
    least one entry so the snapshot assertion has teeth.
    """
    return """\
sources:
  - id: nvd_db
    type: postgres
    description: "NVD mirror"
    classification: unclassified
    data_types: [cve, vulnerability]
    allowed_purposes: [threat-analysis]
    connection: postgresql://pg/db
    table: vulns

  - id: internal_vulns
    type: pgvector
    description: "Internal embeddings"
    classification: cui
    data_types: [vulnerability]
    allowed_purposes: [threat-analysis, incident-response]
    connection: postgresql://pgv/db
    table: vuln_embeddings
    embedding_column: embedding
    metadata_column: metadata
    distance_operator: "<=>"
    top_k: 25
    embedder: default
"""


def _load_sources_from_yaml() -> tuple[list[dict[str, Any]], list[SourceConfig]]:
    """Parse the shared fixture YAML into both raw dicts and validated models."""
    raw = cast(dict[str, Any], yaml.safe_load(_yaml_body()))
    raw_sources = cast(list[dict[str, Any]], raw["sources"])
    assert isinstance(raw_sources, list)
    models = [SourceConfig.model_validate(entry) for entry in raw_sources]
    return raw_sources, models


def test_registry_exposes_all_fields_identical_to_yaml_dict() -> None:
    """(a) AC-1.4 — each registered source round-trips the YAML dict 1:1.

    We compare ``model_dump()`` for every entry, field-for-field, to the
    original mapping so regressions that silently drop or rename a field
    fail loudly here.
    """
    raw_sources, models = _load_sources_from_yaml()

    registry = SourceRegistry(models)

    for raw_entry in raw_sources:
        fetched = registry.get(raw_entry["id"])
        dumped = fetched.model_dump()
        for key, expected in raw_entry.items():
            assert dumped[key] == expected, (
                f"field '{key}' for source '{raw_entry['id']}' "
                f"differs: expected {expected!r}, got {dumped[key]!r}"
            )


def test_registry_get_unknown_raises_key_error() -> None:
    """(b) AC-1.4 — ``.get()`` is strict: unknown ids surface as ``KeyError``."""
    _, models = _load_sources_from_yaml()
    registry = SourceRegistry(models)

    with pytest.raises(KeyError):
        registry.get("unknown")


def test_registry_len_matches_source_count() -> None:
    """(c) AC-1.4 — ``len(registry)`` reflects the configured source count."""
    raw_sources, models = _load_sources_from_yaml()
    registry = SourceRegistry(models)

    assert len(registry) == len(raw_sources)
    # And iteration preserves insertion order for deterministic downstream use.
    assert [s.id for s in registry] == [entry["id"] for entry in raw_sources]


def test_registry_rejects_duplicate_ids() -> None:
    """(d) design §3.2 — duplicate ids at construction raise :class:`ConfigError`.

    This complements the loader-level duplicate check in
    ``test_config_loader.py``; the registry refuses to construct an
    ambiguous index even if callers bypass the loader.
    """
    _, models = _load_sources_from_yaml()
    dup = models + [models[0].model_copy()]

    with pytest.raises(ConfigError) as excinfo:
        SourceRegistry(dup)

    assert models[0].id in str(excinfo.value)
