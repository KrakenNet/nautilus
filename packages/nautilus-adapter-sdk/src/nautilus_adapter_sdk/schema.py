"""Public SDK ``AdapterSchema`` model — a standalone mirror of the in-repo one.

This module used to re-export from ``nautilus.adapters.schema``, which made
every SDK consumer depend on the whole core distribution — asyncpg,
elasticsearch, neo4j, fastapi, uvicorn, mcp and the rest — for four
dataclasses. The SDK declares only ``pydantic``, so importing it from a
package that installed the SDK alone raised ``ModuleNotFoundError``.

The definitions here are duplicated on purpose, the same way
:mod:`nautilus_adapter_sdk.types` duplicates the core models.
``tests/unit/adapters/test_get_schema_drift_guard.py`` pins the two copies
together, including the fingerprint digest: a schema fingerprinted by an
SDK-built adapter has to equal the one the broker would compute, or the
drift baseline compares two different things.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

_SHA256_PREFIX = "sha256:"


def _stable_json(value: Any) -> str:
    """Canonical JSON encoding used for deterministic hashing.

    Must stay byte-identical to ``nautilus.core.attestation_payload``:
    ``sort_keys=True``, no incidental whitespace, ``str`` fallback so a
    ``datetime`` never raises.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(value: Any) -> str:
    """Return ``sha256:<hex>`` of the canonical JSON encoding of ``value``."""
    digest = hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()
    return f"{_SHA256_PREFIX}{digest}"


@dataclass(frozen=True)
class AdapterField:
    """One field/column in an adapter's schema."""

    name: str
    type: str
    nullable: bool
    description: str = ""


@dataclass(frozen=True)
class AdapterTable:
    """One table/collection in an adapter's schema."""

    name: str
    fields: tuple[AdapterField, ...]
    indexes: tuple[str, ...] = ()
    primary_key: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdapterSchema:
    """Per-adapter schema fingerprint surface returned by ``get_schema()``."""

    adapter_id: str
    source_type: str
    tables: tuple[AdapterTable, ...]
    capability_flags: Mapping[str, bool]
    fetched_at: datetime

    @classmethod
    def unknown(cls, adapter_id: str, source_type: str) -> AdapterSchema:
        """Default for adapters without schema introspection (S3, legacy)."""
        return cls(
            adapter_id=adapter_id,
            source_type=source_type,
            tables=(),
            capability_flags={},
            fetched_at=datetime.now(UTC),
        )

    def fingerprint(self) -> str:
        """``sha256:<hex>`` over the canonical JSON of this schema.

        ``fetched_at`` is excluded: it records WHEN the schema was read, not
        WHAT it is, and every adapter stamps it with ``datetime.now(UTC)``.
        Hashing it would make an unchanged schema fingerprint differently on
        every fetch, defeating the drift comparison it exists for.
        """
        payload = {k: v for k, v in dataclasses.asdict(self).items() if k != "fetched_at"}
        return _sha256(payload)


@dataclass(frozen=True)
class SchemaDiffEntry:
    """One entry in a structured schema drift diff."""

    op: Literal["add", "remove", "change", "capability_toggle"]
    path: str
    from_value: Any | None
    to_value: Any | None
    severity: Literal["minor", "major"]


__all__ = ["AdapterField", "AdapterSchema", "AdapterTable", "SchemaDiffEntry"]
