"""AdapterSchema + drift classification + fingerprint store (#21).

ACs satisfied (per ``.forge/shared.md`` Module layout):
- AC-21.a — ``AdapterSchema`` shape (tables / fields / capability flags).
- AC-21.b — ``fingerprint() = sha256:<hex>`` over canonical JSON.
- AC-21.d — ``classify_drift()`` severity rules (PM Q3 LOCKED).
- AC-21.g — ``SchemaFingerprintStore`` ack path.

Reuse anchors:
- ``nautilus/core/attestation_payload.py:58`` ``_stable_json``.
- ``nautilus/core/attestation_payload.py:69`` ``_sha256``.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal


@dataclass(frozen=True)
class AdapterField:
    """One field/column in an adapter's schema. AC-21.a."""

    name: str
    type: str
    nullable: bool
    description: str = ""


@dataclass(frozen=True)
class AdapterTable:
    """One table/collection in an adapter's schema. AC-21.a."""

    name: str
    fields: tuple[AdapterField, ...]
    indexes: tuple[str, ...] = ()
    primary_key: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdapterSchema:
    """Per-adapter schema fingerprint surface (AC-21.a + AC-21.b).

    Each adapter implements get_schema() differently (OQ3):
      - Postgres/pgvector: async information_schema query in connect() (cached)
      - Neo4j: async CALL db.schema.visualization() (cached)
      - Elasticsearch: GET _mapping (cached)
      - InfluxDB: SHOW MEASUREMENTS / SHOW TAG KEYS
      - REST: operator-declared via EndpointSpec; static at registration
      - ServiceNow: REST-derived (table API metadata)
      - S3: AdapterSchema.unknown() — buckets have no schema (capability flags only)

    All eight implementations produce the SAME AdapterSchema shape; fingerprint
    canonicalization is identical via _stable_json + _sha256
    (attestation_payload.py:58,69).

    Shared.md line 286-313.
    """

    adapter_id: str
    source_type: str
    tables: tuple[AdapterTable, ...]
    capability_flags: Mapping[str, bool]
    fetched_at: datetime

    @classmethod
    def unknown(cls, adapter_id: str, source_type: str) -> AdapterSchema:
        """Default for adapters without schema introspection (S3, legacy).

        AC-21 §Edge Cases. Shared.md line 309.
        """
        return cls(
            adapter_id=adapter_id,
            source_type=source_type,
            tables=(),
            capability_flags={},
            fetched_at=datetime.now(UTC),
        )

    def fingerprint(self) -> str:
        """``sha256:<hex>`` over ``_stable_json(self)``. AC-21.b.

        Reuses nautilus/core/attestation_payload.py:58 _stable_json
        and :69 _sha256. Shared.md line 311-313.
        """
        # reuse anchor :69
        from nautilus.core.attestation_payload import _sha256  # pyright: ignore[reportPrivateUsage]

        # Convert to a plain dict for stable serialisation.
        payload = dataclasses.asdict(self)
        return _sha256(payload)


@dataclass(frozen=True)
class SchemaDiffEntry:
    """One entry in a structured schema drift diff. AC-21.d + AC-21.e."""

    op: Literal["add", "remove", "change", "capability_toggle"]
    path: str
    from_value: Any | None
    to_value: Any | None
    severity: Literal["minor", "major"]


def classify_drift(previous: AdapterSchema, current: AdapterSchema) -> list[SchemaDiffEntry]:
    """Return drift entries between ``previous`` and ``current``.

    Severity rules (PM Q3 LOCKED, shared.md line 336-341):
    - minor: new optional field, new index, new capability flag set true
    - major: removed field, renamed field, type change, capability flag
      toggled false, primary-key change.

    Returns an empty list on no drift. AC-21.d.
    """
    entries: list[SchemaDiffEntry] = []

    prev_tables = {t.name: t for t in previous.tables}
    curr_tables = {t.name: t for t in current.tables}

    # Table-level: removed tables are major, added tables are minor.
    for name in prev_tables:
        if name not in curr_tables:
            entries.append(
                SchemaDiffEntry(
                    op="remove",
                    path=f"tables.{name}",
                    from_value=name,
                    to_value=None,
                    severity="major",
                )
            )

    for name in curr_tables:
        if name not in prev_tables:
            entries.append(
                SchemaDiffEntry(
                    op="add",
                    path=f"tables.{name}",
                    from_value=None,
                    to_value=name,
                    severity="minor",
                )
            )

    # Field-level drift within shared tables.
    for tname in prev_tables:
        if tname not in curr_tables:
            continue
        prev_fields = {f.name: f for f in prev_tables[tname].fields}
        curr_fields = {f.name: f for f in curr_tables[tname].fields}

        for fname in prev_fields:
            if fname not in curr_fields:
                entries.append(
                    SchemaDiffEntry(
                        op="remove",
                        path=f"tables.{tname}.{fname}",
                        from_value=prev_fields[fname].type,
                        to_value=None,
                        severity="major",
                    )
                )
            else:
                pf = prev_fields[fname]
                cf = curr_fields[fname]
                if pf.type != cf.type:
                    entries.append(
                        SchemaDiffEntry(
                            op="change",
                            path=f"tables.{tname}.{fname}.type",
                            from_value=pf.type,
                            to_value=cf.type,
                            severity="major",
                        )
                    )

        for fname in curr_fields:
            if fname not in prev_fields:
                # New optional field = minor.
                entries.append(
                    SchemaDiffEntry(
                        op="add",
                        path=f"tables.{tname}.{fname}",
                        from_value=None,
                        to_value=curr_fields[fname].type,
                        severity="minor",
                    )
                )

        # Index drift: new index = minor; removed index = major.
        prev_idx = set(prev_tables[tname].indexes)
        curr_idx = set(curr_tables[tname].indexes)
        for idx in curr_idx - prev_idx:
            entries.append(
                SchemaDiffEntry(
                    op="add",
                    path=f"tables.{tname}.indexes.{idx}",
                    from_value=None,
                    to_value=idx,
                    severity="minor",
                )
            )
        for idx in prev_idx - curr_idx:
            entries.append(
                SchemaDiffEntry(
                    op="remove",
                    path=f"tables.{tname}.indexes.{idx}",
                    from_value=idx,
                    to_value=None,
                    severity="major",
                )
            )

        # Primary-key change = major.
        if prev_tables[tname].primary_key != curr_tables[tname].primary_key:
            entries.append(
                SchemaDiffEntry(
                    op="change",
                    path=f"tables.{tname}.primary_key",
                    from_value=list(prev_tables[tname].primary_key),
                    to_value=list(curr_tables[tname].primary_key),
                    severity="major",
                )
            )

    # Capability flag drift.
    prev_flags = dict(previous.capability_flags)
    curr_flags = dict(current.capability_flags)

    for flag, val in curr_flags.items():
        if flag not in prev_flags:
            if val:
                # New flag set true = minor.
                entries.append(
                    SchemaDiffEntry(
                        op="capability_toggle",
                        path=f"capability_flags.{flag}",
                        from_value=None,
                        to_value=val,
                        severity="minor",
                    )
                )
            else:
                entries.append(
                    SchemaDiffEntry(
                        op="capability_toggle",
                        path=f"capability_flags.{flag}",
                        from_value=None,
                        to_value=val,
                        severity="major",
                    )
                )
        elif prev_flags[flag] != val:
            # Toggled false = major; toggled true = minor.
            severity: Literal["minor", "major"] = "major" if not val else "minor"
            entries.append(
                SchemaDiffEntry(
                    op="capability_toggle",
                    path=f"capability_flags.{flag}",
                    from_value=prev_flags[flag],
                    to_value=val,
                    severity=severity,
                )
            )

    for flag in prev_flags:
        if flag not in curr_flags:
            # Removed flag = major.
            entries.append(
                SchemaDiffEntry(
                    op="capability_toggle",
                    path=f"capability_flags.{flag}",
                    from_value=prev_flags[flag],
                    to_value=None,
                    severity="major",
                )
            )

    return entries


class SchemaFingerprintStore:
    """Persists ``(adapter_id, fingerprint, recorded_at)``.

    Primary state is in-memory (per Broker instance). Optional disk
    persistence writes to ``.nautilus/adapters/fingerprints/<adapter>.json``
    when ``root`` is provided.

    Operator ack writes a NEW tuple via :meth:`record_ack`. AC-21.c/g.
    """

    def __init__(self, root: str | None = None) -> None:
        self._store: dict[str, str] = {}
        self._root = root

    def get(self, adapter_id: str) -> str | None:
        """Return the last-recorded fingerprint for ``adapter_id``. AC-21.c."""
        return self._store.get(adapter_id)

    def record(self, adapter_id: str, fingerprint: str) -> None:
        """Persist a fingerprint at adapter-registration time. AC-21.c."""
        import json
        import os

        self._store[adapter_id] = fingerprint
        if self._root is not None:
            fp_dir = os.path.join(self._root, ".nautilus", "adapters", "fingerprints")
            os.makedirs(fp_dir, exist_ok=True)
            fp_path = os.path.join(fp_dir, f"{adapter_id}.json")
            with open(fp_path, "w") as fh:
                json.dump({"adapter_id": adapter_id, "fingerprint": fingerprint}, fh)

    def record_ack(
        self,
        adapter_id: str,
        fingerprint: str,
        *,
        reviewer: str,
        reason: str,
    ) -> None:
        """Operator-ack a drift event; updates the recorded fingerprint. AC-21.g."""
        import json
        import os
        from datetime import UTC, datetime

        self._store[adapter_id] = fingerprint
        if self._root is not None:
            fp_dir = os.path.join(self._root, ".nautilus", "adapters", "fingerprints")
            os.makedirs(fp_dir, exist_ok=True)
            fp_path = os.path.join(fp_dir, f"{adapter_id}.json")
            with open(fp_path, "w") as fh:
                json.dump(
                    {
                        "adapter_id": adapter_id,
                        "fingerprint": fingerprint,
                        "reviewer": reviewer,
                        "reason": reason,
                        "acked_at": datetime.now(UTC).isoformat(),
                    },
                    fh,
                )


__all__ = [
    "AdapterField",
    "AdapterSchema",
    "AdapterTable",
    "SchemaDiffEntry",
    "SchemaFingerprintStore",
    "classify_drift",
]
