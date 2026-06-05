"""Integration: schema drift severity classification + quarantine (#21 AC-21.d-g)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from nautilus.adapters.schema import (
    AdapterField,
    AdapterSchema,
    AdapterTable,
    SchemaFingerprintStore,
    classify_drift,
)

pytestmark = pytest.mark.integration


def _schema(*, with_email: bool) -> AdapterSchema:
    fields: list[AdapterField] = [AdapterField(name="id", type="int", nullable=False)]
    if with_email:
        fields.append(AdapterField(name="email", type="text", nullable=True))
    return AdapterSchema(
        adapter_id="postgres-int",
        source_type="postgres",
        tables=(AdapterTable(name="users", fields=tuple(fields)),),
        capability_flags={"deterministic": True},
        fetched_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def test_ac_21_c_fingerprint_recorded_at_first_registration(tmp_path: Path) -> None:
    store = SchemaFingerprintStore()
    fp = _schema(with_email=True).fingerprint()
    assert store.get("postgres-int") is None
    store.record("postgres-int", fp)
    assert store.get("postgres-int") == fp


def test_ac_21_d_major_drift_returns_major_entry() -> None:
    previous = _schema(with_email=True)
    current = _schema(with_email=False)
    diff = classify_drift(previous, current)
    assert any(entry.severity == "major" for entry in diff)


def test_ac_21_g_record_ack_updates_recorded_fingerprint(tmp_path: Path) -> None:
    store = SchemaFingerprintStore()
    old = _schema(with_email=True).fingerprint()
    new = _schema(with_email=False).fingerprint()
    store.record("postgres-int", old)
    store.record_ack(
        "postgres-int",
        new,
        reviewer="alice@example.com",
        reason="schema-evolved",
    )
    assert store.get("postgres-int") == new
