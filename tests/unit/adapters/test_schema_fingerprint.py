"""Unit tests for :mod:`nautilus.adapters.schema` (#21, AC-21.a/b/d)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nautilus.adapters.schema import (
    AdapterField,
    AdapterSchema,
    AdapterTable,
    SchemaDiffEntry,
    classify_drift,
)

pytestmark = pytest.mark.unit


def _make_schema(*, with_email: bool = True) -> AdapterSchema:
    fields = [AdapterField(name="id", type="int", nullable=False)]
    if with_email:
        fields.append(AdapterField(name="email", type="text", nullable=True))
    return AdapterSchema(
        adapter_id="postgres-1",
        source_type="postgres",
        tables=(AdapterTable(name="users", fields=tuple(fields)),),
        capability_flags={"deterministic": True},
        fetched_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def test_ac_21_b_fingerprint_is_sha256_prefixed_and_stable() -> None:
    s1 = _make_schema()
    s2 = _make_schema()
    fp1 = s1.fingerprint()
    fp2 = s2.fingerprint()
    assert fp1.startswith("sha256:")
    assert fp1 == fp2


def test_ac_21_b_fingerprint_changes_on_field_diff() -> None:
    s_full = _make_schema(with_email=True)
    s_partial = _make_schema(with_email=False)
    assert s_full.fingerprint() != s_partial.fingerprint()


def test_ac_21_d_added_optional_field_is_minor() -> None:
    previous = _make_schema(with_email=False)
    current = _make_schema(with_email=True)
    diff = classify_drift(previous, current)
    assert len(diff) >= 1
    assert all(isinstance(entry, SchemaDiffEntry) for entry in diff)
    severities = {entry.severity for entry in diff}
    assert "minor" in severities


def test_ac_21_d_removed_field_is_major() -> None:
    previous = _make_schema(with_email=True)
    current = _make_schema(with_email=False)
    diff = classify_drift(previous, current)
    severities = {entry.severity for entry in diff}
    assert "major" in severities


def test_ac_21_a_unknown_returns_default_schema() -> None:
    schema = AdapterSchema.unknown("s3-1", "s3")
    assert schema.adapter_id == "s3-1"
    assert schema.source_type == "s3"
    assert schema.tables == ()


def test_ac_21_d_no_diff_returns_empty_list() -> None:
    s1 = _make_schema()
    s2 = _make_schema()
    assert classify_drift(s1, s2) == []
