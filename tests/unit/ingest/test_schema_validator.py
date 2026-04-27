"""Unit tests for :class:`SchemaValidator` (Task 26, AC-4.1 / AC-4.4 / AC-4.5 / FR-13).

These tests pin the compile-once / validate-each contract consumed by the
Phase-5 ingest orchestrator (Task 30) and the REST adapter wire-up:

* (a) ``compile()`` loads the JSON-Schema document (from a filesystem path
  or a registered ``<scheme>://`` secret reference), compiles a
  ``Draft202012Validator``, and caches it on the instance.
* (b) ``validate()`` partitions rows into ``(ok_rows, violations)`` where
  each violation is a ``(row, reason)`` tuple with a human-readable reason.
* (c) The orchestrator stub ``_validate_ingest_integrity`` returns rows
  unchanged — full pipeline lands in Task 30.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import pytest

from nautilus.ingest.config import IngestIntegrityConfig
from nautilus.ingest.validator import (
    IngestValidators,
    SchemaValidator,
    _validate_ingest_integrity,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


_PERSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer", "minimum": 0},
    },
    "required": ["name", "age"],
    "additionalProperties": False,
}


@pytest.fixture
def schema_file(tmp_path: Path) -> Path:
    """Write the person schema out to ``tmp_path`` and return the path."""
    p = tmp_path / "person.json"
    p.write_text(json.dumps(_PERSON_SCHEMA))
    return p


# ---------------------------------------------------------------------------
# (a) compile() happy path.
# ---------------------------------------------------------------------------


async def test_compile_happy_path(schema_file: Path) -> None:
    """AC-4.1: ``compile()`` loads from a filesystem path and validates rows."""
    validator = SchemaValidator(str(schema_file))
    await validator.compile()

    ok, violations = validator.validate([{"name": "alice", "age": 30}])

    assert ok == [{"name": "alice", "age": 30}]
    assert violations == []


async def test_validate_partitions_valid_and_invalid_rows(schema_file: Path) -> None:
    """AC-4.4/AC-4.5: ``validate()`` returns ``(ok_rows, [(row, reason), ...])``."""
    validator = SchemaValidator(str(schema_file))
    await validator.compile()

    rows: list[dict[str, Any]] = [
        {"name": "alice", "age": 30},
        {"name": "bob", "age": -1},  # fails minimum
        {"name": "carol", "age": 25},
    ]

    ok, violations = validator.validate(rows)

    assert ok == [
        {"name": "alice", "age": 30},
        {"name": "carol", "age": 25},
    ]
    assert len(violations) == 1
    bad_row, reason = violations[0]
    assert bad_row == {"name": "bob", "age": -1}
    assert isinstance(reason, str)
    assert reason  # non-empty human-readable message


async def test_validate_reports_multiple_violation_kinds(schema_file: Path) -> None:
    """Different failure modes (type, missing, extra) each surface a reason string."""
    validator = SchemaValidator(str(schema_file))
    await validator.compile()

    rows: list[dict[str, Any]] = [
        {"age": 30},  # missing 'name'
        {"name": "eve", "age": "old"},  # wrong type
        {"name": "mallory", "age": 20, "nickname": "m"},  # extra property
    ]

    ok, violations = validator.validate(rows)

    assert ok == []
    assert len(violations) == 3
    for row, reason in violations:
        assert isinstance(row, dict)
        assert isinstance(reason, str)
        assert reason


async def test_compile_caches_on_first_call(schema_file: Path) -> None:
    """``compile()`` twice reuses the compiled validator (identity check)."""
    validator = SchemaValidator(str(schema_file))
    await validator.compile()
    first = validator._validator  # pyright: ignore[reportPrivateUsage]

    await validator.compile()
    second = validator._validator  # pyright: ignore[reportPrivateUsage]

    assert first is second


async def test_validate_before_compile_raises(schema_file: Path) -> None:
    """Calling ``validate()`` prior to ``compile()`` is a programmer error."""
    validator = SchemaValidator(str(schema_file))

    with pytest.raises(RuntimeError):
        validator.validate([{"name": "alice", "age": 30}])


# ---------------------------------------------------------------------------
# (b) schema loading — filesystem path + env://VAR via SecretProvider.
# ---------------------------------------------------------------------------


async def test_schema_from_filesystem_path(tmp_path: Path) -> None:
    """A bare filesystem path (no scheme) loads the schema document directly."""
    schema = {
        "type": "object",
        "properties": {"id": {"type": "integer"}},
        "required": ["id"],
    }
    path = tmp_path / "s.json"
    path.write_text(json.dumps(schema))

    validator = SchemaValidator(str(path))
    await validator.compile()

    ok, violations = validator.validate([{"id": 7}, {"id": "nope"}])
    assert ok == [{"id": 7}]
    assert len(violations) == 1


class _InlineJSONProvider:
    """Test-double :class:`SecretProvider` that returns a canned JSON blob."""

    scheme: ClassVar[str] = "env"

    def __init__(self, payload: str) -> None:
        self._payload = payload

    async def get(self, ref: str) -> str:
        return self._payload


async def test_schema_from_secret_reference_via_resolver() -> None:
    """``env://``/``vault://`` refs resolve through the injected ``SecretProvider``."""
    schema = {
        "type": "object",
        "properties": {"n": {"type": "integer"}},
        "required": ["n"],
    }
    provider = _InlineJSONProvider(json.dumps(schema))

    validator = SchemaValidator("env://NAUT_TEST_SCHEMA", resolver=provider)
    await validator.compile()

    ok, violations = validator.validate([{"n": 1}, {"n": "bad"}])
    assert ok == [{"n": 1}]
    assert len(violations) == 1


async def test_schema_ref_with_scheme_without_resolver_raises() -> None:
    """A ``<scheme>://`` reference without a resolver is a config error."""
    validator = SchemaValidator("env://NAUT_TEST_SCHEMA")

    with pytest.raises(ValueError):
        await validator.compile()


# ---------------------------------------------------------------------------
# (c) _validate_ingest_integrity orchestrator — minimal happy-path smoke.
# Full multi-step coverage lives in test_rest_ingest.py (Task 30).
# ---------------------------------------------------------------------------


async def test_orchestrator_minimal_happy_path_returns_valid_rows(
    schema_file: Path,
) -> None:
    """With only a schema validator + valid rows, the orchestrator is a pass-through."""
    cfg = IngestIntegrityConfig.model_validate({"schema": str(schema_file)})
    schema_validator = SchemaValidator(str(schema_file))
    await schema_validator.compile()
    validators = IngestValidators(schema_validator=schema_validator)

    rows: list[dict[str, Any]] = [{"name": "alice", "age": 30}]
    out = await _validate_ingest_integrity(
        rows,
        cfg,
        source_id="nautobot",
        validators=validators,
        audit=None,
    )
    assert out == rows
