"""Regressions for adapter scope translation that silently changed the predicate.

A scope constraint is a policy decision. Three adapters altered or discarded
one without saying so:

- S3 stringified an ``IN`` list, so ``tag.owner IN ['alice','bob']`` became a
  substring test against ``"['alice', 'bob']"`` and a tag value of ``li``
  passed. An empty tag value passed every IN filter.
- InfluxDB ran ``_time`` constraints through a range lift that handled only
  <, <=, >, >= and BETWEEN, then hit an unconditional ``continue``: ``=``,
  ``!=``, ``IN``, ``NOT IN``, ``LIKE`` and ``IS NULL`` produced the same Flux
  as an unconstrained request, leaving the -30d default window.
- InfluxDB stripped every ``%`` from a LIKE pattern and always emitted
  ``containsStr``, so the anchored ``public/%`` also matched
  ``internal/restricted/public/leak``.
- Postgres and pgvector split the table name on ``.`` and kept the last
  segment, dropping the schema qualifier: ``restricted.customers`` queried
  whatever ``search_path`` resolved ``customers`` to.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from nautilus.adapters.base import ScopeEnforcementError
from nautilus.adapters.influxdb import InfluxDBAdapter
from nautilus.adapters.pgvector import PgVectorAdapter
from nautilus.adapters.postgres import PostgresAdapter
from nautilus.adapters.s3 import S3Adapter, _tag_operand
from nautilus.core.models import ScopeConstraint

pytestmark = pytest.mark.unit


def _scope(field: str, operator: str, value: Any) -> ScopeConstraint:
    return ScopeConstraint(source_id="s", field=field, operator=operator, value=value)


# ---------------------------------------------------------------------------
# S3 tag IN
# ---------------------------------------------------------------------------


class TestS3TagInIsExactMembership:
    @staticmethod
    async def _matches(tag_value: str, members: list[str]) -> bool:
        adapter = S3Adapter()
        client = AsyncMock()
        client.get_object_tagging.return_value = {"TagSet": [{"Key": "owner", "Value": tag_value}]}
        adapter._client = client  # noqa: SLF001
        adapter._bucket = "b"  # noqa: SLF001
        return await adapter._matches_tags(  # noqa: SLF001
            "k", [("owner", "IN", _tag_operand("IN", members))]
        )

    @pytest.mark.parametrize("tag_value", ["li", "a", "carol", "", "ce', 'b"])
    async def test_a_non_member_is_rejected(self, tag_value: str) -> None:
        assert await self._matches(tag_value, ["alice", "bob"]) is False

    @pytest.mark.parametrize("tag_value", ["alice", "bob"])
    async def test_a_member_is_accepted(self, tag_value: str) -> None:
        assert await self._matches(tag_value, ["alice", "bob"]) is True

    async def test_a_bare_string_is_one_member_not_a_character_sequence(self) -> None:
        assert await self._matches("alice", ["alice"]) is True
        assert await self._matches("a", ["alice"]) is False

    def test_a_non_sequence_value_is_rejected(self) -> None:
        with pytest.raises(ScopeEnforcementError, match="requires a list"):
            _tag_operand("IN", 42)


# ---------------------------------------------------------------------------
# InfluxDB _time
# ---------------------------------------------------------------------------


def _flux(scope: list[ScopeConstraint]) -> str:
    return InfluxDBAdapter(client=AsyncMock())._build_flux("b", scope, 100)  # noqa: SLF001


class TestInfluxTimeConstraintsAreNeverDropped:
    @pytest.mark.parametrize("op", ["=", "!=", "IN", "NOT IN", "LIKE", "IS NULL"])
    def test_an_unliftable_operator_raises(self, op: str) -> None:
        value = ["2020-01-01T00:00:00Z"] if op in ("IN", "NOT IN") else "2020-01-01T00:00:00Z"
        with pytest.raises(ScopeEnforcementError, match="not expressible as a time range"):
            _flux([_scope("_time", op, value)])

    @pytest.mark.parametrize(("op", "expected"), [(">=", "start"), ("<=", "stop")])
    def test_range_operators_still_lift(self, op: str, expected: str) -> None:
        flux = _flux([_scope("_time", op, "2024-01-01T00:00:00Z")])
        assert f'{expected}: "2024-01-01T00:00:00Z"' in flux

    def test_between_still_lifts_both_bounds(self) -> None:
        flux = _flux([_scope("_time", "BETWEEN", ["2024-01-01T00:00:00Z", "2024-02-01T00:00:00Z"])])
        assert 'start: "2024-01-01T00:00:00Z"' in flux
        assert 'stop: "2024-02-01T00:00:00Z"' in flux

    def test_the_default_window_is_the_thing_a_dropped_constraint_left_behind(self) -> None:
        """Documents what the silent drop produced, so the contrast is explicit."""
        assert "range(start: -30d, stop: now())" in _flux([])


class TestInfluxLikeKeepsItsAnchoring:
    def test_a_prefix_pattern_stays_anchored_at_the_front(self) -> None:
        assert 'strings.hasPrefix(v: r["path"], prefix: "public/")' in _flux(
            [_scope("path", "LIKE", "public/%")]
        )

    def test_a_suffix_pattern_stays_anchored_at_the_end(self) -> None:
        assert 'strings.hasSuffix(v: r["path"], suffix: ".log")' in _flux(
            [_scope("path", "LIKE", "%.log")]
        )

    def test_a_doubly_wildcarded_pattern_is_a_substring_test(self) -> None:
        assert 'strings.containsStr(v: r["path"], substr: "public/")' in _flux(
            [_scope("path", "LIKE", "%public/%")]
        )

    def test_a_pattern_with_no_wildcard_is_equality(self) -> None:
        assert 'r["path"] == "exact"' in _flux([_scope("path", "LIKE", "exact")])

    def test_the_single_character_wildcard_raises_rather_than_matching_nothing(self) -> None:
        with pytest.raises(ScopeEnforcementError, match="single-character"):
            _flux([_scope("path", "LIKE", "web_1")])

    def test_an_interior_wildcard_raises(self) -> None:
        with pytest.raises(ScopeEnforcementError, match="interior"):
            _flux([_scope("path", "LIKE", "a%b")])


# ---------------------------------------------------------------------------
# Schema-qualified table names
# ---------------------------------------------------------------------------


class TestSchemaQualifierSurvives:
    def test_postgres_keeps_the_schema(self) -> None:
        sql, _ = PostgresAdapter()._build_sql(  # noqa: SLF001
            "restricted.customers", [_scope("region", "=", "eu")], 1000
        )
        assert 'FROM "restricted"."customers"' in sql

    def test_postgres_still_handles_a_bare_name(self) -> None:
        sql, _ = PostgresAdapter()._build_sql("customers", [], 1000)  # noqa: SLF001
        assert 'FROM "customers"' in sql

    def test_pgvector_keeps_the_schema(self) -> None:
        sql, _ = PgVectorAdapter()._build_vector_sql(  # noqa: SLF001
            table="restricted.customers",
            embedding_column="emb",
            metadata_column="meta",
            distance_operator="<=>",
            embedding=[0.1, 0.2],
            top_k=5,
            scope=[],
        )
        assert 'FROM "restricted"."customers"' in sql

    def test_a_double_qualifier_is_rejected(self) -> None:
        with pytest.raises(ScopeEnforcementError, match="more than one schema qualifier"):
            PostgresAdapter()._build_sql("a.b.c", [], 10)  # noqa: SLF001

    def test_an_injection_attempt_in_the_schema_is_rejected(self) -> None:
        with pytest.raises(ScopeEnforcementError):
            PostgresAdapter()._build_sql('x"; DROP TABLE y; --.customers', [], 10)  # noqa: SLF001
