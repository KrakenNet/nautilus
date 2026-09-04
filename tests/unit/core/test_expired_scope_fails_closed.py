"""An expired scope grant must not be more permissive than a live one.

A :class:`ScopeConstraint` is a restriction, and the adapter fan-out reads an
empty scope list as "no restrictions". Dropping an expired constraint and
still querying the source therefore *widened* access: while the grant was
live the adapter got ``[('dept','=','eng')]`` and returned one row; once it
expired the adapter got ``[]`` and returned every row the constraint existed
to hide, with ``sources_denied`` empty so nothing flagged it.

The source is now denied for the request instead. Both channels that can
carry ``expires_at`` are covered: ``context["scope_constraints"]``
(broker.py ``_merge_context_scope_constraints``) and constraints emitted by a
rule (``scope_constraint`` carries an ``expires_at`` slot).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from nautilus.adapters.schema import AdapterSchema
from nautilus.config.models import SourceConfig
from nautilus.core.broker import Broker
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

pytestmark = pytest.mark.unit

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"

ROWS = [
    {"id": 1, "dept": "eng", "note": "public roadmap"},
    {"id": 2, "dept": "hr", "note": "SALARY 250000"},
    {"id": 3, "dept": "hr", "note": "SSN 123-45-6789"},
]

PAST = "2020-01-01T00:00:00Z"
FUTURE = "2999-01-01T00:00:00Z"
MALFORMED = "2026-13-01T00:00:00Z"


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


class _ScopeHonouringAdapter:
    """Applies the scope it is handed, exactly as ``PostgresAdapter._build_sql``
    does: no constraints means no WHERE clause, hence every row."""

    source_type = "fake"

    def __init__(self, source_id: str) -> None:
        self._source_id = source_id
        self.scopes_seen: list[list[ScopeConstraint]] = []

    async def connect(self, config: SourceConfig) -> None:
        del config

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, context
        self.scopes_seen.append(list(scope))
        rows = [
            row
            for row in ROWS
            if all(row.get(str(c.field)) == c.value for c in scope if c.operator == "=")
        ]
        return AdapterResult(source_id=self._source_id, rows=rows, duration_ms=0)

    async def close(self) -> None:
        return None

    async def get_schema(self) -> AdapterSchema:
        return AdapterSchema.unknown(self._source_id, self.source_type)


def _broker_with_fake(source_id: str) -> tuple[Broker, _ScopeHonouringAdapter]:
    broker = Broker.from_config(FIXTURE_PATH)
    adapter = _ScopeHonouringAdapter(source_id)
    broker._adapters = {source_id: adapter}  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = {source_id}  # type: ignore[attr-defined]  # noqa: SLF001
    return broker, adapter


def _ctx(expires_at: str | None) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "clearance": "unclassified",
        "purpose": "threat-analysis",
        "session_id": "s1",
        "embedding": [0.1, 0.2, 0.3],
    }
    if expires_at is not None:
        ctx["scope_constraints"] = [
            ScopeConstraint(
                source_id="nvd_db",
                field="dept",
                operator="=",
                value="eng",
                expires_at=expires_at,
            )
        ]
    return ctx


async def _request(expires_at: str | None) -> tuple[Any, _ScopeHonouringAdapter]:
    broker, adapter = _broker_with_fake("nvd_db")
    try:
        resp = await broker.arequest("a1", "find vulnerabilities", _ctx(expires_at))
    finally:
        await broker.aclose()
    return resp, adapter


class TestLiveGrantStillWorks:
    async def test_live_constraint_restricts_the_rows(self) -> None:
        resp, adapter = await _request(FUTURE)
        assert adapter.scopes_seen and [c.field for c in adapter.scopes_seen[0]] == ["dept"]
        assert resp.data["nvd_db"] == [ROWS[0]]
        assert resp.sources_queried == ["nvd_db"]
        assert resp.sources_denied == []


class TestExpiredGrantDeniesInsteadOfWidening:
    @pytest.mark.parametrize("expires_at", [PAST, MALFORMED])
    async def test_source_is_not_queried(self, expires_at: str) -> None:
        resp, adapter = await _request(expires_at)
        assert adapter.scopes_seen == [], "adapter ran with a dropped constraint"
        assert resp.sources_queried == []

    @pytest.mark.parametrize("expires_at", [PAST, MALFORMED])
    async def test_no_hidden_rows_reach_the_caller(self, expires_at: str) -> None:
        resp, _ = await _request(expires_at)
        assert resp.data.get("nvd_db", []) == []

    @pytest.mark.parametrize("expires_at", [PAST, MALFORMED])
    async def test_the_denial_is_reported_not_just_recorded(self, expires_at: str) -> None:
        resp, _ = await _request(expires_at)
        assert "nvd_db" in resp.sources_denied

    @pytest.mark.parametrize("expires_at", [PAST, MALFORMED])
    async def test_expired_is_never_more_permissive_than_live(self, expires_at: str) -> None:
        """The property the bug violated, stated directly."""
        live, _ = await _request(FUTURE)
        expired, _ = await _request(expires_at)
        live_rows = {r["id"] for r in live.data.get("nvd_db", [])}
        expired_rows = {r["id"] for r in expired.data.get("nvd_db", [])}
        assert expired_rows <= live_rows


class TestNoConstraintIsUnaffected:
    async def test_a_request_with_no_scope_constraints_still_queries(self) -> None:
        resp, adapter = await _request(None)
        assert resp.sources_queried == ["nvd_db"]
        assert adapter.scopes_seen == [[]]
        assert resp.sources_denied == []
