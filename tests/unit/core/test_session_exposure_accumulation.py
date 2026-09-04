"""Cumulative session exposure reaches the engine.

:meth:`FathomRouter._assert_session` reads six session slots --
``data_types_seen``, ``sources_visited``, ``pii_sources_accessed_list``,
``pii_sources_accessed``, ``purpose_start_ts`` and ``purpose_ttl_seconds`` --
and ``_update_session`` wrote none of them; it persisted only
``last_request_id`` and ``last_sources_queried``, which no rule reads. Every
request therefore asserted zero ``session_exposure`` facts, so cross-request
aggregation policy saw nothing accumulate, and the shipped
``purpose-expired-deny`` rule (temporal.yaml, salience 250) was loaded but
could never fire.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from nautilus.adapters.schema import AdapterSchema
from nautilus.config.models import SourceConfig
from nautilus.core.broker import Broker
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint
from nautilus.core.session import SessionStore

pytestmark = pytest.mark.unit

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


class _Adapter:
    source_type = "fake"

    def __init__(self, source_id: str) -> None:
        self._source_id = source_id

    async def connect(self, config: SourceConfig) -> None:
        del config

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        return AdapterResult(source_id=self._source_id, rows=[{"id": 1}], duration_ms=0)

    async def close(self) -> None:
        return None

    async def get_schema(self) -> AdapterSchema:
        return AdapterSchema.unknown(self._source_id, self.source_type)


def _broker(config_path: Path = FIXTURE_PATH) -> Broker:
    broker = Broker.from_config(config_path)
    ids = [s.id for s in broker.sources]
    broker._adapters = {sid: _Adapter(sid) for sid in ids}  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = set(ids)  # type: ignore[attr-defined]  # noqa: SLF001
    return broker


def _ctx(purpose: str = "threat-analysis") -> dict[str, Any]:
    return {
        "clearance": "unclassified",
        "purpose": purpose,
        "session_id": "s1",
        "embedding": [0.1, 0.2, 0.3],
    }


async def _session(broker: Broker, session_id: str = "s1") -> dict[str, Any]:
    """Read persisted session state.

    ``_session_get`` picks the sync or async store surface; the tests need the
    same resolution, and the broker exposes no public read.
    """
    return await broker._session_get(session_id)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


async def _session_after(n: int, *, config_path: Path = FIXTURE_PATH) -> dict[str, Any]:
    broker = _broker(config_path)
    try:
        for _ in range(n):
            await broker.arequest("a1", "find vulnerabilities", _ctx())
        return await _session(broker)
    finally:
        await broker.aclose()


class TestExposureIsPersisted:
    async def test_sources_visited_accumulates(self) -> None:
        state = await _session_after(1)
        assert sorted(state["sources_visited"]) == ["internal_vulns", "nvd_db"]

    async def test_data_types_seen_accumulates_from_queried_sources(self) -> None:
        state = await _session_after(1)
        # The union of both fixture sources' declared data_types.
        assert sorted(state["data_types_seen"]) == [
            "cve",
            "patch",
            "scan_result",
            "vulnerability",
        ]

    async def test_repeated_requests_do_not_duplicate_entries(self) -> None:
        state = await _session_after(3)
        assert sorted(state["sources_visited"]) == ["internal_vulns", "nvd_db"]

    async def test_non_pii_sources_leave_the_pii_counter_at_zero(self) -> None:
        state = await _session_after(1)
        assert state["pii_sources_accessed_list"] == []
        assert state["pii_sources_accessed"] == 0


class TestExposureReachesTheEngine:
    """The point of persisting: request N+1's working memory carries it.

    Counted off the router directly -- ``RouteResult.facts_asserted_summary``
    is derived from what ``_assert`` actually pushed into the engine, so this
    cannot pass on bookkeeping alone.
    """

    @staticmethod
    async def _exposure_counts(n: int) -> list[int]:
        broker = _broker()
        counts: list[int] = []
        real_route = broker._router.route  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

        def spy(**kwargs: Any) -> Any:
            result = real_route(**kwargs)
            counts.append(result.facts_asserted_summary.get("session_exposure", 0))
            return result

        broker._router.route = spy  # noqa: SLF001  # pyright: ignore[reportPrivateUsage, reportAttributeAccessIssue]
        try:
            for _ in range(n):
                await broker.arequest("a1", "find vulnerabilities", _ctx())
        finally:
            await broker.aclose()
        return counts

    async def test_first_request_asserts_none(self) -> None:
        """An empty session yields zero exposure facts (NFR-5 back-compat)."""
        assert await self._exposure_counts(1) == [0]

    async def test_the_second_request_sees_the_first_request_exposure(self) -> None:
        counts = await self._exposure_counts(2)
        assert counts[0] == 0
        # 2 sources visited + 4 distinct data types across them.
        assert counts[1] == 6


class TestPurposeTTL:
    @staticmethod
    def _config_with_ttl(tmp_path: Path, ttl: int) -> Path:
        text = FIXTURE_PATH.read_text(encoding="utf-8")
        text += f"\nsession_store:\n  backend: memory\n  purpose_ttl_seconds: {ttl}\n"
        dst = tmp_path / "nautilus.yaml"
        dst.write_text(text, encoding="utf-8")
        return dst

    async def test_window_is_not_written_when_the_ttl_is_disabled(self) -> None:
        state = await _session_after(1)
        assert "purpose_ttl_seconds" not in state

    async def test_window_opens_on_the_first_request(self, tmp_path: Path) -> None:
        state = await _session_after(1, config_path=self._config_with_ttl(tmp_path, 3600))
        assert state["purpose_ttl_seconds"] == 3600.0
        assert state["purpose_start_ts"] > 0

    async def test_window_does_not_restart_on_the_same_purpose(self, tmp_path: Path) -> None:
        cfg = self._config_with_ttl(tmp_path, 3600)
        broker = _broker(cfg)
        try:
            await broker.arequest("a1", "find vulnerabilities", _ctx())
            first_start = (await _session(broker))["purpose_start_ts"]
            await broker.arequest("a1", "find vulnerabilities", _ctx())
            second_start = (await _session(broker))["purpose_start_ts"]
        finally:
            await broker.aclose()
        assert first_start == second_start

    async def test_a_new_purpose_restarts_the_window(self, tmp_path: Path) -> None:
        cfg = self._config_with_ttl(tmp_path, 3600)
        broker = _broker(cfg)
        try:
            await broker.arequest("a1", "find vulnerabilities", _ctx("threat-analysis"))
            first_start = (await _session(broker))["purpose_start_ts"]
            await broker.arequest("a1", "find vulnerabilities", _ctx("incident-response"))
            state = await _session(broker)
        finally:
            await broker.aclose()
        assert state["purpose"] == "incident-response"
        assert state["purpose_start_ts"] >= first_start

    async def test_an_elapsed_purpose_window_denies_the_request(self, tmp_path: Path) -> None:
        """The rule that could never fire, firing."""
        cfg = self._config_with_ttl(tmp_path, 1)
        broker = _broker(cfg)
        try:
            await broker.arequest("a1", "find vulnerabilities", _ctx())
            # Age the window past its TTL without sleeping.
            state = await _session(broker)
            store = broker.session_store
            assert isinstance(store, SessionStore)
            store.update("s1", {"purpose_start_ts": state["purpose_start_ts"] - 3600})
            resp = await broker.arequest("a1", "find vulnerabilities", _ctx())
        finally:
            await broker.aclose()
        assert sorted(resp.sources_denied) == ["internal_vulns", "nvd_db"]
        assert resp.sources_queried == []
