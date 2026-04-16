"""Unit tests for :class:`nautilus.Broker` (Tasks 1.16 + 3.11).

Scope:
- Task 1.16 Done-when (original):
  * ``Broker.from_config`` wires every Phase-1 collaborator without raising.
  * ``broker.request()`` inside a running event loop raises ``RuntimeError``
    whose message mentions ``arequest`` (UQ-4, AC-8.5).
  * ``broker.close()`` / ``aclose()`` is idempotent (FR-17, AC-8.6).
- Task 3.11 additions:
  * AC-8.5 nested-loop detection mentions ``arequest`` (explicit).
  * AC-8.6 ``close()`` idempotency when called twice (explicit).
  * UQ-2 attestation token is present on successful response.
  * ``attestation.enabled=false`` → token is ``None``.
  * FR-18 one adapter raising does not break the others.
  * NFR-3 concurrent adapter execution — two sleep-instrumented adapters
    overlap (wall time ~max, not sum).
  * AC-1.5 no public ``broker.reload`` API in Phase 1.
  * AC-8.7 no public ``broker.query`` API in Phase 1.

End-to-end pipeline behaviour against real adapters lives in
``tests/integration/test_mvp_e2e.py`` (Task 1.17).
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest

from nautilus import Broker, BrokerResponse
from nautilus.adapters.base import Adapter, AdapterError
from nautilus.config.models import SourceConfig
from nautilus.core.broker import Broker as CoreBroker
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nautilus.yaml"


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide dummy DSNs so the config interpolator does not fail.

    Adapters are constructed but never ``connect()``-ed here; the DSN
    values just need to be non-empty strings.
    """
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


# ---------------------------------------------------------------------------
# Fake adapter helpers (Task 3.11 cases c/d/e/f)
# ---------------------------------------------------------------------------


class _FakeAdapter:
    """Minimal :class:`Adapter` Protocol impl returning configured rows or raising.

    Optionally sleeps inside ``execute`` so the concurrency test (NFR-3) can
    measure wall-clock overlap between two adapters.
    """

    source_type: str = "fake"

    def __init__(
        self,
        source_id: str,
        *,
        rows: list[dict[str, Any]] | None = None,
        raises: type[BaseException] | None = None,
        sleep_for: float = 0.0,
    ) -> None:
        self._source_id = source_id
        self._rows = rows if rows is not None else [{"id": 1}]
        self._raises = raises
        self._sleep_for = sleep_for
        self.connected: bool = False
        self.closed: bool = False

    async def connect(self, config: SourceConfig) -> None:
        del config
        self.connected = True

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        if self._sleep_for > 0:
            await asyncio.sleep(self._sleep_for)
        if self._raises is not None:
            raise self._raises(f"fake_adapter {self._source_id} configured to raise")
        return AdapterResult(
            source_id=self._source_id,
            rows=list(self._rows),
            duration_ms=0,
        )

    async def close(self) -> None:
        self.closed = True


def _install_fakes(broker: Broker, fakes: dict[str, _FakeAdapter]) -> None:
    """Swap the broker's real adapters for fakes and mark them connected.

    Reaching into ``_adapters`` / ``_connected_adapters`` is intentional:
    unit tests avoid spinning up a Postgres container, and the broker has
    no public DI surface for adapters in Phase 1 (design §3.1 —
    ``from_config`` is the sole wiring path).
    """
    # ``_adapters``/``_connected_adapters`` are private but stable; see
    # ``nautilus/core/broker.py``. Accessing via ``object.__setattr__`` keeps
    # strict type-checkers happy without a public setter.
    broker._adapters = dict(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = set(fakes.keys())  # type: ignore[attr-defined]  # noqa: SLF001


def _ctx() -> dict[str, Any]:
    """Baseline request context that routes to both nautilus.yaml sources."""
    return {
        "clearance": "unclassified",
        "purpose": "threat-analysis",
        "session_id": "s1",
        "embedding": [0.1, 0.2, 0.3],
    }


def _write_attestation_disabled_yaml(tmp_path: Path) -> Path:
    """Write a nautilus.yaml clone under ``tmp_path`` with ``attestation.enabled=false``."""
    src = FIXTURE_PATH.read_text(encoding="utf-8")
    dst_text = src.replace("enabled: true", "enabled: false")
    assert "enabled: false" in dst_text, "sed replacement must land"
    dst = tmp_path / "nautilus.yaml"
    dst.write_text(dst_text, encoding="utf-8")
    return dst


# ---------------------------------------------------------------------------
# Task 1.16 tests (kept verbatim)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_from_config_returns_broker() -> None:
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        assert isinstance(broker, Broker)
        # Same class identity whether imported from package root or core.
        assert isinstance(broker, CoreBroker)
        # Sources surface via the public ``sources`` property — exactly
        # the two entries in the fixture.
        source_ids = [s.id for s in broker.sources]
        assert source_ids == ["nvd_db", "internal_vulns"]
    finally:
        broker.close()


@pytest.mark.unit
def test_request_inside_running_loop_raises_runtime_error() -> None:
    """Sync request called inside an event loop must raise pointing at arequest (UQ-4, AC-8.5)."""
    broker = Broker.from_config(FIXTURE_PATH)

    async def _caller() -> None:
        with pytest.raises(RuntimeError, match=r"arequest"):
            broker.request(agent_id="agent-1", intent="ignored", context={})

    try:
        asyncio.run(_caller())
    finally:
        broker.close()


@pytest.mark.unit
def test_close_is_idempotent() -> None:
    """AC-8.6: calling ``close()`` twice must not raise."""
    broker = Broker.from_config(FIXTURE_PATH)
    broker.close()
    # Second close must not raise.
    broker.close()


@pytest.mark.unit
async def test_aclose_is_idempotent() -> None:
    broker = Broker.from_config(FIXTURE_PATH)
    await broker.aclose()
    await broker.aclose()


@pytest.mark.unit
def test_broker_response_reexport_is_pydantic_model() -> None:
    """Top-level ``BrokerResponse`` import is the Pydantic model from core.models."""
    # Construct a minimal instance to prove it is the real class.
    resp = BrokerResponse(
        request_id="req-1",
        data={},
        sources_queried=[],
        sources_denied=[],
        sources_skipped=[],
        sources_errored=[],
        scope_restrictions={},
        attestation_token=None,
        duration_ms=0,
    )
    assert resp.request_id == "req-1"


# ---------------------------------------------------------------------------
# Task 3.11 additions
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_fake_adapter_implements_adapter_protocol() -> None:
    """Sanity: our test double satisfies the runtime-checkable ``Adapter`` Protocol."""
    fake = _FakeAdapter("x")
    assert isinstance(fake, Adapter)


@pytest.mark.unit
async def test_attestation_token_present_on_success(tmp_path: Path) -> None:
    """UQ-2: a successful request with attestation enabled returns a signed token."""
    broker = Broker.from_config(FIXTURE_PATH)
    # Route audit writes to tmp_path so we don't pollute the repo root.
    # The broker was already constructed with the fixture audit path, but
    # the test never reads audit output — the sink's file handle is fine
    # to let point at the default path under tmp_path via monkeypatch.chdir.
    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db", rows=[{"id": 1, "cve": "CVE-0"}]),
                "internal_vulns": _FakeAdapter("internal_vulns", rows=[{"id": 2}]),
            },
        )
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
        assert resp.attestation_token is not None, "UQ-2 requires a signed token"
        assert isinstance(resp.attestation_token, str)
        assert resp.attestation_token, "token must be non-empty"
    finally:
        await broker.aclose()
    # tmp_path reference kept for potential future audit assertions.
    del tmp_path


@pytest.mark.unit
async def test_attestation_disabled_returns_none_token(tmp_path: Path) -> None:
    """``attestation.enabled=false`` → ``BrokerResponse.attestation_token`` is ``None``."""
    config_path = _write_attestation_disabled_yaml(tmp_path)
    broker = Broker.from_config(config_path)
    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db"),
                "internal_vulns": _FakeAdapter("internal_vulns"),
            },
        )
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
        assert resp.attestation_token is None
    finally:
        await broker.aclose()


@pytest.mark.unit
async def test_one_adapter_raising_does_not_break_others() -> None:
    """FR-18: a raising adapter surfaces as ``sources_errored``; peers still return data."""
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db", raises=AdapterError),
                "internal_vulns": _FakeAdapter(
                    "internal_vulns",
                    rows=[{"id": 42, "cve": "CVE-OK"}],
                ),
            },
        )
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
        # The surviving adapter returned rows.
        assert resp.sources_queried == ["internal_vulns"]
        assert resp.data["internal_vulns"], "surviving adapter must still return rows"
        # The failing adapter is reported under ``sources_errored``.
        errored_ids = [e.source_id for e in resp.sources_errored]
        assert "nvd_db" in errored_ids
        assert any(e.error_type == "AdapterError" for e in resp.sources_errored)
    finally:
        await broker.aclose()


@pytest.mark.unit
async def test_adapters_run_concurrently() -> None:
    """NFR-3: two sleep-instrumented adapters overlap ≥50% of their durations.

    Patch both adapters to ``await asyncio.sleep(0.1)``. With concurrent
    execution wall time should be ~0.1s, not 0.2s; we assert a 0.15s
    ceiling which leaves a 50% margin for slow CI.
    """
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        sleep_s = 0.1
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db", sleep_for=sleep_s),
                "internal_vulns": _FakeAdapter("internal_vulns", sleep_for=sleep_s),
            },
        )
        started = time.perf_counter()
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
        elapsed = time.perf_counter() - started
        assert set(resp.sources_queried) == {"nvd_db", "internal_vulns"}, (
            f"both sources must succeed; got {resp.sources_queried!r} "
            f"errored={resp.sources_errored!r}"
        )
        # Concurrent: elapsed should be much less than 2*sleep_s.
        # Sequential lower bound would be 0.2s; we assert <0.15s (i.e. the
        # overlap is at least 50% of the per-adapter duration).
        assert elapsed < 2 * sleep_s - (sleep_s / 2), (
            f"adapters appear to have run sequentially: elapsed={elapsed:.3f}s "
            f"(expected < {2 * sleep_s - sleep_s / 2:.3f}s for ≥50% overlap)"
        )
    finally:
        await broker.aclose()


@pytest.mark.unit
def test_no_public_reload_api() -> None:
    """AC-1.5: ``Broker.reload`` is deferred beyond Phase 1."""
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        assert not hasattr(broker, "reload")
    finally:
        broker.close()


@pytest.mark.unit
def test_no_public_query_api() -> None:
    """AC-8.7: ``Broker.query`` is deferred to Phase 2."""
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        assert not hasattr(broker, "query")
    finally:
        broker.close()
