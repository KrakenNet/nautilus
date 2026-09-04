"""The audit entry tells the truth about what the request did.

Three defects, all in what the canonical entry for a request records
(AUDIT.md:847, 870, 902):

- A failure after attestation signing emitted ``attestation_token=None``,
  so the entry denied a token that had already been signed and shipped.
- Two ``routing_decision`` facts for one source executed the adapter twice
  and duplicated the id in the signed ``sources_queried`` claim.
- ``AdapterError`` / ``ScopeEnforcementError`` records reached the log with
  ``trace_id=""`` despite the code's own "filled in by caller" contract.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from nautilus import Broker
from nautilus.adapters.base import AdapterError, ScopeEnforcementError
from nautilus.adapters.schema import AdapterSchema
from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, RoutingDecision, ScopeConstraint

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"
CTX: dict[str, Any] = {"clearance": "unclassified", "purpose": "threat-analysis"}


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


class _FakeAdapter:
    """Counts executions; optionally raises a chosen error type."""

    source_type: str = "fake"

    def __init__(self, source_id: str, raises: BaseException | None = None) -> None:
        self._source_id = source_id
        self._raises = raises
        self.calls: int = 0

    async def connect(self, config: SourceConfig) -> None:
        del config

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return AdapterResult(source_id=self._source_id, rows=[{"id": 1}], duration_ms=0)

    async def close(self) -> None:
        return None

    async def get_schema(self) -> AdapterSchema:
        return AdapterSchema.unknown(self._source_id, self.source_type)


def _broker(tmp_path: Path) -> Broker:
    cfg = tmp_path / "nautilus.yaml"
    cfg.write_text(
        FIXTURE_PATH.read_text(encoding="utf-8").replace(
            "path: ./audit.jsonl", f"path: {tmp_path / 'audit.jsonl'}"
        ),
        encoding="utf-8",
    )
    return Broker.from_config(cfg)


def _audit_entries(tmp_path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(json.loads(line)["metadata"][NAUTILUS_METADATA_KEY])
        for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]


class TestDuplicateRoutingDecisions:
    """Two rules routing one source must not query it twice."""

    @staticmethod
    def _duplicate_route(broker: Broker, source_id: str) -> None:
        real_route = broker._router.route  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

        def _route(**kwargs: Any) -> Any:
            result = real_route(**kwargs)
            extra = [
                RoutingDecision(source_id=rd.source_id, reason="org policy")
                for rd in result.routing_decisions
                if rd.source_id == source_id
            ]
            result.routing_decisions = list(result.routing_decisions) + extra
            return result

        broker._router.route = _route  # type: ignore[method-assign]  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_the_adapter_runs_once_per_source(self, tmp_path: Path) -> None:
        broker = _broker(tmp_path)
        fake = _FakeAdapter("nvd_db")
        broker._adapters = {"nvd_db": fake}  # type: ignore[attr-defined]  # noqa: SLF001
        self._duplicate_route(broker, "nvd_db")

        await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=dict(CTX))
        assert fake.calls == 1

    @pytest.mark.asyncio
    async def test_the_source_is_claimed_once(self, tmp_path: Path) -> None:
        broker = _broker(tmp_path)
        broker._adapters = {"nvd_db": _FakeAdapter("nvd_db")}  # type: ignore[attr-defined]  # noqa: SLF001
        self._duplicate_route(broker, "nvd_db")

        response = await broker.arequest(
            agent_id="a1", intent="find vulnerabilities", context=dict(CTX)
        )
        assert response.sources_queried == ["nvd_db"]

    @pytest.mark.asyncio
    async def test_the_audit_entry_claims_it_once(self, tmp_path: Path) -> None:
        broker = _broker(tmp_path)
        broker._adapters = {"nvd_db": _FakeAdapter("nvd_db")}  # type: ignore[attr-defined]  # noqa: SLF001
        self._duplicate_route(broker, "nvd_db")

        await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=dict(CTX))
        entry = next(e for e in _audit_entries(tmp_path) if e.get("event_type") == "request")
        assert entry["sources_queried"] == ["nvd_db"]

    @pytest.mark.asyncio
    async def test_a_single_routing_decision_is_unaffected(self, tmp_path: Path) -> None:
        broker = _broker(tmp_path)
        fake = _FakeAdapter("nvd_db")
        broker._adapters = {"nvd_db": fake}  # type: ignore[attr-defined]  # noqa: SLF001

        response = await broker.arequest(
            agent_id="a1", intent="find vulnerabilities", context=dict(CTX)
        )
        assert fake.calls == 1
        assert response.sources_queried == ["nvd_db"]


class TestErrorRecordCorrelation:
    @pytest.mark.asyncio
    async def test_an_adapter_error_carries_the_request_id(self, tmp_path: Path) -> None:
        broker = _broker(tmp_path)
        broker._adapters = {  # type: ignore[attr-defined]  # noqa: SLF001
            "nvd_db": _FakeAdapter("nvd_db", AdapterError("pg down"))  # pyright: ignore[reportAttributeAccessIssue]
        }
        response = await broker.arequest(
            agent_id="a1", intent="find vulnerabilities", context=dict(CTX)
        )
        record = next(e for e in response.sources_errored if e.source_id == "nvd_db")
        assert record.error_type == "AdapterError"
        assert record.trace_id == response.request_id

    @pytest.mark.asyncio
    async def test_a_scope_error_carries_the_request_id(self, tmp_path: Path) -> None:
        broker = _broker(tmp_path)
        broker._adapters = {  # type: ignore[attr-defined]  # noqa: SLF001
            "nvd_db": _FakeAdapter("nvd_db", ScopeEnforcementError("unsupported operator"))  # pyright: ignore[reportAttributeAccessIssue]
        }
        response = await broker.arequest(
            agent_id="a1", intent="find vulnerabilities", context=dict(CTX)
        )
        record = next(e for e in response.sources_errored if e.source_id == "nvd_db")
        assert record.error_type == "ScopeEnforcementError"
        assert record.trace_id == response.request_id

    @pytest.mark.asyncio
    async def test_typed_and_untyped_errors_agree(self, tmp_path: Path) -> None:
        # The untyped path always filled trace_id; the typed one did not, so
        # one request's entry mixed correlated and uncorrelated rows.
        broker = _broker(tmp_path)
        broker._adapters = {  # type: ignore[attr-defined]  # noqa: SLF001
            "nvd_db": _FakeAdapter("nvd_db", AdapterError("pg down")),
            "internal_vulns": _FakeAdapter("internal_vulns", RuntimeError("boom")),
        }
        response = await broker.arequest(
            agent_id="a1", intent="find vulnerabilities", context=dict(CTX)
        )
        assert {e.trace_id for e in response.sources_errored} == {response.request_id}

    @pytest.mark.asyncio
    async def test_the_audit_entry_is_correlated_too(self, tmp_path: Path) -> None:
        broker = _broker(tmp_path)
        broker._adapters = {  # type: ignore[attr-defined]  # noqa: SLF001
            "nvd_db": _FakeAdapter("nvd_db", AdapterError("pg down"))  # pyright: ignore[reportAttributeAccessIssue]
        }
        await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=dict(CTX))
        entry = next(e for e in _audit_entries(tmp_path) if e.get("event_type") == "request")
        assert {r["trace_id"] for r in entry["error_records"]} == {entry["request_id"]}


class TestAttestationOnLateFailure:
    @pytest.mark.asyncio
    async def test_a_signed_token_is_recorded_even_when_the_session_write_fails(
        self, tmp_path: Path
    ) -> None:
        broker = _broker(tmp_path)
        broker._adapters = {"nvd_db": _FakeAdapter("nvd_db")}  # type: ignore[attr-defined]  # noqa: SLF001

        def _boom(session_id: str, entry: dict[str, Any]) -> None:
            raise OSError("session store write failed")

        broker._session_store.update = _boom  # type: ignore[method-assign]  # noqa: SLF001

        with pytest.raises(OSError, match="session store write failed"):
            await broker.arequest(
                agent_id="a1",
                intent="find vulnerabilities",
                context={**CTX, "session_id": "s1"},
            )

        entry = next(e for e in _audit_entries(tmp_path) if e.get("event_type") == "request")
        assert entry["attestation_token"] is not None
        assert "OSError" in [r["error_type"] for r in entry["error_records"]]

    @pytest.mark.asyncio
    async def test_a_failure_before_signing_still_records_no_token(self, tmp_path: Path) -> None:
        # Nothing was signed, so the entry must not claim otherwise.
        broker = _broker(tmp_path)

        def _boom(**kwargs: Any) -> Any:
            raise RuntimeError("router exploded")

        broker._router.route = _boom  # type: ignore[method-assign]  # noqa: SLF001

        with pytest.raises(RuntimeError, match="router exploded"):
            await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=dict(CTX))

        entry = next(e for e in _audit_entries(tmp_path) if e.get("event_type") == "request")
        assert entry["attestation_token"] is None
