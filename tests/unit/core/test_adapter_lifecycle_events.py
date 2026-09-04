"""Adapter lifecycle events have producers, and quarantine can be lifted.

Three defects, one root: the audit vocabulary declared adapter events nobody
wrote (UPSTREAM.md:212 found this for ``relationship_observed``; the same
grep shows ``adapter_quarantined``, ``adapter_unquarantined`` and
``schema_drift_severity_overridden``).

- Quarantining an adapter emitted ``schema_drift_detected`` and nothing else,
  so the log recorded the drift but never the decision it caused.
- Every adapter-scoped entry left all six source lists empty, so the entry
  did not name the adapter it was about.
- ``_quarantined_adapters`` is in-memory and nothing ever removed an entry,
  while the error the caller received said "acknowledge drift via schema-ack
  before resuming". An ack re-baselines on disk; the running broker stayed
  quarantined until restart, so the instruction was false.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, get_args

import pytest

from nautilus import Broker
from nautilus.adapters.base import Adapter
from nautilus.adapters.schema import AdapterField, AdapterSchema, AdapterTable
from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterEventType, AdapterResult, AuditEntry, IntentAnalysis
from nautilus.core.models import ScopeConstraint as _ScopeConstraint

pytestmark = pytest.mark.unit

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"
CTX = {"clearance": "unclassified", "purpose": "threat-analysis"}


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


class _SchemaAdapter:
    """Adapter whose reported schema the test can change between requests."""

    source_type: ClassVar[str] = "fake"

    def __init__(self, source_id: str) -> None:
        self._source_id = source_id
        self.with_email: bool = True
        self.schema_raises: bool = False

    async def connect(self, config: SourceConfig) -> None:
        del config

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[_ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        return AdapterResult(source_id=self._source_id, rows=[{"id": 1}], duration_ms=0)

    async def close(self) -> None:
        return None

    async def get_schema(self) -> AdapterSchema:
        if self.schema_raises:
            raise RuntimeError("upstream down")
        fields = [AdapterField(name="id", type="int", nullable=False)]
        if self.with_email:
            fields.append(AdapterField(name="email", type="text", nullable=True))
        return AdapterSchema(
            adapter_id=self._source_id,
            source_type="fake",
            tables=(AdapterTable(name="users", fields=tuple(fields)),),
            capability_flags={"deterministic": True},
            fetched_at=datetime.now(UTC),
        )


def _broker(tmp_path: Path) -> tuple[Broker, _SchemaAdapter]:
    cfg = tmp_path / "nautilus.yaml"
    cfg.write_text(
        FIXTURE_PATH.read_text(encoding="utf-8").replace(
            "path: ./audit.jsonl", f"path: {tmp_path / 'audit.jsonl'}"
        ),
        encoding="utf-8",
    )
    broker = Broker.from_config(cfg)
    adapter = _SchemaAdapter("nvd_db")
    registry: dict[str, Adapter] = {"nvd_db": adapter}
    broker._adapters = registry  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    return broker, adapter


def _events(tmp_path: Path) -> list[dict[str, Any]]:
    """Every Nautilus audit entry written under ``tmp_path``, in order."""
    log = tmp_path / "audit.jsonl"
    if not log.exists():
        return []
    return [
        json.loads(json.loads(line)["metadata"][NAUTILUS_METADATA_KEY])
        for line in log.read_text(encoding="utf-8").splitlines()
    ]


def _errors(response: Any) -> dict[str, str]:
    """``source_id -> error_type``; the fixture config declares more than one
    source and only ``nvd_db`` has an adapter registered."""
    return {e.source_id: e.error_type for e in response.sources_errored}


def _adapter_events(tmp_path: Path) -> list[tuple[str, str | None]]:
    return [
        (e["event_type"], e.get("adapter_id"))
        for e in _events(tmp_path)
        if e.get("event_type") in set(get_args(AdapterEventType))
    ]


class TestQuarantineIsAudited:
    async def test_drift_records_both_the_drift_and_the_quarantine(self, tmp_path: Path) -> None:
        broker, _adapter = _broker(tmp_path)
        await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=CTX)

        restarted, adapter2 = _broker(tmp_path)
        adapter2.with_email = False
        await restarted.arequest(agent_id="a1", intent="find vulnerabilities", context=CTX)

        assert _adapter_events(tmp_path) == [
            ("schema_drift_detected", "nvd_db"),
            ("adapter_quarantined", "nvd_db"),
        ]

    async def test_a_clean_adapter_records_nothing(self, tmp_path: Path) -> None:
        broker, _adapter = _broker(tmp_path)
        await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=CTX)
        assert _adapter_events(tmp_path) == []


class TestAnAckResumesTheRunningBroker:
    @staticmethod
    async def _quarantine(tmp_path: Path) -> tuple[Broker, _SchemaAdapter]:
        """Drive one broker to a quarantined state and return it."""
        seed, _ = _broker(tmp_path)
        await seed.arequest(agent_id="a1", intent="find vulnerabilities", context=CTX)

        broker, adapter = _broker(tmp_path)
        adapter.with_email = False
        response = await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=CTX)
        assert _errors(response)["nvd_db"] == "ADAPTER_QUARANTINED"
        return broker, adapter

    async def test_the_next_request_serves_again_without_a_restart(self, tmp_path: Path) -> None:
        broker, adapter = await self._quarantine(tmp_path)

        # What `nautilus adapters schema-ack` writes.
        broker.fingerprint_store.record_ack(
            "nvd_db",
            (await adapter.get_schema()).fingerprint(),
            reviewer="alice",
            reason="column intentionally dropped",
        )

        response = await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=CTX)
        assert "nvd_db" not in _errors(response)
        assert "nvd_db" in response.sources_queried
        assert _adapter_events(tmp_path)[-1] == ("adapter_unquarantined", "nvd_db")

    async def test_without_an_ack_it_stays_quarantined(self, tmp_path: Path) -> None:
        broker, _adapter = await self._quarantine(tmp_path)
        response = await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=CTX)
        assert _errors(response)["nvd_db"] == "ADAPTER_QUARANTINED"
        assert ("adapter_unquarantined", "nvd_db") not in _adapter_events(tmp_path)

    async def test_an_unreachable_adapter_stays_quarantined(self, tmp_path: Path) -> None:
        broker, adapter = await self._quarantine(tmp_path)
        broker.fingerprint_store.record_ack(
            "nvd_db",
            (await adapter.get_schema()).fingerprint(),
            reviewer="alice",
            reason="acked",
        )
        adapter.schema_raises = True
        response = await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=CTX)
        # An adapter that cannot be re-checked must not be assumed clean.
        assert _errors(response)["nvd_db"] == "ADAPTER_QUARANTINED"

    async def test_a_lifted_quarantine_can_be_re_entered(self, tmp_path: Path) -> None:
        broker, adapter = await self._quarantine(tmp_path)
        broker.fingerprint_store.record_ack(
            "nvd_db",
            (await adapter.get_schema()).fingerprint(),
            reviewer="alice",
            reason="acked",
        )
        await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=CTX)

        adapter.with_email = True  # drifts again, away from the acked baseline
        broker._connected_adapters.discard("nvd_db")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        response = await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=CTX)
        assert _errors(response)["nvd_db"] == "ADAPTER_QUARANTINED"


class TestTheEventVocabulary:
    def test_adapter_events_are_declared_on_the_entry(self) -> None:
        # Two Literals for one vocabulary; this is how they stay one.
        annotation = AuditEntry.model_fields["event_type"].annotation
        declared: set[str] = set()
        for member in get_args(annotation):
            declared.update(get_args(member))
        assert set(get_args(AdapterEventType)) <= declared

    def test_every_adapter_event_carries_the_adapter_id(self, tmp_path: Path) -> None:
        broker, _adapter = _broker(tmp_path)
        for event_type in get_args(AdapterEventType):
            broker.emit_adapter_event(event_type, "nvd_db")
        assert _adapter_events(tmp_path) == [(e, "nvd_db") for e in get_args(AdapterEventType)]


class TestTheAckIsAudited:
    """`nautilus adapters schema-ack` overrides a fail-closed decision.

    An override of an audited decision that is itself unaudited leaves the log
    saying the adapter drifted and never saying anyone accepted it.
    """

    def test_schema_ack_records_the_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import argparse

        from nautilus.cli import adapters as cli_adapters

        # The CLI builds its own broker from the config; hand it the fake
        # adapter the fixture config's `nvd_db` entry stands for.
        real_from_config = Broker.from_config

        def _from_config(path: Any, **kwargs: Any) -> Broker:
            built = real_from_config(path, **kwargs)
            registry: dict[str, Adapter] = {"nvd_db": _SchemaAdapter("nvd_db")}
            built._adapters = registry  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            return built

        _broker(tmp_path)  # writes the config with the tmp audit path
        monkeypatch.setattr(Broker, "from_config", staticmethod(_from_config))
        monkeypatch.setenv("NAUTILUS_REVIEWER", "alice@example.com")

        rc = cli_adapters.dispatch(
            argparse.Namespace(
                cmd="adapters",
                adapters_subcommand="schema-ack",
                name="nvd_db",
                config=str(tmp_path / "nautilus.yaml"),
                reason="column intentionally dropped",
                yes=True,
            )
        )
        assert rc == 0
        assert _adapter_events(tmp_path) == [("schema_drift_severity_overridden", "nvd_db")]
