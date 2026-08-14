"""The schema-drift gate can actually fire (AUDIT.md:558, AUDIT.md:824).

Two defects made drift detection inert end to end:

- ``_check_schema_fingerprints`` built a fresh ``SchemaFingerprintStore`` on
  every call, so ``get()`` always returned ``None``, every check read as a
  first registration, and the quarantine branch had no producer. The check
  also ran only over already-connected adapters, and connect is lazy, so at
  startup it examined nothing at all.
- ``AdapterSchema.fingerprint()`` hashed ``fetched_at``, so an unchanged
  schema fingerprinted differently on every fetch.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from nautilus import Broker
from nautilus.adapters.schema import (
    AdapterField,
    AdapterSchema,
    AdapterTable,
    SchemaFingerprintStore,
)
from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


def _schema(adapter_id: str, *, with_email: bool) -> AdapterSchema:
    fields: list[AdapterField] = [AdapterField(name="id", type="int", nullable=False)]
    if with_email:
        fields.append(AdapterField(name="email", type="text", nullable=True))
    return AdapterSchema(
        adapter_id=adapter_id,
        source_type="fake",
        tables=(AdapterTable(name="users", fields=tuple(fields)),),
        capability_flags={"deterministic": True},
        fetched_at=datetime.now(UTC),
    )


class _SchemaAdapter:
    """Fake adapter whose reported schema the test can change between calls."""

    source_type: str = "fake"

    def __init__(self, source_id: str) -> None:
        self._source_id = source_id
        self.with_email: bool = True
        self.schema_calls: int = 0

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
        self.schema_calls += 1
        return _schema(self._source_id, with_email=self.with_email)


def _broker(tmp_path: Path) -> tuple[Broker, _SchemaAdapter]:
    """Broker on the shared fixture config, rooted at ``tmp_path``."""
    cfg = tmp_path / "nautilus.yaml"
    cfg.write_text(
        FIXTURE_PATH.read_text(encoding="utf-8").replace(
            "path: ./audit.jsonl", f"path: {tmp_path / 'audit.jsonl'}"
        ),
        encoding="utf-8",
    )
    broker = Broker.from_config(cfg)
    adapter = _SchemaAdapter("nvd_db")
    broker._adapters = {"nvd_db": adapter}  # type: ignore[attr-defined]  # noqa: SLF001
    return broker, adapter


class TestFingerprintStability:
    def test_two_fetches_of_one_schema_agree(self) -> None:
        assert _schema("a", with_email=True).fingerprint() == (
            _schema("a", with_email=True).fingerprint()
        )

    def test_a_changed_schema_still_changes_the_fingerprint(self) -> None:
        assert _schema("a", with_email=True).fingerprint() != (
            _schema("a", with_email=False).fingerprint()
        )

    def test_the_adapter_id_is_still_part_of_the_identity(self) -> None:
        assert _schema("a", with_email=True).fingerprint() != (
            _schema("b", with_email=True).fingerprint()
        )


class TestFingerprintStorePersistence:
    def test_a_rooted_store_reads_a_baseline_written_by_a_previous_process(
        self, tmp_path: Path
    ) -> None:
        SchemaFingerprintStore(root=str(tmp_path)).record("pg", "sha256:abc")
        assert SchemaFingerprintStore(root=str(tmp_path)).get("pg") == "sha256:abc"

    def test_an_ack_is_visible_to_the_next_process(self, tmp_path: Path) -> None:
        SchemaFingerprintStore(root=str(tmp_path)).record_ack(
            "pg", "sha256:new", reviewer="alice", reason="evolved"
        )
        assert SchemaFingerprintStore(root=str(tmp_path)).get("pg") == "sha256:new"

    def test_an_unrooted_store_stays_in_memory(self, tmp_path: Path) -> None:
        SchemaFingerprintStore().record("pg", "sha256:abc")
        assert SchemaFingerprintStore(root=str(tmp_path)).get("pg") is None

    def test_an_id_that_names_a_path_is_refused(self, tmp_path: Path) -> None:
        # The id becomes a filename; a traversing id would put the baseline
        # somewhere the store does not own.
        store = SchemaFingerprintStore(root=str(tmp_path))
        with pytest.raises(ValueError, match="not usable as a fingerprint filename"):
            store.record("../../escaped", "sha256:abc")

    def test_a_corrupt_baseline_reads_as_absent(self, tmp_path: Path) -> None:
        fp_dir = tmp_path / ".nautilus" / "adapters" / "fingerprints"
        fp_dir.mkdir(parents=True)
        (fp_dir / "pg.json").write_text("{not json", encoding="utf-8")
        assert SchemaFingerprintStore(root=str(tmp_path)).get("pg") is None

    def test_a_baseline_missing_its_fingerprint_reads_as_absent(self, tmp_path: Path) -> None:
        fp_dir = tmp_path / ".nautilus" / "adapters" / "fingerprints"
        fp_dir.mkdir(parents=True)
        (fp_dir / "pg.json").write_text(json.dumps({"adapter_id": "pg"}), encoding="utf-8")
        assert SchemaFingerprintStore(root=str(tmp_path)).get("pg") is None


class TestBrokerDriftGate:
    @pytest.mark.asyncio
    async def test_the_first_check_records_a_baseline(self, tmp_path: Path) -> None:
        broker, adapter = _broker(tmp_path)
        await broker._check_adapter_schema("nvd_db", adapter)  # noqa: SLF001
        assert broker.fingerprint_store.get("nvd_db") is not None
        assert broker._quarantined_adapters == set()  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_an_unchanged_schema_does_not_quarantine(self, tmp_path: Path) -> None:
        broker, adapter = _broker(tmp_path)
        await broker._check_adapter_schema("nvd_db", adapter)  # noqa: SLF001
        quarantined = await broker._check_adapter_schema("nvd_db", adapter)  # noqa: SLF001
        assert quarantined is False
        assert broker._quarantined_adapters == set()  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_a_dropped_column_quarantines_the_adapter(self, tmp_path: Path) -> None:
        broker, adapter = _broker(tmp_path)
        await broker._check_adapter_schema("nvd_db", adapter)  # noqa: SLF001
        adapter.with_email = False
        quarantined = await broker._check_adapter_schema("nvd_db", adapter)  # noqa: SLF001
        assert quarantined is True
        assert broker._quarantined_adapters == {"nvd_db"}  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_drift_is_audited(self, tmp_path: Path) -> None:
        broker, adapter = _broker(tmp_path)
        await broker._check_adapter_schema("nvd_db", adapter)  # noqa: SLF001
        adapter.with_email = False
        await broker._check_adapter_schema("nvd_db", adapter)  # noqa: SLF001
        # The Nautilus entry rides inside the fathom record's metadata.
        entries = [
            json.loads(json.loads(line)["metadata"][NAUTILUS_METADATA_KEY])
            for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        assert [e for e in entries if e.get("event_type") == "schema_drift_detected"]

    @pytest.mark.asyncio
    async def test_a_schema_fetch_failure_does_not_quarantine(self, tmp_path: Path) -> None:
        broker, adapter = _broker(tmp_path)

        async def _boom() -> AdapterSchema:
            raise RuntimeError("upstream down")

        adapter.get_schema = _boom  # type: ignore[method-assign]
        quarantined = await broker._check_adapter_schema("nvd_db", adapter)  # noqa: SLF001
        assert quarantined is False
        assert broker._quarantined_adapters == set()  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_drift_survives_a_restart(self, tmp_path: Path) -> None:
        # The baseline is on disk under the config directory, so a second
        # broker over the same config still sees the drift.
        broker, adapter = _broker(tmp_path)
        await broker._check_adapter_schema("nvd_db", adapter)  # noqa: SLF001

        restarted, adapter2 = _broker(tmp_path)
        adapter2.with_email = False
        quarantined = await restarted._check_adapter_schema("nvd_db", adapter2)  # noqa: SLF001
        assert quarantined is True

    @pytest.mark.asyncio
    async def test_an_operator_ack_clears_the_gate(self, tmp_path: Path) -> None:
        broker, adapter = _broker(tmp_path)
        await broker._check_adapter_schema("nvd_db", adapter)  # noqa: SLF001
        adapter.with_email = False
        await broker._check_adapter_schema("nvd_db", adapter)  # noqa: SLF001

        broker.fingerprint_store.record_ack(
            "nvd_db",
            (await adapter.get_schema()).fingerprint(),
            reviewer="alice",
            reason="column intentionally dropped",
        )
        restarted, adapter2 = _broker(tmp_path)
        adapter2.with_email = False
        assert await restarted._check_adapter_schema("nvd_db", adapter2) is False  # noqa: SLF001


class TestDriftGateOnTheRequestPath:
    @pytest.mark.asyncio
    async def test_lazy_connect_runs_the_check(self, tmp_path: Path) -> None:
        # setup() sees zero connected adapters because connect is lazy; the
        # check has to happen where the adapter is first reachable.
        broker, adapter = _broker(tmp_path)
        await broker.setup()
        assert adapter.schema_calls == 0

        await broker.arequest(
            agent_id="a1",
            intent="find vulnerabilities",
            context={"clearance": "unclassified", "purpose": "threat-analysis"},
        )
        assert adapter.schema_calls == 1

    @pytest.mark.asyncio
    async def test_a_drifted_adapter_does_not_serve_the_request_that_found_it(
        self, tmp_path: Path
    ) -> None:
        broker, adapter = _broker(tmp_path)
        ctx = {"clearance": "unclassified", "purpose": "threat-analysis"}
        await broker.arequest(agent_id="a1", intent="find vulnerabilities", context=ctx)

        # Drift arrives, and the broker restarts: connect is fresh again.
        restarted, adapter2 = _broker(tmp_path)
        adapter2.with_email = False
        response = await restarted.arequest(
            agent_id="a1", intent="find vulnerabilities", context=ctx
        )
        errors = {e.source_id: e.error_type for e in response.sources_errored}
        assert errors["nvd_db"] == "ADAPTER_QUARANTINED"
        assert response.sources_queried == []
