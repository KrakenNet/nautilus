"""The REST governance routes write the decision they made.

Companion to ``tests/unit/rkm/test_governance_audit.py``, which covers the CLI
side. ``POST /v1/rkm/queue/{id}/approve|reject`` and
``POST /v1/rules/{name}/retract|rollback`` all passed ``audit_logger=None``
while ``docs/concepts/rkm-lifecycle.md`` said the reviewer identity "lands in
the audit trail" — the serving broker owned a sink the whole time and no route
reached for it.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fathom.audit import FileSink
from starlette.testclient import TestClient

from nautilus.audit.logger import NAUTILUS_METADATA_KEY, AuditLogger
from nautilus.rkm.lineage import LineageRecord, LineageStore
from nautilus.rkm.queue import ProposalQueue
from nautilus.rkm.types import Proposal
from nautilus.transport.fastapi_app import create_app

pytestmark = pytest.mark.unit

API_KEY = "topsecret"
REVIEWER = "alice@example.com"
HEADERS = {"X-API-Key": API_KEY, "X-Nautilus-Reviewer": REVIEWER}


def _types(audit_log: Path) -> list[str]:
    if not audit_log.is_file():
        return []
    out: list[str] = []
    for line in audit_log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line).get("metadata", {}).get(NAUTILUS_METADATA_KEY)
        if payload is not None:
            out.append(str(json.loads(payload).get("event_type")))
    return out


def _broker(audit_log: Path) -> Any:
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()
    store = MagicMock()
    store.aget = AsyncMock(return_value=None)
    broker.session_store = store
    broker.sources = []
    broker.arequest = AsyncMock()
    broker.audit_logger = AuditLogger(sink=FileSink(path=audit_log))
    broker._config = SimpleNamespace(  # noqa: SLF001
        api=SimpleNamespace(auth=SimpleNamespace(mode="api_key"), keys=[API_KEY]),
        audit=SimpleNamespace(path=str(audit_log)),
    )
    return broker


def _proposal() -> Proposal:
    return Proposal(
        proposal_id="prop_gov",
        schema_version=2,
        status="pending",
        proposer="pipeline",
        proposed_at=datetime.now(UTC),
        target_module="curator",
        artifact_type="rule",
        artifact={"name": "gov_probe", "version": 1, "yaml": "rules: []"},
        validation={"confidence": 0.9},
        lineage={"derived_from": None},
        decisions=[],
    )


def _record(version: int = 1) -> LineageRecord:
    return LineageRecord(
        rule_name="gov_probe",
        version=version,
        proposer="pipeline",
        observation_ids={},
        sandbox_results={},
        approver=REVIEWER,
        derived_from=(),
        promoted_at=datetime.now(UTC),
    )


@pytest.fixture()
def audit_log(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture()
def client(tmp_path: Path, audit_log: Path) -> Iterator[TestClient]:
    app = create_app(None, existing_broker=_broker(audit_log))
    c = TestClient(app)
    c.__enter__()
    queue = ProposalQueue(tmp_path / "queue")
    queue.submit(_proposal())
    app.state.proposal_queue = queue
    lineage = LineageStore(tmp_path / "lineage")
    lineage.insert(_record(1))
    lineage.insert(_record(2))
    app.state.lineage_store = lineage
    try:
        yield c
    finally:
        c.__exit__(None, None, None)


def test_approve_is_recorded(client: TestClient, audit_log: Path) -> None:
    resp = client.post("/v1/rkm/queue/prop_gov/approve", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    assert _types(audit_log) == ["proposal_approved"]


def test_reject_is_recorded(client: TestClient, audit_log: Path) -> None:
    resp = client.post(
        "/v1/rkm/queue/prop_gov/reject", headers=HEADERS, json={"reason": "too broad"}
    )
    assert resp.status_code == 200, resp.text
    assert _types(audit_log) == ["proposal_rejected"]


def test_retract_is_recorded(client: TestClient, audit_log: Path) -> None:
    resp = client.post(
        "/v1/rules/gov_probe/retract",
        headers=HEADERS,
        json={"reason": "superseded", "yes": True},
    )
    assert resp.status_code == 200, resp.text
    assert _types(audit_log) == ["rule_retracted"]


def test_rollback_is_recorded_and_still_appends(client: TestClient, audit_log: Path) -> None:
    resp = client.post(
        "/v1/rules/gov_probe/rollback",
        headers=HEADERS,
        json={"to_version": 1, "reason": "v2 regressed", "yes": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["new_version"] == 3
    assert body["record"]["version"] == 3
    assert _types(audit_log) == ["rule_rolled_back"]


def test_rolling_back_to_a_missing_version_is_a_404(client: TestClient, audit_log: Path) -> None:
    resp = client.post(
        "/v1/rules/gov_probe/rollback",
        headers=HEADERS,
        json={"to_version": 9, "reason": "typo", "yes": True},
    )
    assert resp.status_code == 404
    assert _types(audit_log) == []
