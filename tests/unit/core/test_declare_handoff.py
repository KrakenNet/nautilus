"""Task 3.5 unit coverage for :meth:`Broker.declare_handoff`.

Seven locked cases (design §3.6, FR-8/FR-10, AC-4.1–AC-4.5):

(a) Allow branch — receiving clearance dominates declared classification.
(b) Deny branch — default ``information-flow-violation`` rule fires when
    the receiver's clearance fails to dominate the declared classification
    (AC-4.3).
(c) Escalate branch — the :class:`HandoffDecision` model accepts
    ``action="escalate"`` as a first-class outcome so user escalation-pack
    rules can map a denial to an escalation without a schema migration.
    The default rule set never produces this value (AC-4.3 note); this
    test pins the schema contract.
(d) Unknown receiving agent → ``HandoffDecision(action="deny",
    denial_records[0].rule_name="unknown-agent")`` (AC-4.2).
(e) Exactly one audit entry written per ``declare_handoff`` call (AC-4.4).
(f) 50 concurrent calls via :func:`asyncio.gather` produce 50 distinct
    ``handoff_id`` values (AC-4.5).
(g) Zero adapter calls — ``declare_handoff`` is a policy-only path and must
    never reach an :class:`Adapter` (AC-4.1, FR-8).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from nautilus import Broker
from nautilus.adapters.base import Adapter
from nautilus.core.models import HandoffDecision

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dummy DSNs so config interpolation succeeds (no adapter is connected)."""
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


def _write_yaml_with_agents(
    tmp_path: Path,
    *,
    source_clearance: str,
    receiver_clearance: str,
    audit_path: Path | None = None,
) -> Path:
    """Clone the test fixture YAML and inject ``agents`` + audit path overrides."""
    src = FIXTURE_PATH.read_text(encoding="utf-8")
    audit_target = audit_path if audit_path is not None else tmp_path / "audit.jsonl"
    # Replace the default audit path so test assertions never touch the repo root.
    src = src.replace("./audit.jsonl", str(audit_target).replace("\\", "/"))
    agents_block = (
        "\nagents:\n"
        f"  agent-source:\n    id: agent-source\n    clearance: {source_clearance}\n"
        f"  agent-receiver:\n    id: agent-receiver\n    clearance: {receiver_clearance}\n"
    )
    dst = tmp_path / "nautilus.yaml"
    dst.write_text(src + agents_block, encoding="utf-8")
    return dst


def _install_mock_adapters(broker: Broker) -> dict[str, AsyncMock]:
    """Replace the broker's adapters with :class:`AsyncMock` instances.

    Returns the mock dict so assertions can check ``.execute.call_count`` /
    ``.query.call_count`` — any non-zero call indicates a regression where
    ``declare_handoff`` accidentally touched the adapter path (AC-4.1).
    """
    mocks: dict[str, AsyncMock] = {}
    for source_id in ("nvd_db", "internal_vulns"):
        m = AsyncMock(spec=Adapter, name=f"adapter_{source_id}")
        mocks[source_id] = m
    broker._adapters = dict(mocks)  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = set(mocks.keys())  # type: ignore[attr-defined]  # noqa: SLF001
    return mocks


def _read_audit_lines(audit_path: Path) -> list[dict[str, Any]]:
    """Load JSONL audit entries from ``audit_path`` (empty list if missing)."""
    if not audit_path.exists():
        return []
    raw = audit_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in raw if line.strip()]


# ---------------------------------------------------------------------------
# (a) Allow branch
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_declare_handoff_allow_when_both_clearances_dominate(tmp_path: Path) -> None:
    """Both agents hold ``secret`` clearance and classification is ``confidential``.

    ``fathom-dominates`` is true for ``from_clearance`` AND for
    ``to_clearance`` → the ``information-flow-violation`` rule does NOT
    fire → action is ``"allow"``.
    """
    cfg = _write_yaml_with_agents(tmp_path, source_clearance="secret", receiver_clearance="secret")
    broker = Broker.from_config(cfg)
    adapter_mocks = _install_mock_adapters(broker)
    try:
        decision = await broker.declare_handoff(
            source_agent_id="agent-source",
            receiving_agent_id="agent-receiver",
            session_id="s-allow",
            data_classifications=["confidential"],
        )
    finally:
        await broker.aclose()

    assert isinstance(decision, HandoffDecision)
    assert decision.action == "allow", f"expected allow, got {decision.action}"
    assert decision.denial_records == []
    assert decision.handoff_id
    # AC-4.1 — policy-only path; no adapter methods invoked.
    for mock in adapter_mocks.values():
        mock.execute.assert_not_called()


# ---------------------------------------------------------------------------
# (b) Deny branch (AC-4.3)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_declare_handoff_deny_when_receiver_does_not_dominate(tmp_path: Path) -> None:
    """Source has ``secret``, receiver has ``unclassified``, classification ``secret``.

    Source clearance dominates the classification but receiver does NOT →
    ``information-flow-violation`` fires → action is ``"deny"`` (AC-4.3).
    """
    cfg = _write_yaml_with_agents(
        tmp_path, source_clearance="secret", receiver_clearance="unclassified"
    )
    broker = Broker.from_config(cfg)
    adapter_mocks = _install_mock_adapters(broker)
    try:
        decision = await broker.declare_handoff(
            source_agent_id="agent-source",
            receiving_agent_id="agent-receiver",
            session_id="s-deny",
            data_classifications=["secret"],
        )
    finally:
        await broker.aclose()

    assert decision.action == "deny"
    assert decision.denial_records, "deny branch must carry at least one denial_record"
    rule_names = [d.rule_name for d in decision.denial_records]
    assert "information-flow-violation" in rule_names, (
        f"expected information-flow-violation in {rule_names!r}"
    )
    # AC-4.1 — still zero adapter calls even on the deny branch.
    for mock in adapter_mocks.values():
        mock.execute.assert_not_called()


# ---------------------------------------------------------------------------
# (c) Escalate branch — schema contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_handoff_decision_supports_escalate_action() -> None:
    """AC-4.3 note: ``HandoffDecision.action`` accepts ``"escalate"``.

    The default rule set never produces this value (broker maps denials →
    ``"deny"``), but the schema MUST admit ``"escalate"`` so user
    escalation-pack rules can map a denial to an escalation without a
    model-level migration. This pins the ``Literal`` contract.
    """
    decision = HandoffDecision(
        handoff_id="h-esc-1",
        action="escalate",
        denial_records=[],
        rule_trace=["pii-aggregation-confidential"],
    )
    assert decision.action == "escalate"
    # Round-trip through JSON preserves the literal tag.
    reloaded = HandoffDecision.model_validate_json(decision.model_dump_json())
    assert reloaded.action == "escalate"
    assert reloaded.rule_trace == ["pii-aggregation-confidential"]


# ---------------------------------------------------------------------------
# (d) Unknown receiving agent (AC-4.2)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_declare_handoff_unknown_receiving_agent_denied(tmp_path: Path) -> None:
    """AC-4.2 — unknown receiving id short-circuits to a synthetic deny.

    The :class:`HandoffDecision` must carry ``action="deny"`` and exactly
    one :class:`DenialRecord` whose ``rule_name`` is ``"unknown-agent"``.
    """
    cfg = _write_yaml_with_agents(
        tmp_path, source_clearance="unclassified", receiver_clearance="unclassified"
    )
    broker = Broker.from_config(cfg)
    adapter_mocks = _install_mock_adapters(broker)
    try:
        decision = await broker.declare_handoff(
            source_agent_id="agent-source",
            receiving_agent_id="ghost-agent",  # NOT in the registry
            session_id="s-ghost",
            data_classifications=["unclassified"],
        )
    finally:
        await broker.aclose()

    assert decision.action == "deny"
    assert len(decision.denial_records) == 1
    assert decision.denial_records[0].rule_name == "unknown-agent"
    # Zero adapter calls on the short-circuit path too.
    for mock in adapter_mocks.values():
        mock.execute.assert_not_called()


# ---------------------------------------------------------------------------
# (e) Exactly one audit entry per call (AC-4.4)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_declare_handoff_emits_exactly_one_audit_entry(tmp_path: Path) -> None:
    """AC-4.4 / NFR-15 — one ``event_type="handoff_declared"`` entry per call."""
    audit_path = tmp_path / "handoff-audit.jsonl"
    cfg = _write_yaml_with_agents(
        tmp_path,
        source_clearance="secret",
        receiver_clearance="secret",
        audit_path=audit_path,
    )
    broker = Broker.from_config(cfg)
    _install_mock_adapters(broker)
    try:
        decision = await broker.declare_handoff(
            source_agent_id="agent-source",
            receiving_agent_id="agent-receiver",
            session_id="s-audit",
            data_classifications=["confidential"],
        )
    finally:
        await broker.aclose()

    entries = _read_audit_lines(audit_path)
    assert len(entries) == 1, f"expected exactly one audit entry, got {len(entries)}"

    # Each top-level JSONL record is a fathom AuditRecord; the Nautilus entry
    # lives under metadata["nautilus_audit_entry"] (see NAUTILUS_METADATA_KEY).
    from nautilus.audit.logger import NAUTILUS_METADATA_KEY

    payload = json.loads(entries[0]["metadata"][NAUTILUS_METADATA_KEY])
    assert payload["event_type"] == "handoff_declared"
    assert payload["handoff_id"] == decision.handoff_id
    assert payload["handoff_decision"]["action"] == "allow"


# ---------------------------------------------------------------------------
# (f) 50 concurrent calls produce 50 distinct handoff_ids (AC-4.5)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_declare_handoff_50_concurrent_distinct_ids(tmp_path: Path) -> None:
    """AC-4.5 — ``asyncio.gather`` of 50 calls yields 50 unique ``handoff_id`` values."""
    cfg = _write_yaml_with_agents(tmp_path, source_clearance="secret", receiver_clearance="secret")
    broker = Broker.from_config(cfg)
    _install_mock_adapters(broker)
    try:
        decisions = await asyncio.gather(
            *[
                broker.declare_handoff(
                    source_agent_id="agent-source",
                    receiving_agent_id="agent-receiver",
                    session_id=f"s-concurrent-{i}",
                    data_classifications=["confidential"],
                )
                for i in range(50)
            ]
        )
    finally:
        await broker.aclose()

    assert len(decisions) == 50
    ids = {d.handoff_id for d in decisions}
    assert len(ids) == 50, (
        f"expected 50 distinct handoff_ids, got {len(ids)} "
        f"(collisions across {len(decisions)} calls)"
    )
    # All calls landed on the allow branch under the test rule pack.
    assert all(d.action == "allow" for d in decisions)


# ---------------------------------------------------------------------------
# (g) Zero adapter calls across every branch (AC-4.1, FR-8)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_declare_handoff_never_touches_adapters(tmp_path: Path) -> None:
    """AC-4.1 / FR-8 — ``declare_handoff`` is a pure policy path.

    Exercises the allow, deny, and unknown-agent branches against mock
    adapters and asserts the mocks' ``execute`` / ``query`` methods are
    never invoked — any non-zero call would indicate a regression where
    the handoff path accidentally reached the data layer.
    """
    cfg = _write_yaml_with_agents(
        tmp_path, source_clearance="secret", receiver_clearance="unclassified"
    )
    broker = Broker.from_config(cfg)
    adapter_mocks = _install_mock_adapters(broker)
    try:
        # allow (receiver dominates classification unclassified ≤ unclassified)
        await broker.declare_handoff(
            source_agent_id="agent-source",
            receiving_agent_id="agent-receiver",
            session_id="s-allow",
            data_classifications=["unclassified"],
        )
        # deny (receiver unclassified cannot dominate classification secret)
        await broker.declare_handoff(
            source_agent_id="agent-source",
            receiving_agent_id="agent-receiver",
            session_id="s-deny",
            data_classifications=["secret"],
        )
        # unknown-agent short-circuit
        await broker.declare_handoff(
            source_agent_id="agent-source",
            receiving_agent_id="ghost-agent",
            session_id="s-ghost",
            data_classifications=["unclassified"],
        )
    finally:
        await broker.aclose()

    for source_id, mock in adapter_mocks.items():
        mock.execute.assert_not_called()
        assert mock.method_calls == [] or all(
            call[0] not in {"execute", "query", "connect"} for call in mock.method_calls
        ), f"adapter {source_id!r} received a data-layer call: {mock.method_calls!r}"
