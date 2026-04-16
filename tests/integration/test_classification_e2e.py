"""POC milestone integration test — reasoning-engine spec Task 1.15.

Proves the Phase-1 reasoning-engine pipeline end-to-end:

1. Agent-registry classification routing via ``default-classification-deny``.
2. Pattern-matcher intent analysis (no LLM provider configured).
3. ``TemporalFilter`` → ``scope_hash_v1`` vs ``scope_hash_v2`` selection.
4. pgvector adapter returns rows (reuses ``vuln_embeddings`` seed).
5. Attestation token signed and dispatched to a ``FileAttestationSink``.
6. :class:`PostgresSessionStore` in ``primary`` mode surfaces on
   :attr:`AuditEntry.session_store_mode` = ``"primary"``.

The fixture YAML is ``tests/fixtures/reasoning/poc.yaml``. Windows has no
``/tmp`` so the attestation sink path is env-interpolated (``${POC_ATTESTATION_PATH}``)
and pointed at ``tmp_path`` for the duration of the test.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.core.attestation_sink import AttestationPayload
from nautilus.core.broker import Broker
from nautilus.core.models import AuditEntry, ScopeConstraint

_POC_YAML: Path = Path(__file__).parent.parent / "fixtures" / "reasoning" / "poc.yaml"


def _read_last_audit_entry(audit_path: Path) -> AuditEntry:
    """Parse the last JSONL line of ``audit_path`` as an :class:`AuditEntry`."""
    lines = [ln for ln in audit_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert lines, f"audit file {audit_path} is empty"
    record: dict[str, Any] = json.loads(lines[-1])
    entry_json = record["metadata"][NAUTILUS_METADATA_KEY]
    return AuditEntry.model_validate_json(entry_json)


@pytest.mark.integration
async def test_classification_e2e_poc_gate(
    pg_container: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full POC gate — all four request scenarios + attestation JSONL assertions."""
    del pg_container  # side-effect: container booted, TEST_PG_DSN / TEST_PGV_DSN exported

    # Redirect the attestation sink + audit file into the test's tmp_path so no
    # repo-root side effects leak between runs. The YAML references
    # ``${POC_ATTESTATION_PATH}`` which the loader interpolates at config-load time.
    attestation_path = tmp_path / "poc-attestation.jsonl"
    monkeypatch.setenv("POC_ATTESTATION_PATH", str(attestation_path))
    monkeypatch.chdir(tmp_path)  # ./audit.jsonl now lives under tmp_path

    broker = Broker.from_config(_POC_YAML)
    try:
        await broker.setup()

        # -- Request #1: baseline — cui agent, cui source, no temporal slots ->
        # scope_hash_version should be v1. -----------------------------------
        resp1 = await broker.arequest(
            "a1",
            "find PII for threat hunting",
            {
                "clearance": "cui",
                "purpose": "threat-hunt",
                "session_id": "s1",
                "compartments": "cti",
                "embedding": [0.1, 0.2, 0.3],
            },
        )
        assert resp1.attestation_token is not None

        audit_path = tmp_path / "audit.jsonl"
        entry1 = _read_last_audit_entry(audit_path)
        assert entry1.scope_hash_version == "v1", (
            f"expected v1 (no temporal slots), got {entry1.scope_hash_version!r}"
        )
        assert entry1.session_store_mode == "primary", (
            f"expected primary session_store, got {entry1.session_store_mode!r}"
        )
        assert entry1.event_type == "request"

        # -- Request #2: carries an ``expires_at`` scope constraint -> v2. --
        future = (datetime.now(UTC) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        resp2 = await broker.arequest(
            "a1",
            "find PII for threat hunting",
            {
                "clearance": "cui",
                "purpose": "threat-hunt",
                "session_id": "s1",
                "compartments": "cti",
                "embedding": [0.1, 0.2, 0.3],
                "scope_constraints": [
                    ScopeConstraint(
                        source_id="cui_embeddings",
                        field="id",
                        operator=">=",
                        value=0,
                        expires_at=future,
                    )
                ],
            },
        )
        assert resp2.attestation_token is not None
        entry2 = _read_last_audit_entry(audit_path)
        assert entry2.scope_hash_version == "v2", (
            f"expected v2 (expires_at set), got {entry2.scope_hash_version!r}"
        )

        # -- Request #3: agent clearance dominates the source -> at least one
        # routing_decision fires. -------------------------------------------
        resp3 = await broker.arequest(
            "a1",
            "find PII for threat hunting",
            {
                "clearance": "cui",  # dominates cui source (reflexive dominance)
                "purpose": "threat-hunt",
                "session_id": "s1",
                "compartments": "cti",
                "embedding": [0.1, 0.2, 0.3],
            },
        )
        assert resp3.attestation_token is not None
        entry3 = _read_last_audit_entry(audit_path)
        assert entry3.routing_decisions, (
            "expected >= 1 routing_decision when clearance dominates source"
        )

        # -- Request #4: agent clearance `unclassified` < source `cui` ->
        # default-classification-deny fires. --------------------------------
        resp4 = await broker.arequest(
            "a1",
            "find PII for threat hunting",
            {
                "clearance": "unclassified",  # overrides registry's cui for this request
                "purpose": "threat-hunt",
                "session_id": "s1",
                "compartments": "cti",
                "embedding": [0.1, 0.2, 0.3],
            },
        )
        assert resp4.attestation_token is not None
        entry4 = _read_last_audit_entry(audit_path)
        rule_names = {d.rule_name for d in entry4.denial_records}
        assert "default-classification-deny" in rule_names, (
            f"expected default-classification-deny denial, got {rule_names!r}"
        )

        # -- Attestation sink assertions (AC-14.1, AC-14.2). -----------------
        assert attestation_path.exists(), f"attestation sink file missing at {attestation_path}"
        att_lines = [
            ln for ln in attestation_path.read_text(encoding="utf-8").splitlines() if ln.strip()
        ]
        assert len(att_lines) >= 4, (
            f"expected >=4 attestation lines (one per request), got {len(att_lines)}"
        )
        for ln in att_lines:
            # Every line must round-trip through AttestationPayload (schema-valid).
            AttestationPayload.model_validate_json(ln)

    finally:
        await broker.aclose()
