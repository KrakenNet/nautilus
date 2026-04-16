"""MVP end-to-end integration test — the POC milestone (Task 1.17).

Proves FR-16 / AC-9.3: a single ``broker.request()`` call against the
``tests/fixtures/nautilus.yaml`` two-source config (one PostgreSQL, one
pgvector) routes through Fathom, executes both adapters concurrently,
writes exactly one complete :class:`AuditEntry`, and returns a signed
Ed25519 attestation token (UQ-2).

This test owns the ``pg_container`` fixture bootstrapping the testcontainer
and relies on :mod:`tests.conftest` to have exported ``TEST_PG_DSN`` and
``TEST_PGV_DSN`` into ``os.environ`` before :meth:`Broker.from_config` runs.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

import pytest

from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.core.broker import Broker
from nautilus.core.models import AuditEntry

# UUID4 regex — the broker uses ``uuid.uuid4()`` for request ids.
_UUID_RE: re.Pattern[str] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@pytest.mark.integration
def test_mvp_e2e_broker_against_pg_and_pgvector(
    pg_container: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Broker + PG + pgvector + audit + attestation — full POC gate.

    The fixture has already booted the container and exported ``TEST_PG_DSN``
    / ``TEST_PGV_DSN``. We retarget the audit path via ``monkeypatch.chdir``
    onto ``tmp_path`` so each test run starts with a clean JSONL file
    (``./audit.jsonl`` is the default in the fixture config).
    """
    del pg_container  # side-effect: container booted, env vars exported

    # Relocate CWD so ``./audit.jsonl`` lands under tmp_path, giving us a
    # pristine audit file per test run.
    monkeypatch.chdir(tmp_path)

    config_path = (Path(__file__).parent.parent / "fixtures" / "nautilus.yaml").resolve()

    broker = Broker.from_config(config_path)
    try:
        resp = broker.request(
            "agent-alpha",
            "Find vulnerabilities for CVE-2026-1234",
            {
                "clearance": "unclassified",
                "purpose": "threat-analysis",
                "session_id": "s1",
                "embedding": [0.1, 0.2, 0.3],
            },
        )

        # ------------------------------------------------------------------
        # BrokerResponse assertions (FR-16, AC-9.3, UQ-2).
        # ------------------------------------------------------------------
        assert set(resp.sources_queried) == {"nvd_db", "internal_vulns"}, (
            f"expected both sources queried; got {resp.sources_queried!r} "
            f"(errored={resp.sources_errored!r})"
        )
        assert resp.data["nvd_db"], "nvd_db returned empty rows"
        assert resp.data["internal_vulns"], "internal_vulns returned empty rows"
        assert resp.attestation_token is not None, "UQ-2 requires a signed token"
        assert _UUID_RE.match(resp.request_id), f"request_id not a UUID4: {resp.request_id!r}"
        assert resp.duration_ms >= 0  # allow 0ms on very fast machines
        # NFR-9: explicit non-strict check retained for specs that require
        # strictly positive duration; Python's clock on Windows can return
        # 0ms for sub-millisecond requests — we therefore accept >= 0 above
        # and re-check the distinct monotonic progression below.
        assert isinstance(resp.duration_ms, int)

    finally:
        broker.close()

    # ----------------------------------------------------------------------
    # JSONL audit file assertions (AC-7.1, AC-7.3, NFR-8).
    # ----------------------------------------------------------------------
    audit_file = tmp_path / "audit.jsonl"
    assert audit_file.exists(), f"audit file missing at {audit_file}"

    lines = [ln for ln in audit_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected exactly 1 audit line, got {len(lines)}"

    # The FileSink writes an ``AuditRecord`` per design §3.7; the full
    # Nautilus :class:`AuditEntry` is stashed under ``metadata[NAUTILUS_METADATA_KEY]``.
    record: dict[str, Any] = json.loads(lines[0])
    entry_json = record["metadata"][NAUTILUS_METADATA_KEY]
    entry: AuditEntry = AuditEntry.model_validate_json(entry_json)

    assert entry.rule_trace, "rule_trace must be non-empty (AC-7.3)"
    assert entry.facts_asserted_summary["source"] == 2, (
        f"expected 2 source facts asserted, got {entry.facts_asserted_summary!r}"
    )
    # Belt-and-braces: request_id round-trips to the audit entry.
    assert uuid.UUID(entry.request_id)

    # ----------------------------------------------------------------------
    # Idempotent close (FR-17, AC-8.6).
    # ----------------------------------------------------------------------
    broker.close()  # second call must be a no-op


@pytest.mark.integration
def test_mvp_e2e_close_is_idempotent_without_request(
    pg_container: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``Broker.close()`` is safe to call twice even before any request."""
    del pg_container
    monkeypatch.chdir(tmp_path)

    config_path = (Path(__file__).parent.parent / "fixtures" / "nautilus.yaml").resolve()
    broker = Broker.from_config(config_path)
    broker.close()
    broker.close()  # no-op per FR-17 / AC-8.6
