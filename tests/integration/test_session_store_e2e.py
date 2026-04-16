"""Session-store end-to-end integration tests (Task 3.14, AC-2.x, NFR-7).

Pins the Phase-2 persistent-session-store contract against a real
``pgvector/pgvector:pg17`` container via the session-scoped
``pg_container`` fixture in :mod:`tests.conftest`. Exercises four
scenarios that the unit suite can only stub:

(a) AC-2.2 — :meth:`Broker.setup` is idempotent on repeated calls (the
    DDL uses ``CREATE TABLE IF NOT EXISTS``; calling it twice must not
    error).
(b) AC-2.1 — two consecutive ``broker.request()`` calls sharing the same
    ``session_id`` see accumulated state: the second request's session
    dict (as handed to the Fathom router via ``_assert_session``) carries
    the ``last_request_id`` / ``last_sources_queried`` fields written by
    the first request's ``_update_session`` step.
(c) AC-2.4 — a restart of the broker picks up the same session state
    from Postgres: close broker #1, build broker #2 against the same
    DSN, confirm the second broker's store returns the first broker's
    last-request metadata.
(d) NFR-7 / D-1 — an unreachable DSN with ``on_failure="fail_closed"``
    surfaces :class:`SessionStoreUnavailableError` out of
    ``broker.request`` AND the best-effort audit entry emitted in the
    ``except Exception`` block carries an ``error_records`` entry with
    ``error_type="SessionStoreUnavailableError"``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.core.broker import Broker
from nautilus.core.fathom_router import FathomRouter
from nautilus.core.models import AuditEntry
from nautilus.core.session_pg import PostgresSessionStore, SessionStoreUnavailableError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_pg_session_config(tmp_path: Path, *, dsn: str | None = None) -> Path:
    """Emit a minimal ``nautilus.yaml`` pointing the session store at Postgres.

    Mirrors the shape of ``tests/fixtures/nautilus.yaml`` (the Phase-1
    two-source fixture) but overlays a ``session_store`` block with
    ``backend: postgres``. When ``dsn`` is ``None`` the broker falls back
    to ``TEST_PG_DSN`` (exported by the ``pg_container`` fixture) per
    :meth:`Broker._build_session_store` — that is the normal test path.
    When ``dsn`` is supplied verbatim (e.g. an unreachable host for the
    fail-closed case) it is inlined into the YAML and ``TEST_PG_DSN`` is
    ignored.
    """
    config: dict[str, Any] = {
        "sources": [
            {
                "id": "nvd_db",
                "type": "postgres",
                "description": "National Vulnerability Database mirror (test fixture)",
                "classification": "unclassified",
                "data_types": ["cve", "vulnerability", "patch"],
                "allowed_purposes": ["threat-analysis", "incident-response"],
                "connection": "${TEST_PG_DSN}",
                "table": "vulns",
            },
            {
                "id": "internal_vulns",
                "type": "pgvector",
                "description": "Internal vulnerability embeddings (test fixture)",
                "classification": "unclassified",
                "data_types": ["vulnerability", "scan_result"],
                "allowed_purposes": ["threat-analysis"],
                "connection": "${TEST_PGV_DSN}",
                "table": "vuln_embeddings",
                "embedding_column": "embedding",
                "metadata_column": "metadata",
                "distance_operator": "<=>",
                "top_k": 10,
            },
        ],
        "rules": {"user_rules_dirs": []},
        "analysis": {
            "keyword_map": {
                "vulnerability": ["vulnerability", "vuln", "weakness"],
                "patch": ["patch", "fix", "update"],
                "asset": ["asset", "system", "host", "server"],
            }
        },
        "audit": {"path": "./audit.jsonl"},
        "attestation": {"enabled": True},
        "session_store": {"backend": "postgres", "on_failure": "fail_closed"},
    }
    if dsn is not None:
        config["session_store"]["dsn"] = dsn
    config_path = tmp_path / "nautilus.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return config_path


def _read_audit_entries(audit_file: Path) -> list[AuditEntry]:
    """Parse every ``AuditEntry`` from the JSONL file written by the broker."""
    entries: list[AuditEntry] = []
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record: dict[str, Any] = json.loads(line)
        entry_json = record["metadata"][NAUTILUS_METADATA_KEY]
        entries.append(AuditEntry.model_validate_json(entry_json))
    return entries


# ---------------------------------------------------------------------------
# (a) AC-2.2 — Broker.setup() idempotent on repeated calls.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_a_broker_setup_is_idempotent_on_repeated_calls(
    pg_container: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-2.2 — calling :meth:`Broker.setup` twice must not raise.

    The DDL uses ``CREATE TABLE IF NOT EXISTS`` (see
    :mod:`nautilus.core.session_pg`); the second call exercises the
    idempotent branch against the live Postgres schema. Both calls run
    inside a single :func:`asyncio.run` so the asyncpg pool built by the
    first ``setup()`` stays attached to the event loop for the second.
    """
    del pg_container  # side-effect: container booted, env vars exported
    monkeypatch.chdir(tmp_path)

    config_path = _write_pg_session_config(tmp_path)
    broker = Broker.from_config(config_path)
    # Confirm the store is wired to Postgres (NFR-5 fallback would be
    # InMemorySessionStore — guard against silent misconfiguration).
    assert isinstance(broker.session_store, PostgresSessionStore)

    async def _body() -> None:
        # First call: creates table + pool. Second: re-runs idempotent DDL.
        await broker.setup()
        await broker.setup()
        # Close inside the same loop the pool was built in, so aclose sees
        # a live loop for the pool shutdown.
        await broker.aclose()

    import asyncio

    asyncio.run(_body())


# ---------------------------------------------------------------------------
# (b) AC-2.1 — two requests sharing session_id accumulate state.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_b_second_request_sees_accumulated_session_state_in_fathom_facts(
    pg_container: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-2.1 — request #2 with shared ``session_id`` sees request #1's state.

    The broker's ``_update_session`` step stamps
    ``{last_request_id, last_sources_queried}`` into the Postgres row
    after every successful request. The Fathom router's
    ``_assert_session`` reads that dict on the next request and folds it
    into the asserted ``session`` fact. We spy on ``FathomRouter.route``
    to capture the ``session`` kwarg the router sees at request time —
    the second invocation MUST contain request #1's ``last_request_id``.
    """
    del pg_container
    monkeypatch.chdir(tmp_path)

    config_path = _write_pg_session_config(tmp_path)
    broker = Broker.from_config(config_path)

    # Spy on the router — capture the session dict passed to each ``route``
    # call without disturbing its behaviour.
    captured_sessions: list[dict[str, Any]] = []
    original_route = broker._router.route  # pyright: ignore[reportPrivateUsage]

    def _spy_route(*args: Any, **kwargs: Any) -> Any:
        session_arg = kwargs.get("session", {})
        captured_sessions.append(dict(session_arg))
        return original_route(*args, **kwargs)

    monkeypatch.setattr(broker._router, "route", _spy_route)  # pyright: ignore[reportPrivateUsage]

    ctx = {
        "clearance": "unclassified",
        "purpose": "threat-analysis",
        "session_id": "sess-b",
        "embedding": [0.1, 0.2, 0.3],
    }

    # asyncpg pools are pinned to the event loop that built them; the sync
    # ``broker.request`` path would spin a fresh loop per call and invalidate
    # the pool. Batch setup + both requests + aclose into one loop.
    async def _body() -> tuple[Any, Any]:
        await broker.setup()
        r1 = await broker.arequest("agent-alpha", "Find vulnerabilities for CVE-2026-0001", ctx)
        r2 = await broker.arequest("agent-alpha", "Find vulnerabilities for CVE-2026-0002", ctx)
        await broker.aclose()
        return r1, r2

    import asyncio

    resp1, resp2 = asyncio.run(_body())

    # Two router invocations captured — one per request.
    assert len(captured_sessions) == 2, (
        f"expected 2 router.route() calls; got {len(captured_sessions)}"
    )

    # Request #1's session dict has no prior-request metadata (fresh session).
    first_session = captured_sessions[0]
    assert first_session.get("id") == "sess-b"
    assert "last_request_id" not in first_session

    # Request #2's session dict MUST carry request #1's id — that is the
    # AC-2.1 accumulation contract round-tripped through Postgres.
    second_session = captured_sessions[1]
    assert second_session.get("id") == "sess-b"
    assert second_session.get("last_request_id") == resp1.request_id, (
        f"expected request #2's session dict to carry request #1's id "
        f"({resp1.request_id!r}); got {second_session!r}"
    )
    assert second_session.get("last_sources_queried") == sorted(resp1.sources_queried)
    # Sanity: request #2 and request #1 are distinct.
    assert resp1.request_id != resp2.request_id


# ---------------------------------------------------------------------------
# (c) AC-2.4 — restart broker; second broker sees state via Postgres.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_c_restart_broker_sees_same_session_state_via_postgres(
    pg_container: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-2.4 — a fresh broker process sees session state persisted by the prior one.

    Builds broker #1, issues one request with ``session_id=sess-c``,
    closes it. Builds broker #2 against the same DSN, reads the session
    row directly via the async store surface, and confirms it carries
    broker #1's ``last_request_id``.
    """
    del pg_container
    monkeypatch.chdir(tmp_path)

    config_path = _write_pg_session_config(tmp_path)

    # --- Broker #1: write. All async ops share one event loop.
    broker_one = Broker.from_config(config_path)

    async def _write() -> Any:
        await broker_one.setup()
        r1 = await broker_one.arequest(
            "agent-alpha",
            "Find vulnerabilities for CVE-2026-0003",
            {
                "clearance": "unclassified",
                "purpose": "threat-analysis",
                "session_id": "sess-c",
                "embedding": [0.1, 0.2, 0.3],
            },
        )
        await broker_one.aclose()
        return r1

    import asyncio

    resp1 = asyncio.run(_write())

    # --- Broker #2: fresh instance, same DSN, read the state back.
    broker_two = Broker.from_config(config_path)

    async def _read() -> dict[str, Any]:
        await broker_two.setup()
        store_two = broker_two.session_store
        assert isinstance(store_two, PostgresSessionStore)
        # Use the async surface directly — bypass broker.request so the
        # assertion is solely about persistence, not routing.
        state_row: dict[str, Any] = await store_two.aget("sess-c")
        await broker_two.aclose()
        return state_row

    state: dict[str, Any] = asyncio.run(_read())

    assert state, f"session row for sess-c missing in second broker: {state!r}"
    assert state.get("last_request_id") == resp1.request_id, (
        f"broker #2 did not see broker #1's last_request_id ({resp1.request_id!r}); got {state!r}"
    )
    assert state.get("last_sources_queried") == sorted(resp1.sources_queried)


# ---------------------------------------------------------------------------
# (d) NFR-7 / D-1 — unreachable DSN + fail_closed → SessionStoreUnavailableError.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_d_unreachable_dsn_fail_closed_raises_and_audits_error_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NFR-7 / D-1 — broker raises SessionStoreUnavailableError + audits error_type.

    No container dependency — the DSN points at a non-existent host so
    the store never reaches Postgres. We intentionally SKIP
    :meth:`Broker.setup` so the failure surfaces from
    :meth:`Broker.arequest` itself (via ``_session_get`` → ``aget`` →
    "called before setup() succeeded"), which is caught by the generic
    ``except Exception`` block in ``arequest`` and written to audit
    before re-raising.
    """
    monkeypatch.chdir(tmp_path)
    # Neutralise any inherited TEST_PG_DSN from prior fixtures — this test
    # must not share a container with the e2e cases above.
    monkeypatch.delenv("TEST_PG_DSN", raising=False)
    monkeypatch.delenv("TEST_PGV_DSN", raising=False)
    # The source configs still interpolate ${TEST_PG_DSN}; give them a
    # throwaway value (sources aren't used by the failing path but the
    # config loader resolves env vars eagerly).
    monkeypatch.setenv("TEST_PG_DSN", "postgresql://unused:5432/unused")
    monkeypatch.setenv("TEST_PGV_DSN", "postgresql://unused:5432/unused")

    # ``postgresql://127.0.0.1:1/db`` — port 1 is unreachable on every host
    # and does not require DNS resolution, so the failure is fast and
    # deterministic across CI runners.
    config_path = _write_pg_session_config(
        tmp_path,
        dsn="postgresql://127.0.0.1:1/nautilus_does_not_exist",
    )

    broker = Broker.from_config(config_path)
    try:
        assert isinstance(broker.session_store, PostgresSessionStore)

        with pytest.raises(SessionStoreUnavailableError):
            broker.request(
                "agent-alpha",
                "Find vulnerabilities for CVE-2026-0004",
                {
                    "clearance": "unclassified",
                    "purpose": "threat-analysis",
                    "session_id": "sess-d",
                },
            )
    finally:
        broker.close()

    # Audit entry written from the broker's generic except block must carry
    # the SessionStoreUnavailableError error_type (NFR-7 operator signal).
    audit_file = tmp_path / "audit.jsonl"
    assert audit_file.exists(), f"audit file missing at {audit_file}"

    entries = _read_audit_entries(audit_file)
    assert entries, "expected at least one audit entry for the failed request"

    failed_entry = entries[-1]
    error_types = [er.error_type for er in failed_entry.error_records]
    assert "SessionStoreUnavailableError" in error_types, (
        f"expected SessionStoreUnavailableError in error_records; got {error_types!r}"
    )
    # Sanity pins on the failing entry shape.
    assert failed_entry.agent_id == "agent-alpha"
    assert failed_entry.session_id == "sess-d"
    # ``sources_errored`` aggregates the ids present in error_records; the
    # broker-level failure is tagged under ``<broker>``.
    assert "<broker>" in failed_entry.sources_errored


# Silence the "unused" hint on FathomRouter — imported only to document the
# spy surface used by test (b).
_ = FathomRouter
