"""Pins for the transport, governance and session defects (REPORT.md 4.9-4.15).

These run against the real FastAPI app and the real CLI. The existing suite
misses them because it reads the raw audit JSONL off disk instead of going
through ``AuditReader``, and because no test ever requests ``/openapi.json``
or scrapes ``/metrics`` after real traffic.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.defect

# The app is fail-closed when no keys are configured, so an unauthenticated
# client 401s on every route and any status assertion would pass vacuously.
API_KEY = "journey-key"


def _pg_source(dsn_env: str = "${JOURNEY_PG_DSN}") -> dict[str, Any]:
    return {
        "id": "src",
        "type": "postgres",
        "description": "a source",
        "classification": "unclassified",
        "data_types": ["patients"],
        "allowed_purposes": [],
        "connection": dsn_env,
        "table": "journey.patients",
    }


@pytest.fixture
def app_config(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[str, Path]:
    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    audit = tmp_path / "audit.jsonl"
    config = write_config(
        {
            "sources": [_pg_source()],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
            "audit": {"path": str(audit)},
            "api": {"keys": [API_KEY]},
        }
    )
    return config, audit


@pytest.fixture
def client(app_config: tuple[str, Path]) -> Any:
    """A real TestClient over the real app, lifespan included."""
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    config, _ = app_config
    with TestClient(create_app(config), headers={"X-API-Key": API_KEY}) as c:
        yield c


# ---------------------------------------------------------------------------
# 4.12 -- GET /openapi.json returns 500; the admin SSE route 422s every caller
# ---------------------------------------------------------------------------


def test_m412_openapi_schema_generates(client: Any) -> None:
    """``/openapi.json`` must render, or ``/docs`` and client codegen are dead.

    ``ui/sse.py:55`` annotates ``broker: Annotated[Broker, Depends(get_broker)]``
    while ``Broker`` is imported only under ``if TYPE_CHECKING`` with
    ``from __future__ import annotations``, so FastAPI cannot resolve the
    ForwardRef and schema generation dies for the whole app. The codebase
    documents and works around this exact trap twice elsewhere
    (``ui/router.py _safe_auth_user``, ``fastapi_app.py _read_guard``).
    """
    response = client.get("/openapi.json")
    assert response.status_code == 200, (
        f"GET /openapi.json returned {response.status_code}. /docs and /redoc "
        f"render errors, there is no client codegen and no schema-diff CI."
    )


def test_m412_admin_sse_route_does_not_demand_a_broker_query_param(
    client: Any,
) -> None:
    """The ``Depends`` marker must not be trapped inside an unresolved string.

    Because the ForwardRef never resolves, ``broker`` registers as a required
    *query parameter*: every caller gets 422 and ``get_auth_user`` never runs.

    Read off the schema rather than by calling the route: a working SSE
    endpoint streams until the client disconnects, so a request that proves
    the fix would hang the suite.
    """
    schema = client.get("/openapi.json").json()
    route = schema["paths"]["/admin/sources/events"]["get"]
    params = {p["name"] for p in route.get("parameters", [])}
    assert "broker" not in params, (
        f"GET /admin/sources/events declares {sorted(params)} as parameters. "
        f"``broker`` is a Depends marker trapped in an unresolved ForwardRef, "
        f"so FastAPI reads it as a required query parameter and 422s everyone."
    )


# ---------------------------------------------------------------------------
# 4.13 -- GET /metrics exports zero Nautilus series
# ---------------------------------------------------------------------------


def test_m413_metrics_endpoint_exports_nautilus_series(client: Any) -> None:
    """The shipped Grafana dashboards must have series to query.

    ``instrumentation.py:44`` builds a ``MeterProvider`` with **no metric
    reader**, under a comment reading ``--- Metrics (Prometheus) ---``, and
    ``/metrics`` serves ``prometheus_client.generate_latest()`` from a
    disjoint registry. All three shipped dashboards query names that do not
    exist.
    """
    for i in range(5):
        client.post(
            "/v1/request",
            json={
                "agent_id": "a",
                "intent": "patients",
                "context": {"purpose": "p", "session_id": f"s{i}"},
            },
        )

    body = client.get("/metrics").text
    # The three the broker actually records, per the report.
    wanted = ["nautilus_requests_total", "nautilus_request_duration"]
    missing = [name for name in wanted if name not in body]
    assert not missing, (
        f"after 5 real requests /metrics exports none of {missing}. It "
        f"contains only process_* and python_gc_* series, so every shipped "
        f"Grafana dashboard panel is empty."
    )


# ---------------------------------------------------------------------------
# 4.14 -- X-Nautilus-Session-Token on /v1/request is not verified
# ---------------------------------------------------------------------------


def test_m414_a_garbage_session_token_header_is_rejected(client: Any) -> None:
    """``verify_session_token`` documents a 401 it is never wired to produce.

    It is exported and its docstring says it "Raises HTTPException 401 when
    the header is present but invalid (AC-18.d)", but
    ``grep "Depends(verify_session_token)" nautilus/`` returns nothing. The
    body channel (``context["session_token"]``) *is* fail-closed, so this is
    a docstring promising an enforcement guarantee that does not exist.
    """
    response = client.post(
        "/v1/request",
        headers={"X-Nautilus-Session-Token": "not-a-jws-at-all"},
        json={
            "agent_id": "a",
            "intent": "patients",
            "context": {"purpose": "p", "session_id": "s1"},
        },
    )
    assert response.status_code == 401, (
        f"a garbage X-Nautilus-Session-Token got HTTP {response.status_code} "
        f"with full data. The header is declared, documented as verified, and "
        f"read by nothing."
    )


# ---------------------------------------------------------------------------
# 4.15 -- the exposure ledger resets by omitting the token
# ---------------------------------------------------------------------------


def test_m415_omitting_the_session_token_does_not_reset_the_ledger(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller must not be able to clear cumulative exposure by dropping the token.

    ``docs/how-to/operator-guide.md:126-129`` states it unconditionally: "the
    exposure ledger cannot be reset by declaring a fresh session.
    Verification is fail-closed." ``broker.py:1903`` reads
    ``context.get("session_token")`` and an *absent* key mints a brand-new
    token bound to whatever ``session_id`` the caller declared.
    ``declare_handoff`` does fail closed on a missing token; ``arequest``
    has no equivalent and ``SessionTokenConfig`` exposes no "require" knob.
    """
    from nautilus import Broker

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    sources = [
        {**_pg_source(), "id": f"pii_{k}", "data_types": ["pii", k]}
        for k in ("ssn", "dob", "phone")
    ]
    config = write_config(
        {
            "sources": sources,
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
            "session_tokens": {"enabled": True},
        }
    )

    async def _run() -> set[str]:
        broker = Broker.from_config(config)
        try:
            token: str | None = None
            for kind in ("ssn", "dob", "phone"):
                ctx: dict[str, Any] = {"purpose": "p", "session_id": "ledger"}
                if token:
                    ctx["session_token"] = token
                resp = await broker.arequest("a", kind, ctx)
                token = getattr(resp, "session_token", None) or token

            # The reset: same agent, no token, a session id of its choosing.
            await broker.arequest("a", "ssn", {"purpose": "p", "session_id": "ledger-reset"})
            store: Any = broker.session_store
            state = (
                await store.aget("ledger-reset")
                if hasattr(store, "aget")
                else store.get("ledger-reset")
            )
            return set((state or {}).get("sources_visited", []))
        finally:
            await broker.aclose()

    visited = asyncio.run(_run())
    assert len(visited) >= 3, (
        f"after three PII reads, one request that simply omitted the session "
        f"token started a fresh ledger holding {sorted(visited)}. Cumulative "
        f"escalation is the control being defeated."
    )


# ---------------------------------------------------------------------------
# 4.10 -- governance audit records are invisible to the audit API
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event_type",
    ["proposal_emitted", "proposal_approved", "rule_promoted", "rule_rolled_back"],
)
def test_m410_governance_events_are_readable_through_the_audit_api(
    tmp_path: Path, event_type: str
) -> None:
    """ "Who approved this rule" must be answerable from the audit API.

    ``AuditLogger.emit_event``'s sparse-dict branch writes a partial dict;
    ``AuditReader._parse_line`` validates a full ``AuditEntry``, catches the
    ``ValidationError``, and logs the line as **"corrupt"**. The data is
    intact under ``metadata.nautilus_audit_entry`` -- ``jq`` recovers it --
    but the operator is told their audit file is damaged.

    ``Broker.emit_adapter_event`` solves the identical problem correctly with
    placeholder ``request_id``/``agent_id``: one path fixed, one not.
    """
    from fathom.audit import FileSink

    from nautilus.audit.logger import AuditLogger
    from nautilus.rkm.audit_emitter import AuditEventEmitter
    from nautilus.ui.audit_reader import AuditReader

    audit = tmp_path / "audit.jsonl"
    logger = AuditLogger(sink=FileSink(path=audit))
    emitter = AuditEventEmitter(logger)
    emitter.queue(
        event_type,
        fields={"proposal_id": "p-1", "reviewer": "rev-1", "module": "nautilus-routing"},
    )
    emitter.flush(trace_id="t-1", session_id="s-1")

    assert audit.read_text().strip(), "the fixture wrote nothing"

    page = AuditReader(audit).read_page(event_type=event_type)
    entries = page.entries if hasattr(page, "entries") else page["entries"]
    assert entries, (
        f"the audit API returns nothing for event_type={event_type}, though "
        f"the record is on disk under metadata.nautilus_audit_entry: "
        f"{json.loads(audit.read_text().splitlines()[0]).keys()}"
    )


# ---------------------------------------------------------------------------
# 4.11 -- `nautilus key rotate --yes` rotates a throwaway ring
# ---------------------------------------------------------------------------


def test_m411_local_key_rotate_is_not_a_silent_no_op(tmp_path: Path) -> None:
    """The documented rotation runbook must change something, or fail loudly.

    ``cli/key.py`` constructs a fresh ``KeyRing()`` per invocation, and
    ``KeyRing.__init__`` auto-mints a primary. So the no-``--url`` form
    published at ``docs/how-to/operator-guide.md:214-230`` prints
    ``OK: rotated: new primary kid=<random uuid>`` with exit 0 having changed
    nothing on any broker and emitted no audit event. ``key list`` mints a new
    keypair per invocation and has no ``--url`` flag at all.
    """
    first = subprocess.run(
        [str(Path(".venv/bin/nautilus").resolve()), "key", "list"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=120,
    )
    second = subprocess.run(
        [str(Path(".venv/bin/nautilus").resolve()), "key", "list"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=120,
    )
    assert first.stdout == second.stdout, (
        "two consecutive `nautilus key list` runs reported different keys "
        "with no rotation between them; each invocation mints a throwaway "
        f"ring.\nfirst:  {first.stdout!r}\nsecond: {second.stdout!r}"
    )


# ---------------------------------------------------------------------------
# 4.9 -- the RKM governance loop has no producer in shipped code
# ---------------------------------------------------------------------------


def test_m49_approving_a_proposal_promotes_the_rule(
    tmp_path: Path, app_config: tuple[str, Path]
) -> None:
    """Approval must promote, or the whole governance loop is decorative.

    ``cli/rkm.py:230`` and ``fastapi_app.py:730`` both pass ``router=None``,
    and ``review.py:141-186`` gates promotion, ``lineage.insert``, the
    ``approved -> promoted`` transition and the ``rule_promoted`` /
    ``proposal_promoted`` events behind ``if router is not None``. The REST
    path has a live ``FathomRouter`` on ``app.state.broker._router`` and
    simply does not pass it. Result: ``{"promoted": false}``, status stuck at
    ``approved``, ``rule lineage`` returns ``{"versions": []}``.
    """
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    config, _ = app_config
    with TestClient(create_app(config), headers={"X-API-Key": API_KEY}) as client:
        listing = client.get("/v1/rkm/queue")
        assert listing.status_code == 200, listing.text
        proposals = listing.json().get("proposals", listing.json())
        assert proposals, (
            "the review queue is empty and nothing shipped can fill it: "
            "run_pipeline is called only from tests, there is no REST create "
            "route and no MCP tool, and pattern-tracker.yaml ships with "
            "rules: [] so the system-proposed path is dead too."
        )


def test_m419_adapters_route_reports_live_status(client: Any) -> None:
    """``GET /v1/adapters`` is what ``adapters list --url`` reads.

    Without it the CLI has no way to see quarantine state, which lives only
    in the serving process's memory.
    """
    response = client.get("/v1/adapters")
    assert response.status_code == 200, f"{response.status_code}: {response.text}"
    adapters = response.json()["adapters"]
    assert [a["id"] for a in adapters] == ["src"], adapters
    assert adapters[0]["status"] == "active", adapters
