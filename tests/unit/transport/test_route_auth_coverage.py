"""Every route is authenticated unless it is deliberately public.

The RKM queue and rule-governance routes shipped ungated: with
``api.auth.mode: api_key`` set and a key configured, ``POST /v1/request``
401'd while ``GET /v1/rkm/queue`` returned every pending proposal's full
rule body and ``POST /v1/rules/{name}/retract`` retired a rule under an
attacker-chosen reviewer. Their only gate was ``X-Nautilus-Reviewer``,
which names a reviewer rather than authenticating one.

The first test is the drift guard: it reads the route table rather than a
hand-written list, so a route added later is a failure unless someone puts
it in :data:`PUBLIC_ROUTES` on purpose. The rest prove the gate is live and
not merely declared.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.routing import APIRoute
from starlette.routing import Route
from starlette.testclient import TestClient

from nautilus.transport.fastapi_app import create_app

pytestmark = pytest.mark.unit

# Routes that must stay reachable without a credential, each with the reason.
PUBLIC_ROUTES: dict[str, str] = {
    "/healthz": "liveness probe — must answer during unauthenticated restarts",
    "/readyz": "readiness probe — same",
    "/v1/keys/jwks.json": "public verification keys, public by definition",
    "/v1/sources": "metadata-only listing, AC-12.3 (no DSNs or credentials)",
    "/v1/adapters/{name}/schema": "adapter capability discovery, AC-21.a",
    "/metrics": "Prometheus scrape target",
    "/": "redirect to /admin, which carries its own session auth",
}

# The admin UI mounts its own router with session auth; it is out of scope here.
_ADMIN_PREFIXES = ("/admin", "/static")

# FastAPI's own docs routes are plain Starlette routes with no dependency
# support, so they cannot carry a guard and are excluded by the APIRoute
# filter below. They serve the schema of the API, not its data.
_DOCS_ROUTES = frozenset({"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"})

API_KEY = "topsecret"


def _broker() -> Any:
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()
    store = MagicMock()
    store.aget = AsyncMock(return_value=None)
    broker.session_store = store
    broker.sources = []
    broker.arequest = AsyncMock()
    broker._config = SimpleNamespace(
        api=SimpleNamespace(auth=SimpleNamespace(mode="api_key"), keys=[API_KEY]),
        audit=SimpleNamespace(path="audit.jsonl"),
    )
    return broker


@pytest.fixture()
def client() -> TestClient:
    c = TestClient(create_app(None, existing_broker=_broker()))
    c.__enter__()
    try:
        yield c
    finally:
        c.__exit__(None, None, None)


def _guard_names(route: APIRoute) -> set[str]:
    return {d.call.__name__ for d in route.dependant.dependencies if d.call is not None}


def test_every_route_is_gated_or_explicitly_public() -> None:
    """A new route must be gated or listed in PUBLIC_ROUTES, never neither."""
    app = create_app(None, existing_broker=_broker())
    ungated = [
        r.path
        for r in app.routes
        if isinstance(r, APIRoute)
        and not r.path.startswith(_ADMIN_PREFIXES)
        and r.path not in PUBLIC_ROUTES
        and not {"_write_guard", "_read_guard"} & _guard_names(r)
    ]
    assert ungated == [], f"routes with no auth dependency and no PUBLIC_ROUTES entry: {ungated}"


def test_only_the_docs_routes_escape_the_dependency_check() -> None:
    """Nothing but FastAPI's docs slips past the APIRoute filter above."""
    app = create_app(None, existing_broker=_broker())
    skipped = {
        r.path
        for r in app.routes
        if isinstance(r, Route)
        and not isinstance(r, APIRoute)
        and not r.path.startswith(_ADMIN_PREFIXES)
    }
    assert skipped <= _DOCS_ROUTES, f"unchecked non-APIRoute routes: {skipped - _DOCS_ROUTES}"


def test_public_routes_list_has_no_dead_entries() -> None:
    """PUBLIC_ROUTES must not accumulate paths the app no longer serves."""
    app = create_app(None, existing_broker=_broker())
    served = {r.path for r in app.routes if isinstance(r, Route)}
    assert set(PUBLIC_ROUTES) <= served, f"stale entries: {set(PUBLIC_ROUTES) - served}"


GOVERNANCE_CALLS: list[tuple[str, str]] = [
    ("GET", "/v1/rkm/queue"),
    ("GET", "/v1/rkm/queue/prop_1"),
    ("POST", "/v1/rkm/queue/prop_1/approve"),
    ("POST", "/v1/rkm/queue/prop_1/reject"),
    ("GET", "/v1/rules/deny_phi/lineage"),
    ("POST", "/v1/rules/deny_phi/retract"),
    ("POST", "/v1/rules/deny_phi/rollback"),
]


@pytest.mark.parametrize(("method", "path"), GOVERNANCE_CALLS)
def test_governance_route_rejects_a_missing_key(client: TestClient, method: str, path: str) -> None:
    resp = client.request(method, path, headers={"X-Nautilus-Reviewer": "attacker"})
    assert resp.status_code in (401, 403), f"{method} {path} -> {resp.status_code}"


@pytest.mark.parametrize(("method", "path"), GOVERNANCE_CALLS)
def test_governance_route_rejects_a_wrong_key(client: TestClient, method: str, path: str) -> None:
    resp = client.request(
        method,
        path,
        headers={"X-API-Key": "wrong", "X-Nautilus-Reviewer": "attacker"},
    )
    assert resp.status_code in (401, 403), f"{method} {path} -> {resp.status_code}"


@pytest.mark.parametrize(("method", "path"), GOVERNANCE_CALLS)
def test_a_valid_key_gets_past_the_gate(client: TestClient, method: str, path: str) -> None:
    """The gate must not be a blanket deny: a real key reaches the handler.

    The handlers then 404 on the fabricated proposal/rule ids, which is the
    point — anything other than 401/403 means authentication passed.
    """
    resp = client.request(
        method,
        path,
        headers={"X-API-Key": API_KEY, "X-Nautilus-Reviewer": "operator"},
    )
    assert resp.status_code not in (401, 403), f"{method} {path} -> {resp.status_code}"


@pytest.mark.parametrize("path", sorted(PUBLIC_ROUTES))
def test_public_route_needs_no_key(client: TestClient, path: str) -> None:
    if path == "/metrics":
        pytest.importorskip("prometheus_client")
    resp = client.get(path.replace("{name}", "postgres"), follow_redirects=False)
    assert resp.status_code not in (401, 403), f"GET {path} -> {resp.status_code}"
