# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false, reportPrivateUsage=false
"""WAVE E14 — the minors from the same live-fire re-run, all reproduced first.

1. **The source catalogue is not clearance-aware.** ``GET /v1/sources`` and the
   console's ``/admin/sources`` hand every caller every source's description,
   classification and data types. No rows — but "the crown jewels, classified
   secret, holds ``crown-jewels``" is what an unclassified key is not supposed
   to learn, and the route already knows which agent is asking.

2. **Two documented metrics are missing from a cold ``/metrics``.** The
   operator guide names ``nautilus_scope_denials_total`` and
   ``nautilus_adapter_errors_total`` as things to alert on. An OTEL counter is
   not exported until it is first incremented, so an alert written against a
   fresh broker matches nothing and reads as healthy.

3. **``nautilus demo`` describes an audit log nobody can open.** It announces
   the entries, then deletes the temp directory holding them on the way out.
   The demo's whole claim is "every decision is recorded" and it shows none of
   it.

4. **The schema-version gate has no way past it.** Wave E11 refuses a store
   stamped for another version and names three options: a fresh file, the
   matching build, or nothing. There is no supported migration, and no command
   that says what version a store carries.

5. **Forgetting ``setup()`` reports the store as down.** ``afrom_config``
   without ``setup()`` fails the first request with
   ``SessionStoreUnavailableError`` — which is the class
   ``session_store.on_failure: fallback_memory`` exists to swallow, so the same
   mistake silently degrades a durable store to memory instead of failing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_KEY = "e14-key"


def _config(path: Path, **overrides: Any) -> str:
    document: dict[str, Any] = {
        "sources": [
            {
                "id": "orders",
                "type": "static",
                "classification": "unclassified",
                "data_types": ["orders"],
                "rows": [{"order_id": 1}],
            },
            {
                "id": "crown_jewels",
                "type": "static",
                "classification": "secret",
                "description": "the crown jewels",
                "data_types": ["crown-jewels"],
                "rows": [{"k": 1}],
            },
        ],
        "agents": {"a1": {"id": "a1", "clearance": "unclassified"}},
        "audit": {"path": str(path.parent / "audit.jsonl")},
        "api": {
            "keys": [{"key": _KEY, "agent_id": "a1", "capabilities": ["query", "audit_read"]}]
        },
    }
    document.update(overrides)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


async def _client(config: str) -> Any:
    from httpx import ASGITransport, AsyncClient

    from nautilus.core.broker import Broker
    from nautilus.transport.fastapi_app import create_app

    broker = await Broker.afrom_config(config)
    await broker.setup()
    app = create_app(None, existing_broker=broker)
    app.state.broker = broker
    app.state.ready = True
    app.state.api_keys = broker.config.api.keys
    app.state.auth_mode = "api_key"
    app.state.key_ring = broker.key_ring
    app.state.broker_instance_id = broker.instance_id
    return broker, AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


# ---------------------------------------------------------------------------
# 1. The catalogue answers what the caller may know about.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e14_the_catalogue_hides_what_the_caller_cannot_reach(tmp_path: Path) -> None:
    """A source's existence, purpose and shape is not free information.

    The router already refuses an unclassified agent every ``secret`` source.
    Listing them anyway means the catalogue tells a caller exactly what it is
    being kept from — name, prose description, and the data types to ask for —
    which is the reconnaissance step the classification rules exist to stop.
    """
    broker, client = await _client(_config(tmp_path / "nautilus.yaml"))
    try:
        listed = await client.get("/v1/sources", headers={"X-API-Key": _KEY})
    finally:
        await client.aclose()
        await broker.aclose()

    assert listed.status_code == 200, listed.text
    ids = {s["id"] for s in listed.json()["sources"]}
    assert "orders" in ids, f"the caller lost a source it can read: {ids}"
    assert "crown_jewels" not in ids, (
        f"an unclassified-clearance key was shown a secret source: "
        f"{listed.json()['sources']}"
    )
    assert "crown jewels" not in listed.text, "the description leaked with it"


@pytest.mark.asyncio
async def test_e14_a_root_key_still_sees_the_whole_catalogue(tmp_path: Path) -> None:
    """Control: a bare key names its own agent, so it is not filtered by one.

    The bare-string key form is documented as "any agent_id, every
    capability". It has no bound agent to derive a clearance from, so there is
    nothing to filter against and the operator-facing listing must stay whole.
    """
    config = _config(tmp_path / "nautilus.yaml", api={"keys": [_KEY]})
    broker, client = await _client(config)
    try:
        listed = await client.get("/v1/sources", headers={"X-API-Key": _KEY})
    finally:
        await client.aclose()
        await broker.aclose()
    ids = {s["id"] for s in listed.json()["sources"]}
    assert ids == {"orders", "crown_jewels"}, ids


# ---------------------------------------------------------------------------
# 2. A documented metric exists before it first fires.
# ---------------------------------------------------------------------------


def test_e14_documented_counters_are_present_on_a_cold_metrics(tmp_path: Path) -> None:
    """An alert on a series that does not exist yet is an alert that never fires.

    Both counters are named in the operator guide as things to page on. OTEL
    does not export a counter until its first ``add``, so on a broker that has
    denied nothing and errored nothing the series are simply absent — and
    ``rate(nautilus_scope_denials_total[5m]) > 0`` on a dashboard reads as "no
    denials" rather than "no data".

    Driven through ``TestClient`` because the meter provider is installed in
    the lifespan, and that is the only thing that makes the exporter real.
    """
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    config = _config(tmp_path / "nautilus.yaml")
    with TestClient(create_app(config)) as client:
        cold = client.get("/metrics", headers={"X-API-Key": _KEY})

    if cold.status_code == 404:
        pytest.skip("prometheus exporter not installed in this environment")
    assert cold.status_code == 200, cold.text
    for name in ("nautilus_scope_denials_total", "nautilus_adapter_errors_total"):
        assert name in cold.text, (
            f"{name} is documented as alertable but is absent from a cold "
            f"/metrics, so an alert written against it matches nothing"
        )


# ---------------------------------------------------------------------------
# 3. The demo shows the thing it claims.
# ---------------------------------------------------------------------------


def test_e14_the_demo_shows_an_audit_entry_it_still_has() -> None:
    """"Every decision is recorded" is a claim the demo can just demonstrate.

    It writes real entries into a temp directory and deletes it on the way out,
    so the one line about the audit log points at a path that no longer exists
    by the time the reader finishes reading it.
    """
    result = subprocess.run(  # noqa: S603 — this interpreter, a literal argv
        [sys.executable, "-m", "nautilus", "demo"],
        check=False,
        capture_output=True,
        timeout=180,
        cwd=_REPO_ROOT,
    )
    out = result.stdout.decode("utf-8", "replace")
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-2000:]
    assert "audit" in out.lower(), out

    # The demo must put a real recorded decision in front of the reader, not
    # only assert that one exists somewhere it has already deleted.
    start = out.find("{")
    assert start != -1, (
        "the demo says the decisions were appended to an audit log and shows "
        "none of it; the directory holding it is deleted when the demo exits"
    )
    decoder = json.JSONDecoder()
    entry: dict[str, Any] = decoder.raw_decode(out[start:])[0]
    assert entry.get("event_type") == "handoff_declared", (
        f"the demo printed the sink's wrapper rather than the Nautilus audit "
        f"entry every doc describes: {sorted(entry)}"
    )
    assert entry.get("request_id"), entry


# ---------------------------------------------------------------------------
# 4. There is a way to look at, and move, a stamped store.
# ---------------------------------------------------------------------------


def test_e14_the_cli_can_report_a_store_schema_version(tmp_path: Path) -> None:
    """The gate refuses by version number and nothing reports the number.

    An operator who hits "carries schema version 2, this build understands 1"
    has no command that says what any store carries, so the first step of
    diagnosing a stuck rollout is reading Nautilus's source.
    """
    import asyncio

    from nautilus.core.session_sqlite import SqliteSessionStore

    db = tmp_path / "sessions.db"

    async def _make() -> None:
        store = SqliteSessionStore(str(db))
        await store.setup()
        await store.aclose()

    asyncio.run(_make())

    result = subprocess.run(  # noqa: S603 — this interpreter, a literal argv
        [sys.executable, "-m", "nautilus", "session", "version", "--sqlite-path", str(db)],
        check=False,
        capture_output=True,
        timeout=120,
        cwd=_REPO_ROOT,
    )
    out = (result.stdout + result.stderr).decode("utf-8", "replace")
    assert result.returncode == 0, out[-2000:]
    assert "1" in out, f"the command reported no version: {out!r}"


# ---------------------------------------------------------------------------
# 5. Forgetting setup() says so.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e14_a_broker_without_setup_does_not_look_like_a_down_store(
    tmp_path: Path,
) -> None:
    """``SessionStoreUnavailableError`` is the class ``on_failure`` swallows.

    A durable store used before ``setup()`` raises exactly the error
    ``session_store.on_failure: fallback_memory`` exists to degrade past, so
    the same forgotten call that fails loudly in one config silently drops a
    deployment to an in-memory ledger in another.
    """
    from nautilus.core.broker import Broker

    config = _config(
        tmp_path / "nautilus.yaml",
        session_store={"backend": "sqlite", "sqlite_path": str(tmp_path / "s.db")},
    )
    broker = await Broker.afrom_config(config)
    try:
        response = await broker.arequest(
            "a1", "recent orders", {"purpose": "analytics", "session_id": "s"}
        )
    finally:
        await broker.aclose()

    assert response.outcome != "errored", (
        "a broker built with afrom_config and used without an explicit setup() "
        "failed its first request; the session store connects lazily like every "
        "adapter does"
    )


@pytest.mark.asyncio
async def test_e14_calling_setup_twice_is_still_fine(tmp_path: Path) -> None:
    """Control: setup() is documented idempotent and must stay so."""
    from nautilus.core.broker import Broker

    config = _config(
        tmp_path / "nautilus.yaml",
        session_store={"backend": "sqlite", "sqlite_path": str(tmp_path / "s.db")},
    )
    broker = await Broker.afrom_config(config)
    try:
        await broker.setup()
        await broker.setup()
        response = await broker.arequest(
            "a1", "recent orders", {"purpose": "analytics", "session_id": "s"}
        )
    finally:
        await broker.aclose()
    assert response.outcome != "errored"
