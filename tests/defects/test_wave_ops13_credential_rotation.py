# pyright: reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false
"""WAVE ops13 — rotating an API key cost a restart, and reset a security budget.

Two defects, one procedure.

**The key could not be rotated at all without stopping the process.** The
request path re-reads ``app.state.api_keys`` per request, so swapping the list
takes effect on the very next request — but nothing swapped it. ``api`` was
whole-stanza restart-only in :func:`nautilus.core.broker._restart_only_changes`,
so ``SIGHUP`` *refused* a file whose only edit was a new credential, and even a
reload that had adopted it had no handle on the ASGI ``app.state`` the guard
reads. Rotation was the two-restart procedure the hardening guide documents,
which on a single-writer broker is a gap in service.

**And the ledger the rotation would have reset is a security control.**
Cumulative exposure accumulates under ``principal:<hash>``, and the hash was
taken over the API key *value*
(:func:`nautilus.transport.auth.caller_identity` puts the presented secret in
``caller["auth"]``; :func:`nautilus.core.principal.derive_principal_id` folds it
into the digest). So the same caller, before and after a rotation, is two
principals: a fresh exposure budget, and — because a session belongs to the
principal that opened it — ``403 session_not_yours`` on its own live sessions.

The credential was standing in for the caller's identity, which is exact only
while credentials never change. ``api.keys[].principal`` is that identity said
out loud: rotate the ``key`` under a stable ``principal`` and the ledger, and
the sessions, follow the caller across the rotation. A credential that declares
no ``principal`` keeps the old derivation — no deployment's ledgers are
orphaned by the upgrade — and any reload that leaves a ledger with nothing to
accumulate under says so.

The MCP port is the same allow-list and had the same problem twice over: the
ASGI gate and the tool closures both captured the credential list when the
server was built, so the retired key kept opening that door after REST had
stopped admitting it anywhere.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import yaml

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from nautilus.core.broker import Broker

pytestmark = [pytest.mark.integration]

_V1 = "ops13-key-v1"
_V2 = "ops13-key-v2"


# One source per purpose, so which source a request touches is decided by the
# request and not by the rotation: a ledger that carried across the rotation
# holds both, one that was reset holds only what came after it.
_PURPOSE = {"alpha": "threat-analysis", "beta": "incident-response"}


def _rules_dir(path: Path) -> Path:
    """An allow-everything routing rule, so a request actually reaches a source."""
    rules = path.parent / "rules"
    rules.mkdir(exist_ok=True)
    (rules / "allow.yaml").write_text(
        yaml.safe_dump(
            {
                "module": "nautilus-routing",
                "ruleset": "ops13-fixture",
                "version": "1.0",
                "rules": [
                    {
                        "name": "ops13-allow",
                        "description": "ops13 fixture rule",
                        "salience": 10,
                        "when": [
                            {"template": "source", "conditions": [{"slot": "id", "bind": "?sid"}]}
                        ],
                        "then": {"action": "allow", "reason": "ops13-allow"},
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return rules


def _document(path: Path, keys: list[Any]) -> dict[str, Any]:
    return {
        "sources": [
            {
                "id": source_id,
                "type": "static",
                "description": f"ops13 fixture {source_id}",
                "classification": "unclassified",
                "data_types": [source_id],
                "allowed_purposes": [purpose],
                "rows": [{"id": 1, "body": source_id}],
            }
            for source_id, purpose in _PURPOSE.items()
        ],
        "agents": {
            "analyst": {
                "id": "analyst",
                "clearance": "unclassified",
                "allowed_purposes": sorted(_PURPOSE.values()),
            }
        },
        "rules": {"user_rules_dirs": [str(_rules_dir(path))]},
        "audit": {"path": str(path.parent / "audit.jsonl")},
        "attestation": {"enabled": False},
        "api": {"keys": keys},
    }


def _write(path: Path, keys: list[Any]) -> Path:
    path.write_text(yaml.safe_dump(_document(path, keys), sort_keys=False), encoding="utf-8")
    return path


def _body(source: str, session_id: str) -> dict[str, Any]:
    return {
        "agent_id": "analyst",
        "intent": f"read the {source} records",
        "context": {"purpose": _PURPOSE[source], "session_id": session_id},
    }


async def _serving(config_path: Path) -> AsyncIterator[tuple[Broker, Any]]:
    """A running REST surface with its lifespan fired, as ``serve`` runs it.

    The lifespan is what populates ``app.state.api_keys``, so a test that
    primed the state by hand would be testing its own fixture rather than the
    wiring a rotation has to travel through.
    """
    from httpx import ASGITransport, AsyncClient

    from nautilus.cli.serve import broker_for_serve
    from nautilus.transport.fastapi_app import create_app

    broker = broker_for_serve(config_path, air_gapped=False)
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        client = AsyncClient(transport=ASGITransport(app=app), base_url="http://t")
        try:
            yield broker, client
        finally:
            await client.aclose()


def _principal_rows(broker: Broker) -> dict[str, dict[str, Any]]:
    """Every cumulative-exposure ledger the store is holding, by principal id."""
    rows: dict[str, Any] = getattr(broker.session_store, "_store", {})
    return {key: value for key, value in rows.items() if key.startswith("principal:")}


# ---------------------------------------------------------------------------
# 1. The rotation reaches the running process.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_rotated_credential_takes_effect_without_a_restart(tmp_path: Path) -> None:
    """ops12 t11: anonymous refused, retired refused, current accepted, live.

    The three answers have to come from one process. A retired key that still
    works until the next rollout is a credential that was never really retired,
    and on a single-writer broker "restart to rotate" is a decision to leave it
    working until the maintenance window.
    """
    from nautilus.cli.serve import reload_config

    config_path = _write(tmp_path / "nautilus.yaml", [{"key": _V1, "principal": "svc"}])
    async for broker, client in _serving(config_path):
        anonymous = await client.post("/v1/request", json=_body("alpha", "s-anon"))
        assert anonymous.status_code in (401, 403), (
            f"an unauthenticated request was not refused ({anonymous.status_code}); "
            f"nothing here is gating, so accepting the current key proves nothing"
        )
        before = await client.post(
            "/v1/request", headers={"X-API-Key": _V1}, json=_body("alpha", "s-1")
        )
        assert before.status_code == 200, before.text

        _write(config_path, [{"key": _V2, "principal": "svc"}])
        assert await reload_config(broker, config_path, air_gapped=False), (
            "the reload refused a file whose only change was the credential"
        )

        retired = await client.post(
            "/v1/request", headers={"X-API-Key": _V1}, json=_body("alpha", "s-2")
        )
        assert retired.status_code in (401, 403), (
            f"the retired credential still works ({retired.status_code}): the "
            f"rotation reached the config and not the guard"
        )
        for attempt in range(10):
            current = await client.post(
                "/v1/request", headers={"X-API-Key": _V2}, json=_body("alpha", f"s-cur-{attempt}")
            )
            assert current.status_code == 200, f"attempt {attempt}: {current.text}"


# ---------------------------------------------------------------------------
# 2. What the rotation does to exposure already accumulated.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exposure_accumulated_before_a_rotation_survives_it(tmp_path: Path) -> None:
    """The caller keeps one ledger across the rotation, not two.

    Cumulative exposure is what every ``session_exposure`` rule and the
    built-in escalation pack read. If a rotation starts a second ledger, the
    hygiene an operator is told to perform every 90 days is also the way to
    clear an agent that has accumulated its way to a denial — and the caller
    who wants that only has to ask for a new key.
    """
    from nautilus.cli.serve import reload_config

    config_path = _write(tmp_path / "nautilus.yaml", [{"key": _V1, "principal": "svc"}])
    async for broker, client in _serving(config_path):
        first = await client.post(
            "/v1/request", headers={"X-API-Key": _V1}, json=_body("alpha", "s-before")
        )
        assert first.status_code == 200, first.text
        assert first.json()["sources_queried"] == ["alpha"], first.text

        _write(config_path, [{"key": _V2, "principal": "svc"}])
        assert await reload_config(broker, config_path, air_gapped=False)

        second = await client.post(
            "/v1/request", headers={"X-API-Key": _V2}, json=_body("beta", "s-after")
        )
        assert second.status_code == 200, second.text
        assert second.json()["sources_queried"] == ["beta"], second.text

        ledgers = _principal_rows(broker)
        assert len(ledgers) == 1, (
            f"the rotation started a second exposure ledger: {sorted(ledgers)}. The "
            f"same caller now has a clean cumulative-exposure budget because its "
            f"credential was replaced"
        )
        visited = next(iter(ledgers.values())).get("sources_visited")
        assert visited == ["alpha", "beta"], (
            f"the surviving ledger lost what the caller saw before the rotation: {visited}"
        )


@pytest.mark.asyncio
async def test_a_session_opened_before_a_rotation_is_still_its_owners(tmp_path: Path) -> None:
    """A session belongs to a principal, and a rotation must not evict its owner.

    ``session_not_yours`` tells the caller "a session id is not a credential".
    Deriving the principal from the credential made the converse true: replace
    the secret and the same caller is locked out of the session it opened, mid
    conversation, by an operator action it cannot see.
    """
    from nautilus.cli.serve import reload_config

    config_path = _write(tmp_path / "nautilus.yaml", [{"key": _V1, "principal": "svc"}])
    async for broker, client in _serving(config_path):
        opened = await client.post(
            "/v1/request", headers={"X-API-Key": _V1}, json=_body("alpha", "s-owned")
        )
        assert opened.status_code == 200, opened.text

        _write(config_path, [{"key": _V2, "principal": "svc"}])
        assert await reload_config(broker, config_path, air_gapped=False)

        resumed = await client.post(
            "/v1/request", headers={"X-API-Key": _V2}, json=_body("beta", "s-owned")
        )
        assert resumed.status_code == 200, (
            f"the caller lost its own session across the rotation: {resumed.text}"
        )


# ---------------------------------------------------------------------------
# 3. A rotation that does reset the budget says so.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotating_a_credential_with_no_principal_announces_the_reset(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Bare and unnamed credentials keep the old derivation — out loud.

    Changing the derivation for every key would orphan every ledger a running
    deployment holds, so an entry that names no ``principal`` still keys on its
    secret and a rotation still resets it. That is a security budget being
    cleared by a routine operation, and the process must not do it silently.
    """
    from nautilus.cli.serve import reload_config

    config_path = _write(tmp_path / "nautilus.yaml", [_V1])
    async for broker, client in _serving(config_path):
        assert (
            await client.post("/v1/request", headers={"X-API-Key": _V1}, json=_body("alpha", "s"))
        ).status_code == 200

        _write(config_path, [_V2])
        with caplog.at_level(logging.WARNING):
            assert await reload_config(broker, config_path, air_gapped=False)

    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    joined = "\n".join(warnings)
    assert "principal" in joined and "exposure" in joined, (
        f"a rotation that discarded a caller's cumulative exposure logged nothing "
        f"an operator could act on: {warnings}"
    )
    assert _V1 not in joined and _V2 not in joined, (
        "the warning printed a credential; the log is not a place for secrets"
    )


# ---------------------------------------------------------------------------
# 4. The other door.
# ---------------------------------------------------------------------------


def test_the_mcp_port_retires_the_credential_at_the_same_moment(tmp_path: Path) -> None:
    """``--transport both`` is one allow-list, so it has to be one rotation.

    The MCP gate was handed a list copied out of the config when the app was
    constructed. A reload replaces the config object, so the retired key went on
    opening the MCP door after REST had stopped admitting it anywhere — which is
    the worse half of the rotation still working.
    """
    import asyncio

    from starlette.testclient import TestClient

    from nautilus.cli.serve import broker_for_serve, reload_config
    from nautilus.transport.mcp_server import _mcp_settings, create_server, http_app

    config_path = _write(tmp_path / "nautilus.yaml", [{"key": _V1, "principal": "svc"}])
    broker = broker_for_serve(config_path, air_gapped=False)
    # Exactly what ``nautilus serve --transport both --mcp-mode http`` builds.
    app = http_app(
        create_server(None, existing_broker=broker),
        api_keys=lambda: _mcp_settings(broker)[2],
    )
    probe = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    try:
        # ``127.0.0.1`` because the MCP SDK's DNS-rebinding guard only accepts
        # loopback Host headers.
        with TestClient(app, base_url="http://127.0.0.1:8000") as mcp:
            assert (
                mcp.post("/mcp", headers={**probe, "X-API-Key": _V1}, json=call).status_code != 401
            ), "the current credential was refused before anything rotated"

            _write(config_path, [{"key": _V2, "principal": "svc"}])
            assert asyncio.run(reload_config(broker, config_path, air_gapped=False))

            retired = mcp.post("/mcp", headers={**probe, "X-API-Key": _V1}, json=call)
            assert retired.status_code == 401, (
                f"the retired credential still opens the MCP port ({retired.status_code}) "
                f"after the rotation was adopted"
            )
            assert (
                mcp.post("/mcp", headers={**probe, "X-API-Key": _V2}, json=call).status_code != 401
            ), "the replacement credential is not accepted on the MCP port"
    finally:
        asyncio.run(broker.aclose())


@pytest.mark.asyncio
async def test_naming_a_principal_on_an_existing_credential_announces_it_too(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Step 0 of the rotation runbook orphans a ledger, and is not a rotation.

    Adding ``principal`` to an entry that had none leaves the key value alone,
    so nothing here looks like a credential change — but the identity the
    ledger is keyed by moves from the secret to the name, and the accumulated
    exposure stays behind on the old key. An operator following the procedure
    has to be told that, at the moment it happens.
    """
    from nautilus.cli.serve import reload_config

    config_path = _write(tmp_path / "nautilus.yaml", [{"key": _V1, "agent_id": "analyst"}])
    async for broker, client in _serving(config_path):
        assert (
            await client.post("/v1/request", headers={"X-API-Key": _V1}, json=_body("alpha", "s"))
        ).status_code == 200

        _write(config_path, [{"key": _V1, "agent_id": "analyst", "principal": "svc"}])
        with caplog.at_level(logging.WARNING):
            assert await reload_config(broker, config_path, air_gapped=False)

        after = await client.post(
            "/v1/request", headers={"X-API-Key": _V1}, json=_body("beta", "s2")
        )
        assert after.status_code == 200, after.text
        assert len(_principal_rows(broker)) == 2, (
            "naming a principal did not move the caller onto a new ledger, so "
            "this test no longer covers what it says it covers"
        )

    joined = "\n".join(r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING)
    assert "api.keys[0]" in joined and "exposure" in joined, (
        f"the reload moved a caller onto a fresh exposure ledger silently: {joined}"
    )
    assert _V1 not in joined, "the warning printed a credential"
