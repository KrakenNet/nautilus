"""One pin per Wave B1 item — binding an identity to the caller who asserted it.

Wave B1 is the §2 work of the readiness review: authentication and authorization
are fully decoupled today. The API key proves you may talk to the port; the
``agent_id`` in the request body decides what you may read, and nothing connects
the two. The receipt inherits the flaw — the attestation signs a name someone
typed, and with one shared key an operator cannot tell which credential to
revoke.

Each pin drives the surface a deployment actually presents: the REST app built
from a real ``nautilus.yaml``, or the broker as a library.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.defect

_SOURCE: dict[str, Any] = {
    "id": "src",
    "type": "postgres",
    "description": "a source",
    "classification": "unclassified",
    "data_types": ["patients"],
    "allowed_purposes": ["care"],
    # Never reached: every pin here is decided before any adapter connects.
    "connection": "postgresql://127.0.0.1:1/none",
    "table": "public.t",
}


def _config(tmp_path: Path, **overrides: Any) -> str:
    """Write a loadable ``nautilus.yaml`` and return its path."""
    config: dict[str, Any] = {
        "sources": [_SOURCE],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "rules": {"packs": [], "user_rules_dirs": []},
    }
    config.update(overrides)
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return str(path)


def _client(config_path: str, **client_kwargs: Any) -> Any:
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    return TestClient(create_app(config_path), **client_kwargs)


def _ask(client: Any, agent_id: str, **headers: str) -> Any:
    return client.post(
        "/v1/request",
        headers=headers,
        json={"agent_id": agent_id, "intent": "patients", "context": {"purpose": "care"}},
    )


# ===========================================================================
# B1a / B1b -- a key that names an agent, and the bare key that does not
# ===========================================================================


def test_b1a_a_key_bound_to_an_agent_refuses_to_speak_for_another(tmp_path: Path) -> None:
    """A structured key entry must gate ``body.agent_id``.

    The write guard authenticates the key and returns the raw header string;
    the handler then passes ``body.agent_id`` — the caller's own JSON — straight
    into ``broker.arequest``. The registry hands that name its clearance, so on
    the flagship example config every key is a key to every clearance.

    The control is the matching request: the same key asking for the agent it
    is bound to must be served, or this pin would pass on a broker that had
    stopped accepting anything.
    """
    config = _config(
        tmp_path,
        agents={
            "analyst": {"id": "analyst", "clearance": "unclassified"},
            "intern": {"id": "intern", "clearance": "unclassified"},
        },
        api={"keys": [{"key": "analyst-key", "agent_id": "analyst", "capabilities": ["query"]}]},
    )
    with _client(config) as client:
        impersonation = _ask(client, "intern", **{"X-API-Key": "analyst-key"})
        assert impersonation.status_code == 403, (
            f"a key bound to agent 'analyst' asserted agent_id='intern' and got "
            f"{impersonation.status_code}: authentication and authorization are "
            f"still fully decoupled"
        )
        own = _ask(client, "analyst", **{"X-API-Key": "analyst-key"})
        assert own.status_code == 200, (
            f"the bound key was refused for its own agent ({own.status_code}), so "
            f"the pin above proves nothing: {own.text}"
        )


def test_b1b_a_bare_key_keeps_working_and_says_what_it_is(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The bare-string key form must survive, and must announce itself.

    Every shipped example, the getting-started guide and the operator guide use
    ``keys: [<string>]``. That form stays root — bound to no agent, able to call
    every governance route — so the only honest thing to do is say so once at
    startup rather than silently.
    """
    import logging

    config = _config(tmp_path, api={"keys": ["bare-key"]})
    with caplog.at_level(logging.WARNING), _client(config) as client:
        served = _ask(client, "analyst", **{"X-API-Key": "bare-key"})
    assert served.status_code == 200, (
        f"a bare-string key stopped working ({served.status_code}); every shipped "
        f"example uses that form: {served.text}"
    )
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("bare" in message and "agent_id" in message for message in warnings), (
        f"startup said nothing about a key that is bound to no agent and can call "
        f"every governance route. Warnings seen: {warnings}"
    )


# ===========================================================================
# B1c -- capabilities gate the governance routes
# ===========================================================================


def test_b1c_a_query_only_key_cannot_govern(tmp_path: Path) -> None:
    """Governance must be a capability, not a side effect of holding any key.

    ``/v1/rkm/queue``, the approve/reject pair, rule retract/rollback and key
    rotate/revoke all sit behind the same ``_write_guard`` as ``/v1/request``,
    so any key that can ask a question can also rewrite the policy that answers
    it and rotate the signing key that attests to it.

    The control is the second key, which declares ``govern`` and must get past
    the guard — whatever the route then makes of an empty body.
    """
    config = _config(
        tmp_path,
        api={
            "keys": [
                {"key": "reader", "agent_id": "analyst", "capabilities": ["query"]},
                {"key": "ops", "agent_id": "analyst", "capabilities": ["query", "govern"]},
            ]
        },
    )
    with _client(config) as client:
        refused = client.post("/v1/rkm/queue", headers={"X-API-Key": "reader"}, json={})
        assert refused.status_code == 403, (
            f"a key declaring only 'query' submitted to the rule queue and got "
            f"{refused.status_code}: every key is still a root key"
        )
        allowed = client.post("/v1/rkm/queue", headers={"X-API-Key": "ops"}, json={})
        assert allowed.status_code != 403, (
            f"the control key declares 'govern' and was still refused "
            f"({allowed.status_code}), so the pin above proves nothing"
        )


# ===========================================================================
# B1d -- proxy_trust binds the forwarded identity to a declared subject
# ===========================================================================


def test_b1d_proxy_trust_binds_the_forwarded_user_to_an_agent(tmp_path: Path) -> None:
    """The one cryptographically bound path must actually bind something.

    ``proxy_trust`` is where an ingress terminates mTLS/SPIFFE/OIDC and forwards
    the resolved identity. Nautilus reads the header, checks the peer, and then
    routes on whatever ``agent_id`` the body claims anyway.

    The control is the request that names the agent the subject maps to.
    """
    config = _config(
        tmp_path,
        agents={
            "analyst": {
                "id": "analyst",
                "clearance": "unclassified",
                "subject": "spiffe://corp/ns/agents/sa/analyst",
            },
            "intern": {"id": "intern", "clearance": "unclassified"},
        },
        api={
            "keys": ["unused"],
            "auth": {"mode": "proxy_trust", "trusted_proxies": ["10.0.0.0/8"]},
        },
    )
    forwarded = {"X-Forwarded-User": "spiffe://corp/ns/agents/sa/analyst"}
    with _client(config, client=("10.0.0.5", 40000)) as client:
        impersonation = _ask(client, "intern", **forwarded)
        assert impersonation.status_code == 403, (
            f"the proxy authenticated the analyst's SPIFFE id and the body asked as "
            f"'intern'; the broker answered {impersonation.status_code}"
        )
        own = _ask(client, "analyst", **forwarded)
        assert own.status_code == 200, (
            f"the forwarded subject was refused for its own agent ({own.status_code}): {own.text}"
        )


# ===========================================================================
# B1e -- an agent's allowed_purposes are enforced when routing
# ===========================================================================


def test_b1e_an_agents_allowed_purposes_are_enforced(tmp_path: Path) -> None:
    """``purpose`` is a live authorization input that the caller types.

    ``deny-purpose-mismatch`` and the HIPAA pack's ``deny-phi-outside-tpo`` both
    gate on it, and nothing bounds which purposes an agent may claim. An
    operator who has written down what an agent is for has nowhere to put it.

    The control is the same agent asking for a purpose it does hold.
    """
    import asyncio

    from nautilus import Broker

    # The source itself permits both purposes, so only the agent-level
    # restriction can deny: otherwise this pin passes on the source's own
    # ``allowed_purposes`` and proves nothing about the agent's.
    config = _config(
        tmp_path,
        sources=[{**_SOURCE, "allowed_purposes": ["care", "marketing"]}],
        agents={
            "analyst": {
                "id": "analyst",
                "clearance": "unclassified",
                "allowed_purposes": ["care"],
            }
        },
    )

    async def _denied(purpose: str) -> list[str]:
        broker = Broker.from_config(config)
        try:
            response = await broker.arequest("analyst", "patients", {"purpose": purpose})
            return list(response.sources_denied)
        finally:
            await broker.aclose()

    assert asyncio.run(_denied("marketing")) == ["src"], (
        "the agent declared allowed_purposes: [care] and was routed for 'marketing'"
    )
    assert asyncio.run(_denied("care")) == [], (
        "the agent was denied a purpose it holds, so the pin above proves nothing"
    )


# ===========================================================================
# B1f / B1g -- the receipt names the credential, not just the asserted agent
# ===========================================================================


def _one_request(config: str, caller: dict[str, str]) -> Any:
    import asyncio

    from nautilus import Broker

    async def _go() -> Any:
        broker = Broker.from_config(config)
        try:
            return await broker.arequest("analyst", "patients", {"purpose": "care"}, caller=caller)
        finally:
            await broker.aclose()

    return asyncio.run(_go())


def test_b1f_the_audit_entry_names_the_principal_it_decided_for(tmp_path: Path) -> None:
    """An auditor must be able to tell which credential to revoke.

    ``AuditEntry`` carries ``agent_id`` and no authenticated-caller field, while
    ``state.principal_id`` — already a SHA-256 prefix, so it leaks no secret —
    exists at emit time and is thrown away.
    """
    from fathom.models import AuditRecord

    from nautilus.audit.logger import decode_nautilus_entry
    from nautilus.core.principal import derive_principal_id

    audit_path = tmp_path / "audit.jsonl"
    config = _config(tmp_path, audit={"path": str(audit_path)})
    _one_request(config, {"auth": "the-key", "peer": "10.0.0.5"})

    # Each JSONL line is an outer Fathom record carrying the Nautilus entry —
    # the same double-parse the admin UI's reader does. The file also holds the
    # attestation event, so pick the routing entry by its event type.
    decoded = [
        decode_nautilus_entry(AuditRecord.model_validate(json.loads(line)))
        for line in audit_path.read_text(encoding="utf-8").strip().split("\n")
    ]
    requests = [e for e in decoded if e.event_type == "request"]
    assert requests, "no routing entry was written to the audit log"
    entry = requests[0]
    expected = derive_principal_id("analyst", auth_principal="the-key", peer="10.0.0.5")
    assert getattr(entry, "principal_id", None) == expected, (
        f"the receipt records agent_id={entry.agent_id!r} and no authenticated "
        f"caller, so an operator with one shared key cannot tell whose request "
        f"this was. principal_id={getattr(entry, 'principal_id', None)!r}"
    )


def test_b1g_the_attestation_binds_the_authenticated_caller(tmp_path: Path) -> None:
    """The signature is sound and the claim it signs is a name someone typed.

    ``decision`` is ``nautilus:{request_id}:agent={agent_id}``. Two different
    credentials asserting the same ``agent_id`` produce the same claim, so the
    signed record cannot distinguish them.
    """
    import jwt as pyjwt

    config = _config(tmp_path, attestation={"enabled": True})
    response = _one_request(config, {"auth": "the-key", "peer": "10.0.0.5"})
    assert response.attestation_token, "no attestation token was issued"
    claims = pyjwt.decode(response.attestation_token, options={"verify_signature": False})
    assert "principal=" in claims["decision"], (
        f"the signed decision is {claims['decision']!r}: it names the asserted "
        f"agent and nothing about the credential that asserted it"
    )


# ===========================================================================
# B1h -- a session token is bound to the agent it was minted for
# ===========================================================================


def test_b1h_a_session_token_minted_for_another_agent_is_refused(tmp_path: Path) -> None:
    """A bearer token that any agent can present is a session anyone can join.

    ``_verify_handoff_token`` already makes exactly this check on the handoff
    path (``broker.py:1655``); the request path verifies the signature and the
    expiry and then takes the token's ``session_id`` while ignoring its
    ``agent_id``, so agent B can inherit agent A's session — and its exposure
    ledger — by replaying A's token.

    The control is the token presented by the agent it was minted for.
    """
    import asyncio

    from nautilus import Broker
    from nautilus.attestation.session_token import SessionTokenError

    config = _config(
        tmp_path,
        agents={
            "analyst": {"id": "analyst", "clearance": "unclassified"},
            "intern": {"id": "intern", "clearance": "unclassified"},
        },
        session_tokens={"enabled": True},
    )

    async def _go() -> tuple[str, Any, Any]:
        broker = Broker.from_config(config)
        try:
            minted = await broker.arequest("analyst", "patients", {"purpose": "care"})
            token = minted.session_token
            assert token, "no session token was minted"
            replayed: Any
            try:
                await broker.arequest(
                    "intern", "patients", {"purpose": "care", "session_token": token}
                )
                replayed = None
            except SessionTokenError as exc:
                replayed = exc
            own = await broker.arequest(
                "analyst", "patients", {"purpose": "care", "session_token": token}
            )
            return token, replayed, own
        finally:
            await broker.aclose()

    _token, replayed, own = asyncio.run(_go())
    assert replayed is not None, (
        "agent 'intern' presented a token minted for 'analyst' and the request "
        "was served, inheriting that session's exposure ledger"
    )
    assert own is not None, "the agent the token was minted for was refused its own token"


# ===========================================================================
# B1i -- the read surfaces are authenticated
# ===========================================================================


@pytest.mark.parametrize("path", ["/v1/sources", "/v1/adapters"])
def test_b1i_the_inventory_routes_require_a_credential(tmp_path: Path, path: str) -> None:
    """What sources exist, and how they are classified, is not public.

    Every other ``/v1`` route is guarded. These two enumerate the deployment's
    sources, their classifications and their data types to anyone who can reach
    the port — which is the reconnaissance step before an impersonation attempt.

    The control is the same request with the key.
    """
    config = _config(tmp_path, api={"keys": ["k1"]})
    with _client(config) as client:
        anonymous = client.get(path)
        assert anonymous.status_code in (401, 403), (
            f"GET {path} answered {anonymous.status_code} with no credential: "
            f"{anonymous.text[:200]}"
        )
        authenticated = client.get(path, headers={"X-API-Key": "k1"})
        assert authenticated.status_code == 200, (
            f"GET {path} refused a valid key ({authenticated.status_code}), so the "
            f"pin above proves nothing"
        )


# ===========================================================================
# B1j -- the reviewer on a governance action is the authenticated caller
# ===========================================================================


def test_b1j_the_rkm_reviewer_is_the_authenticated_caller(tmp_path: Path) -> None:
    """A reviewer header names a reviewer; it does not authenticate one.

    ``X-Nautilus-Reviewer``'s own module docstring says exactly that, and the
    approve/reject routes take it as the identity written into the lineage
    record. A caller with any key can sign any name to a policy change.

    The control is the bare-key path, which has no bound identity and must keep
    falling back to the header rather than 500ing or refusing.
    """
    config = _config(
        tmp_path,
        api={
            "keys": [
                {"key": "ops", "agent_id": "analyst", "capabilities": ["query", "govern"]},
                "bare",
            ]
        },
    )
    with _client(config) as client:
        bound = client.post("/v1/rkm/queue/no-such-proposal/approve", headers={"X-API-Key": "ops"})
        assert bound.status_code == 404, (
            f"a caller whose key is bound to agent 'analyst' approved without "
            f"X-Nautilus-Reviewer and got {bound.status_code}; the route still "
            f"demands the self-asserted header instead of using the resolved caller"
        )
        bare = client.post("/v1/rkm/queue/no-such-proposal/approve", headers={"X-API-Key": "bare"})
        assert bare.status_code == 400, (
            f"the unbound control key got {bare.status_code}; with no identity to "
            f"derive a reviewer from, the header is still required"
        )


# ===========================================================================
# B1k -- every route that answers about the deployment is guarded
# ===========================================================================


def test_b1k_every_v1_route_requires_a_credential(tmp_path: Path) -> None:
    """The enumeration this file exists to make impossible to lose again.

    ``/v1/sources`` and ``/v1/adapters`` were open because nothing walked the
    route table and asked. This walks it: every ``/v1`` route must refuse an
    anonymous caller, except the two that are deliberately public — the JWKS a
    verifier needs before it has any credential, and nothing else.
    """
    from fastapi.routing import APIRoute

    from nautilus.transport.fastapi_app import create_app

    public = {"/v1/keys/jwks.json"}
    app = create_app(_config(tmp_path, api={"keys": ["k1"]}))
    routes = [
        r
        for r in app.routes
        if isinstance(r, APIRoute) and r.path.startswith("/v1") and r.path not in public
    ]
    assert routes, "no /v1 routes were found — the walk itself is broken"

    from fastapi.testclient import TestClient

    open_routes: list[str] = []
    with TestClient(app) as client:
        for route in routes:
            method = "POST" if "POST" in route.methods else "GET"
            path = route.path.replace("{proposal_id}", "p").replace("{rule_name}", "r")
            path = path.replace("{request_id}", "r").replace("{kid}", "k").replace("{name}", "n")
            response = client.request(method, path, json={})
            if response.status_code not in (401, 403):
                open_routes.append(f"{method} {route.path} -> {response.status_code}")
    assert not open_routes, f"these routes answered an anonymous caller: {open_routes}"
