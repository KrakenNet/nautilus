"""WAVE E6 — the four security majors from the live-fire audit.

Every one reproduced first-hand before a line of fix was written.

1. **``POST /v1/sessions`` performs no authorization.** The route is
   authenticated and gated on the ``query`` capability, then passes
   ``body["agent_id"]``, ``body["purpose"]`` and ``body["clearance"]`` straight
   into the signer. A key bound to ``intern`` mints::

       {"agent_id": "cleared", "clearance": "top-secret",
        "session_id": "victim-session", ...}

   and that JWS verifies against ``GET /v1/keys/jwks.json``, which is
   unauthenticated by design. The broker itself is not fooled — it reads
   clearance from the AgentRegistry, which is why this is major and not a
   blocker — but ``nautilus/adapters/base.py`` forwards the token downstream as
   ``X-Nautilus-Session-Token`` and ``docs/how-to/verify-a-token.md`` tells
   third parties to trust its claims. The broker's own minting path already
   reads clearance from the registry; this endpoint is the one that does not.

2. **The MCP transport enforces no capabilities.** ``verify_api_key`` asks only
   whether the secret matches *some* configured entry. A key configured
   ``{capabilities: [audit_read]}`` gets 403 on ``/v1/request`` and runs
   ``nautilus_request`` over MCP in the same breath. The agent binding does
   hold on MCP, so a credential stays inside its own agent's entitlements —
   what it gains is the whole query surface.

3. **The signed response hash cannot be recomputed from the wire.**
   ``_stable_json`` hashes the adapter's Python objects with ``default=str``,
   so a ``datetime`` is committed as ``"2026-08-28 15:17:50.955432+00:00"``
   while the caller receives ``"2026-08-28T15:17:50.955432Z"``::

       claimed     sha256:f1ce3bab0b8d3dcc581e7a2c996d3265f3d630512263e5966336c8f8942d94da
       recomputed  sha256:d027a32c8c0076cd27b24d1ea0844fcd7ccb86ae40604790d7d16c19a74c55e1

   Nothing stores the rows — not the token, not the audit log, not the
   attestation sink — so the wire response is the only copy, and it does not
   verify. An honest response is indistinguishable from a tampered one, which
   is the one direction the claim exists to rule out.

4. **No bound on what a request may send.** ``BrokerRequest.intent`` is a bare
   ``str`` and no body-size limit exists anywhere in the transport, while the
   audit entry stores the raw intent three times. Measured: a 4 MB intent is
   accepted and writes 12.6 MB to the audit log in 0.22 s. The audit sink is
   the fail-closed path — ``/readyz`` returns 503 on ``audit_logger.probe()``
   — so filling the volume drains every replica rather than degrading one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

_BOUND_KEY = "intern-key"
_AUDIT_ONLY_KEY = "auditonly-key"


def _write(tmp_path: Path, document: dict[str, Any]) -> str:
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


def _rest(config_path: str) -> Any:
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    return TestClient(create_app(config_path))


def _mcp_handshake(client: Any, headers: dict[str, str]) -> dict[str, str]:
    """Initialize a streamable-HTTP MCP session; return headers carrying its id."""
    init = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "wave-e6", "version": "0"},
            },
        },
    )
    assert init.status_code == 200, f"control failed: MCP initialize said {init.text}"
    session_id = init.headers.get("mcp-session-id")
    assert session_id, "control failed: the MCP server issued no session id"
    session_headers = {**headers, "mcp-session-id": session_id}
    client.post(
        "/mcp",
        headers=session_headers,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    return session_headers


# ---------------------------------------------------------------------------
# 1. POST /v1/sessions authorizes nothing.
# ---------------------------------------------------------------------------


def _token_config(tmp_path: Path) -> str:
    return _write(
        tmp_path,
        {
            "sources": [
                {
                    "id": "orders",
                    "type": "static",
                    "classification": "unclassified",
                    "data_types": ["orders"],
                    "rows": [{"id": 1}],
                }
            ],
            "agents": {
                "intern": {"id": "intern", "clearance": "unclassified"},
                "cleared": {"id": "cleared", "clearance": "confidential"},
            },
            "audit": {"path": str(tmp_path / "audit.jsonl")},
            "api": {"keys": [{"key": _BOUND_KEY, "agent_id": "intern", "capabilities": ["query"]}]},
            "session_tokens": {"enabled": True, "key_ring_path": str(tmp_path / "ring.json")},
        },
    )


def _claims(client: Any, token: str) -> dict[str, Any]:
    """Decode without verifying — these pins are about *what was signed*."""
    import jwt

    return dict(jwt.decode(token, options={"verify_signature": False}))


def test_e6_a_bound_credential_cannot_mint_a_token_for_another_agent(tmp_path: Path) -> None:
    """``/v1/sessions`` must refuse what ``/v1/request`` refuses.

    The same binding that stops ``intern`` *asking* as ``cleared`` has to stop
    it *minting* as ``cleared``: the token is a bearer credential that Nautilus
    forwards downstream and publishes a verification key for.
    """
    with _rest(_token_config(tmp_path)) as client:
        control = client.post(
            "/v1/request",
            headers={"X-API-Key": _BOUND_KEY},
            json={"agent_id": "cleared", "intent": "orders", "context": {"purpose": "x"}},
        )
        assert control.status_code == 403, "the control route stopped enforcing the binding"

        minted = client.post(
            "/v1/sessions",
            headers={"X-API-Key": _BOUND_KEY},
            json={"session_id": "victim-session", "agent_id": "cleared", "purpose": "x"},
        )

    assert minted.status_code == 403, (
        f"a key bound to 'intern' minted a session token for agent 'cleared' "
        f"({minted.status_code}): {minted.text[:400]}"
    )


def test_e6_the_signed_clearance_comes_from_the_registry(tmp_path: Path) -> None:
    """A caller does not get to name its own clearance in a signed claim.

    ``Broker._process_session_token`` reads clearance from the AgentRegistry
    precisely because it is an authorization input. This endpoint took it from
    the request body, so the broker would sign ``clearance: top-secret`` for an
    agent whose record says ``unclassified``.
    """
    with _rest(_token_config(tmp_path)) as client:
        minted = client.post(
            "/v1/sessions",
            headers={"X-API-Key": _BOUND_KEY},
            json={
                "session_id": "s1",
                "agent_id": "intern",
                "purpose": "x",
                "clearance": "top-secret",
            },
        )
        assert minted.status_code == 200, minted.text
        claims = _claims(client, minted.json()["token"])

    assert claims.get("clearance") == "unclassified", (
        f"the broker signed clearance={claims.get('clearance')!r} on the caller's "
        f"word; agents.intern.clearance is 'unclassified'"
    )


def test_e6_an_unbound_credential_still_mints(tmp_path: Path) -> None:
    """Control: the binding check must not break the bare-key configuration.

    A bare-string key names its own agent by design (the historical behaviour);
    only a *bound* credential is confined to one agent.
    """
    config = _write(
        tmp_path,
        {
            "sources": [
                {
                    "id": "orders",
                    "type": "static",
                    "classification": "unclassified",
                    "data_types": ["orders"],
                    "rows": [{"id": 1}],
                }
            ],
            "agents": {"cleared": {"id": "cleared", "clearance": "confidential"}},
            "audit": {"path": str(tmp_path / "audit.jsonl")},
            "api": {"keys": ["bare-key"]},
            "session_tokens": {"enabled": True, "key_ring_path": str(tmp_path / "ring.json")},
        },
    )
    with _rest(config) as client:
        minted = client.post(
            "/v1/sessions",
            headers={"X-API-Key": "bare-key"},
            json={"session_id": "s1", "agent_id": "cleared", "purpose": "x"},
        )
    assert minted.status_code == 200, minted.text


# ---------------------------------------------------------------------------
# 2. MCP enforces no capabilities.
# ---------------------------------------------------------------------------


def _capability_config(tmp_path: Path) -> str:
    return _write(
        tmp_path,
        {
            "sources": [
                {
                    "id": "orders",
                    "type": "static",
                    "classification": "unclassified",
                    "data_types": ["orders"],
                    "rows": [{"id": 1}],
                }
            ],
            "agents": {"intern": {"id": "intern", "clearance": "unclassified"}},
            "audit": {"path": str(tmp_path / "audit.jsonl")},
            "api": {
                "keys": [
                    {"key": _AUDIT_ONLY_KEY, "agent_id": "intern", "capabilities": ["audit_read"]},
                    {"key": _BOUND_KEY, "agent_id": "intern", "capabilities": ["query"]},
                ]
            },
        },
    )


def _mcp_call(client: Any, key: str) -> Any:
    headers = _mcp_handshake(
        client,
        {
            "X-API-Key": key,
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
    )
    return client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "nautilus_request",
                "arguments": {
                    "agent_id": "intern",
                    "intent": "list recent orders",
                    "context": {"purpose": "analytics", "session_id": "m1"},
                },
            },
        },
    )


def _mcp_refusal(response: Any) -> str | None:
    """The refusal text if this MCP reply refused, else ``None``.

    A refusal arrives one of three ways: an HTTP status from the ASGI gate, a
    JSON-RPC ``error``, or a tool result flagged ``isError``. Matching on the
    substring "error" instead would fire on ``sources_errored`` in a perfectly
    successful body.
    """
    if response.status_code >= 400:
        return f"HTTP {response.status_code}: {response.text[:400]}"
    reply: dict[str, Any] = response.json()
    if "error" in reply:
        return json.dumps(reply["error"])[:400]
    result: dict[str, Any] = reply.get("result", {})
    if result.get("isError"):
        return json.dumps(result.get("content"))[:400]
    return None


def _mcp_client(config_path: str) -> Any:
    """The MCP HTTP surface an operator gets, wired from the same config.

    The keys come off the loaded config rather than being hand-built: an
    ``ApiKeyEntry`` is what ``verify_api_key`` reads, and a dict that merely
    looks like one authenticates nobody.
    """
    from starlette.testclient import TestClient

    from nautilus import Broker
    from nautilus.transport.mcp_server import create_server, http_app

    broker = Broker.from_config(config_path)
    app = http_app(
        create_server(None, existing_broker=broker),
        api_keys=list(broker.config.api.keys),
    )
    # 127.0.0.1: the MCP SDK's DNS-rebinding guard only accepts a loopback Host.
    return TestClient(app, base_url="http://127.0.0.1:8000")


def test_e6_mcp_refuses_a_credential_without_the_query_capability(tmp_path: Path) -> None:
    """One credential, one set of capabilities, whichever transport it uses.

    The operator guide presents capabilities as what gates surfaces and REST
    and MCP as resolving the caller identically. Only the agent binding was
    true on MCP.
    """
    config = _capability_config(tmp_path)
    with _rest(config) as rest:
        control = rest.post(
            "/v1/request",
            headers={"X-API-Key": _AUDIT_ONLY_KEY},
            json={"agent_id": "intern", "intent": "orders", "context": {"purpose": "x"}},
        )
        assert control.status_code == 403, "the control route stopped checking capabilities"

    with _mcp_client(config) as mcp:
        called = _mcp_call(mcp, _AUDIT_ONLY_KEY)

    assert _mcp_refusal(called) is not None, (
        f"a credential holding only 'audit_read' executed nautilus_request over "
        f"MCP: HTTP {called.status_code} {called.text[:400]}"
    )


def test_e6_mcp_still_serves_a_credential_that_holds_query(tmp_path: Path) -> None:
    """Control: the capability gate must refuse the right credential only."""
    with _mcp_client(_capability_config(tmp_path)) as mcp:
        called = _mcp_call(mcp, _BOUND_KEY)

    refusal = _mcp_refusal(called)
    assert refusal is None, f"the query-capable key was refused: {refusal}"


# ---------------------------------------------------------------------------
# 3. The signed hash must be recomputable from the wire.
# ---------------------------------------------------------------------------


def _hash_config(tmp_path: Path) -> str:
    """A source whose rows carry a ``datetime`` — YAML parses one natively."""
    document = f"""
sources:
  - id: orders
    type: static
    classification: unclassified
    data_types: [orders]
    rows:
      - id: 1
        created_at: 2026-08-28 15:17:50.955432+00:00
agents:
  a1: {{id: a1, clearance: unclassified}}
attestation:
  enabled: true
audit:
  path: {tmp_path / "audit.jsonl"}
api:
  keys: [k]
"""
    path = tmp_path / "nautilus.yaml"
    path.write_text(document, encoding="utf-8")
    return str(path)


def test_e6_the_signed_response_hash_recomputes_from_the_wire(tmp_path: Path) -> None:
    """Follow ``docs/how-to/verify-a-token.md`` literally; it has to work.

    Nothing but the caller holds the rows, so a hash that cannot be recomputed
    from them is a claim nobody can check — which makes an honest response
    indistinguishable from a tampered one.
    """
    from nautilus.core.attestation_payload import compute_raw_response_hash

    with _rest(_hash_config(tmp_path)) as client:
        response = client.post(
            "/v1/request",
            headers={"X-API-Key": "k"},
            json={
                "agent_id": "a1",
                "intent": "list recent orders",
                "context": {"purpose": "analytics", "session_id": "s1"},
            },
        )
    body = response.json()
    assert body["outcome"] == "allowed", body

    claims = _claims(client, body["attestation_token"])
    payload = claims.get("nautilus", claims)
    claimed = payload["source_response_hashes"]["orders"]
    recomputed = compute_raw_response_hash(body["data"]["orders"])

    assert recomputed == claimed, (
        f"the signed per-source hash cannot be recomputed from the rows the "
        f"caller received.\n  claimed    {claimed}\n  recomputed {recomputed}\n"
        f"  rows       {json.dumps(body['data']['orders'])}"
    )


# ---------------------------------------------------------------------------
# 4. Nothing bounds what a request may send.
# ---------------------------------------------------------------------------


def _bound_config(tmp_path: Path) -> str:
    return _write(
        tmp_path,
        {
            "sources": [
                {
                    "id": "orders",
                    "type": "static",
                    "classification": "unclassified",
                    "data_types": ["orders"],
                    "rows": [{"id": 1}],
                }
            ],
            "agents": {"a1": {"id": "a1", "clearance": "unclassified"}},
            "audit": {"path": str(tmp_path / "audit.jsonl")},
            "api": {"keys": ["k"]},
        },
    )


def test_e6_an_oversized_request_body_is_refused(tmp_path: Path) -> None:
    """A 4 MB intent wrote 12.6 MB of audit in 0.22 s from a query-only key.

    The audit sink is the fail-closed path: ``/readyz`` reports 503 when
    ``audit_logger.probe()`` complains, so an operator who fills that volume
    drains every replica rather than degrading one.
    """
    audit_path = tmp_path / "audit.jsonl"
    with _rest(_bound_config(tmp_path)) as client:
        response = client.post(
            "/v1/request",
            headers={"X-API-Key": "k"},
            json={
                "agent_id": "a1",
                "intent": "x" * 4_000_000,
                "context": {"purpose": "analytics", "session_id": "s1"},
            },
        )

    assert response.status_code in {413, 422}, (
        f"a 4 MB request body was accepted with {response.status_code}; the "
        f"audit log grew to {audit_path.stat().st_size if audit_path.exists() else 0} bytes"
    )


def test_e6_an_ordinary_request_is_not_refused(tmp_path: Path) -> None:
    """Control: the bound must sit well above anything a real caller sends."""
    with _rest(_bound_config(tmp_path)) as client:
        response = client.post(
            "/v1/request",
            headers={"X-API-Key": "k"},
            json={
                "agent_id": "a1",
                "intent": "list recent orders for the eastern region",
                "context": {"purpose": "analytics", "session_id": "s1"},
            },
        )
    assert response.status_code == 200, response.text
