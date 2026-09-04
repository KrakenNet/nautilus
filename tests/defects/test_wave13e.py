# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false, reportPrivateUsage=false
"""WAVE 13E — two doors that resolved a caller without asking who was knocking.

**A. The MCP HTTP port believed ``X-Forwarded-User`` from any peer.**
``caller_identity``'s ``proxy_trust`` branch reads the header raw and justifies
it in a comment: "``proxy_trust_dependency`` has already refused a subject no
agent claims". On the MCP path nothing had. That dependency is wired into
``fastapi_app`` and ``ui/dependencies`` and appears nowhere in ``mcp_server`` or
its ``serve`` wiring — the only gate on that port is ``wrap_http_with_api_key``,
which checks ``X-API-Key`` and nothing else. So under ``api.auth.mode:
proxy_trust`` any holder of any configured key, from any address, named itself:
no ``trusted_proxies`` peer check, no unmapped-subject refusal, ``agent_id``
``None`` (unbound — it may speak for any agent) and ``ALL_CAPABILITIES``, which
a key scoped to ``audit_read`` most certainly is not. Rotating the header per
request also mints a fresh ``principal:``, so the cumulative-exposure ledger
became resettable at will.

**B. ``/admin/sources`` published the unfiltered catalogue.**
The line calls ``caller_identity(request)`` with no ``keys=``, so ``_match_key``
is never reached, ``agent_id`` stays ``None``, and ``sources_visible_to(None)``
returns everything. The comment directly above it says the console "must not
publish a catalogue the API refuses to" — and one URL away ``/v1/sources``
refuses exactly that. Every id, description, data type and classification the
caller's clearance can never reach is the reconnaissance that filter exists to
deny.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
import yaml
from starlette.testclient import TestClient

pytestmark = [pytest.mark.integration]

_PROXY = "127.0.0.1"
_OUTSIDER = "203.0.113.9"
_SUBJECT = "spiffe://mesh/ns/prod/sa/analyst"

# Never a real credential: this value only ever reaches a config this test wrote.
_KEY = "wave13e-test-key"


def _write(path: Path, document: dict[str, Any]) -> Path:
    config = path / "nautilus.yaml"
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    return config


# ===========================================================================
# A -- the MCP port under proxy_trust
# ===========================================================================


def _mcp_config(tmp_path: Path) -> Path:
    """``proxy_trust`` plus the key the MCP gate insists on, tightly scoped.

    ``capabilities: [audit_read]`` is the escalation probe: ``nautilus_sources``
    is gated on ``query``, so this credential must never run it, whatever it
    puts in a header.
    """
    return _write(
        tmp_path,
        {
            "sources": [
                {
                    "id": "orders",
                    "type": "static",
                    "description": "order rows",
                    "classification": "unclassified",
                    "data_types": ["orders"],
                    "allowed_purposes": ["monitoring"],
                    "rows": [{"order_id": 1}],
                }
            ],
            "agents": {
                "analyst": {
                    "id": "analyst",
                    "clearance": "unclassified",
                    "default_purpose": "monitoring",
                    "subject": _SUBJECT,
                }
            },
            "audit": {"path": str(tmp_path / "audit.jsonl")},
            "api": {
                "keys": [
                    {"key": _KEY, "principal": "probe", "capabilities": ["audit_read"]},
                ],
                "auth": {"mode": "proxy_trust", "trusted_proxies": [_PROXY]},
            },
            "ui": {"enabled": False},
        },
    )


def _call_mcp_sources(config: Path, *, peer: str, forwarded: str | None) -> Any:
    """Drive ``nautilus_sources`` over the real MCP HTTP transport.

    Exactly what ``nautilus serve --transport both --mcp-mode http`` builds, so
    the gate under test is the one a deployment runs. ``Host`` stays loopback
    for the SDK's DNS-rebinding guard; ``client=`` is the socket peer the
    trusted-proxy check reads.
    """
    from nautilus.cli.serve import broker_for_serve
    from nautilus.transport.mcp_server import _mcp_settings, create_server, http_app

    broker = broker_for_serve(config, air_gapped=False)
    app = http_app(
        create_server(None, existing_broker=broker),
        api_keys=lambda: _mcp_settings(broker)[2],
    )
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "X-API-Key": _KEY,
    }
    if forwarded is not None:
        headers["X-Forwarded-User"] = forwarded
    try:
        with TestClient(app, base_url="http://127.0.0.1:8000", client=(peer, 40000)) as client:
            handshake = client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "wave13e", "version": "0"},
                    },
                },
            )
            assert handshake.status_code == 200, (
                f"control failed: the MCP handshake itself was refused "
                f"({handshake.status_code}), so nothing below tests the tool gate: "
                f"{handshake.text[:300]}"
            )
            session = handshake.headers.get("mcp-session-id")
            assert session, "control failed: no mcp-session-id, so no tool can be called"
            headers = {**headers, "mcp-session-id": session}
            client.post(
                "/mcp",
                headers=headers,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
            return client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "nautilus_sources", "arguments": {}},
                },
            )
    finally:
        asyncio.run(broker.aclose())


def _served_the_catalogue(response: Any) -> bool:
    """Did the tool call actually hand back source metadata?"""
    if response.status_code != 200:
        return False
    result = response.json().get("result")
    if not isinstance(result, dict) or result.get("isError"):
        return False
    return "orders" in response.text


def test_13e_the_mcp_port_does_not_believe_a_forwarded_user_from_any_peer(
    tmp_path: Path,
) -> None:
    """An unvetted ``X-Forwarded-User`` was a root credential on the MCP port.

    The attacker holds a key scoped to ``audit_read`` and connects from an
    address no ``trusted_proxies`` entry covers. ``nautilus_sources`` is gated
    on ``query``. It ran anyway, because the ``proxy_trust`` branch discarded
    the key entry — capabilities and all — for a header the peer set itself.
    """
    response = _call_mcp_sources(_mcp_config(tmp_path), peer=_OUTSIDER, forwarded="attacker")

    assert not _served_the_catalogue(response), (
        f"an untrusted peer set X-Forwarded-User and ran a query-gated MCP tool "
        f"with a key that holds only audit_read: {response.text[:400]}"
    )


def test_13e_an_unmapped_forwarded_subject_is_refused_on_the_mcp_port(
    tmp_path: Path,
) -> None:
    """The peer check is not the whole vetting; the subject map is the rest.

    Even from the real proxy, a subject ``agents.<id>.subject`` never named
    resolves to ``agent_id=None`` — unbound, naming its own agent, holding
    everything. ``/v1`` has refused that since wave E18; this port had not.
    """
    response = _call_mcp_sources(
        _mcp_config(tmp_path),
        peer=_PROXY,
        forwarded="spiffe://mesh/ns/prod/sa/analsyt",  # typo
    )

    assert not _served_the_catalogue(response), (
        f"a subject no agent claims was served as an unbound root caller over MCP: "
        f"{response.text[:400]}"
    )


def test_13e_a_vetted_forwarded_subject_still_works_on_the_mcp_port(
    tmp_path: Path,
) -> None:
    """Control. The refusals above must be about vetting, not about proxy_trust.

    The real proxy forwarding the subject the config binds is the deployment
    this mode exists for, and it has to keep working.
    """
    response = _call_mcp_sources(_mcp_config(tmp_path), peer=_PROXY, forwarded=_SUBJECT)

    assert _served_the_catalogue(response), (
        f"the trusted proxy forwarded a subject bound to agents.analyst.subject "
        f"and the MCP port refused it: {response.status_code} {response.text[:400]}"
    )


# ===========================================================================
# B -- the console catalogue
# ===========================================================================


def _console_config(tmp_path: Path) -> Path:
    """Two classifications on the built-in ladder, and a key bound to the lower."""
    return _write(
        tmp_path,
        {
            "sources": [
                {
                    "id": "orders",
                    "type": "static",
                    "description": "order rows",
                    "classification": "unclassified",
                    "data_types": ["orders"],
                    "allowed_purposes": ["monitoring"],
                    "rows": [{"order_id": 1}],
                },
                {
                    "id": "payroll",
                    "type": "static",
                    "description": "salary by employee",
                    "classification": "secret",
                    "data_types": ["compensation"],
                    "allowed_purposes": ["monitoring"],
                    "rows": [{"employee": "e-1", "salary": 1}],
                },
            ],
            "agents": {
                "analyst": {
                    "id": "analyst",
                    "clearance": "unclassified",
                    "default_purpose": "monitoring",
                }
            },
            "audit": {"path": str(tmp_path / "audit.jsonl")},
            "api": {
                "keys": [
                    {
                        "key": _KEY,
                        "principal": "probe",
                        "agent_id": "analyst",
                        "capabilities": ["query"],
                    }
                ]
            },
            "ui": {"enabled": True},
        },
    )


def test_13e_the_console_source_page_applies_the_clearance_filter(tmp_path: Path) -> None:
    """``/admin/sources`` is the same catalogue, so it is the same filter.

    The credential is bound to an ``unclassified`` agent. ``/v1/sources`` hides
    the ``secret`` source from it; the console listed the id, the prose
    description, the data types and the classification anyway.
    """
    from nautilus.transport.fastapi_app import create_app

    config = _console_config(tmp_path)
    with TestClient(create_app(str(config))) as client:
        api = client.get("/v1/sources", headers={"X-API-Key": _KEY})
        console = client.get("/admin/sources", headers={"X-API-Key": _KEY})

    assert api.status_code == 200, api.text
    assert [s["id"] for s in api.json()["sources"]] == ["orders"], (
        f"control failed: /v1/sources did not filter, so the console has nothing "
        f"to disagree with: {api.json()}"
    )
    assert console.status_code == 200, console.text
    assert "payroll" not in console.text and "salary by employee" not in console.text, (
        "the console published a source /v1/sources refuses to name to the same "
        "credential -- id, description, data types and classification"
    )
    assert "orders" in console.text, (
        f"control failed: the console listed nothing at all, so the assertion above "
        f"would pass on an empty page: {console.text[:400]}"
    )
