# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""WAVE E3 — the admin playground is a second front door with no lock on it.

``/admin/api/query`` reaches the same broker as ``/v1/request`` and enforces
none of what that route enforces. Three things are missing, and every one of
them is a control that exists and works on the documented entrypoint:

1. **Agent binding.** ``/v1/request`` refuses a credential bound to
   ``agent_id=a1`` that asks as ``a2`` (403). The playground reads
   ``body["agent_id"]`` and passes it straight through.
2. **Capabilities.** ``/v1/request`` carries
   ``Depends(_require_capability("query"))``. The playground has no capability
   check at all, so a key scoped to ``audit_read`` queries data through it.
3. **Ledger keying.** The playground passes ``auth=f"admin:{user}"``, so the
   same credential accumulates cumulative exposure under a *different*
   principal than it does on ``/v1/request``. §4.15 exists because a caller
   must not be able to reset its own exposure ledger; switching transport is
   exactly that reset.

The admin UI is also mounted unconditionally, on a config that never mentions
it. An operator who deploys ``nautilus.yaml`` gets a browser-authenticated
query console on the same port whether they asked for one or not, so
``ui.enabled`` defaults off and the routes are not registered at all when it
is off — 404, not a login page, because a login page is an invitation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

_KEY = "playground-key"
_SOURCE: dict[str, Any] = {
    "id": "orders",
    "type": "static",
    "classification": "unclassified",
    "data_types": ["orders"],
    "rows": [{"id": 1, "region": "us-east"}],
}


def _config(tmp_path: Path, **overrides: Any) -> str:
    """A loadable config; ``overrides`` carry whatever the pin is about."""
    document: dict[str, Any] = {
        "sources": [_SOURCE],
        "agents": {
            "a1": {"id": "a1", "clearance": "unclassified"},
            "a2": {"id": "a2", "clearance": "unclassified"},
        },
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "api": {"keys": [_KEY]},
    }
    document.update(overrides)
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


def _client(config_path: str) -> Any:
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    return TestClient(create_app(config_path))


def _query(client: Any, agent_id: str = "a1", **context: Any) -> Any:
    """Submit through the playground, authenticated by the admin cookie."""
    return client.post(
        "/admin/api/query",
        cookies={"nautilus_key": _KEY},
        json={
            "agent_id": agent_id,
            "intent": "list recent orders",
            "context": {"purpose": "analytics", **context},
        },
    )


def _principals(audit_path: Path) -> list[str]:
    """Every ``principal_id`` the audit log recorded, in order."""
    found: list[str] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        blob = json.dumps(record)
        if "principal:" not in blob:
            continue
        for meta in record.get("metadata", {}).values():
            if not isinstance(meta, str):
                continue
            try:
                entry = json.loads(meta)
            except ValueError:
                continue
            principal = entry.get("principal_id")
            if principal:
                found.append(principal)
    return found


# ---------------------------------------------------------------------------
# The console is opt-in.
# ---------------------------------------------------------------------------


def test_e3_the_admin_ui_is_off_unless_the_config_asks_for_it(tmp_path: Path) -> None:
    """A config that never mentions the UI must not serve one.

    404, not a redirect to a login page: a login page on a port an operator
    did not know was open is an invitation to guess at the key.
    """
    with _client(_config(tmp_path)) as client:
        response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 404, (
        f"GET /admin answered {response.status_code} on a config with no ui "
        f"section. The browser query console ships on by default."
    )


def test_e3_ui_enabled_serves_the_console(tmp_path: Path) -> None:
    """Control: the switch turns it on, so the pin above is a default, not a removal."""
    config = _config(tmp_path, ui={"enabled": True})
    with _client(config) as client:
        response = client.get("/admin", follow_redirects=False)
    assert response.status_code != 404, (
        "ui.enabled: true did not serve /admin; the fix removed the console "
        "rather than making it opt-in"
    )


# ---------------------------------------------------------------------------
# When it is on, it enforces what /v1/request enforces.
# ---------------------------------------------------------------------------


def test_e3_the_playground_refuses_a_credential_bound_to_another_agent(
    tmp_path: Path,
) -> None:
    """A key bound to ``a1`` cannot ask as ``a2`` — on either front door."""
    config = _config(
        tmp_path,
        ui={"enabled": True},
        api={"keys": [{"key": _KEY, "agent_id": "a1", "capabilities": ["query"]}]},
    )
    with _client(config) as client:
        rest = client.post(
            "/v1/request",
            headers={"X-API-Key": _KEY},
            json={"agent_id": "a2", "intent": "orders", "context": {"purpose": "x"}},
        )
        assert rest.status_code == 403, "the control route stopped enforcing the binding"

        playground = _query(client, agent_id="a2")

    assert playground.status_code == 403, (
        f"the playground answered {playground.status_code} to a credential bound "
        f"to a1 asking as a2, which /v1/request refuses with 403. The console "
        f"reaches the same broker and must enforce the same binding."
    )


def test_e3_the_playground_refuses_a_credential_without_query(tmp_path: Path) -> None:
    """A key scoped to ``audit_read`` may read the trail, not run queries."""
    config = _config(
        tmp_path,
        ui={"enabled": True},
        api={"keys": [{"key": _KEY, "capabilities": ["audit_read"]}]},
    )
    with _client(config) as client:
        rest = client.post(
            "/v1/request",
            headers={"X-API-Key": _KEY},
            json={"agent_id": "a1", "intent": "orders", "context": {"purpose": "x"}},
        )
        assert rest.status_code == 403, "the control route stopped checking capabilities"

        playground = _query(client)

    assert playground.status_code == 403, (
        f"the playground answered {playground.status_code} to a key that does not "
        f"hold the 'query' capability. The capability is enforced on /v1/request "
        f"and nowhere else, so the console is the way around it."
    )


def test_e3_the_playground_shares_one_exposure_ledger_with_v1_request(
    tmp_path: Path,
) -> None:
    """One credential, one cumulative-exposure ledger, whichever door it uses.

    §4.15 keys exposure to the identity the *transport* authenticated,
    precisely so a caller cannot reset its own history. Prefixing the
    playground's principal with ``admin:`` hands that reset back: accumulate
    on ``/v1/request``, then continue against a clean ledger on ``/admin``.
    """
    audit_path = tmp_path / "audit.jsonl"
    config = _config(tmp_path, ui={"enabled": True})
    with _client(config) as client:
        rest = client.post(
            "/v1/request",
            headers={"X-API-Key": _KEY},
            json={
                "agent_id": "a1",
                "intent": "list recent orders",
                "context": {"purpose": "analytics", "session_id": "s1"},
            },
        )
        assert rest.status_code == 200, rest.text
        playground = _query(client, session_id="s2")
        assert playground.status_code == 200, playground.text

    principals = _principals(audit_path)
    assert len(principals) >= 2, f"expected an audit entry per request, got principals={principals}"
    assert principals[0] == principals[-1], (
        f"the same key produced principal {principals[0]!r} on /v1/request and "
        f"{principals[-1]!r} on /admin/api/query. Two ledgers for one caller is "
        f"the reset §4.15 exists to close."
    )
