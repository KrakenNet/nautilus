# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false, reportPrivateUsage=false
"""WAVE E18 — an unmapped forwarded subject was a root credential.

Under ``api.auth.mode: proxy_trust`` the upstream mesh authenticates the caller
and forwards the resolved identity in ``X-Forwarded-User``. ``agents.<id>.subject``
is what turns that subject into a bound agent.

``caller_identity`` reads ``agent_subjects.get(auth)``, and when the subject is
not in the map that returns ``None`` -- which is the *unbound* case: the caller
names whatever ``agent_id`` it likes and holds ``ALL_CAPABILITIES``, including
``govern`` (promote and retract rules) and key rotation. Its docstring says an
unmapped subject "stays unbound rather than being refused here --
``proxy_trust_dependency`` owns the 401". It does not. That dependency refuses a
peer outside ``trusted_proxies`` and a *missing* header, and never consults the
subject map at all.

So one typo in a SPIFFE ID -- or one new workload the mesh authenticates before
anybody adds it to the config -- converts a credential that should have been
bound to a single agent into a root one, with no log line saying so.

The fix is fail-closed only where the operator has expressed intent: when
``agent_subjects`` is non-empty, an unmapped subject is refused. A deployment
that has bound nobody keeps working exactly as before, the same way a bare
API-key string does.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

_PROXY = "127.0.0.1"


def _config(path: Path, *, subjects: bool) -> str:
    agents: dict[str, Any] = {
        "analyst": {"id": "analyst", "clearance": "unclassified", "default_purpose": "monitoring"}
    }
    if subjects:
        # The operator has said which subject is which agent. That is the
        # statement the refusal below is enforcing.
        agents["analyst"]["subject"] = "spiffe://mesh/ns/prod/sa/analyst"
    document: dict[str, Any] = {
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
        "agents": agents,
        "audit": {"path": str(path / "audit.jsonl")},
        "api": {"auth": {"mode": "proxy_trust", "trusted_proxies": [_PROXY]}},
        "ui": {"enabled": False},
    }
    cfg = path / "nautilus.yaml"
    cfg.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(cfg)


def _client(config: str) -> Any:
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    # ``client=`` sets the socket peer the trusted-proxy check reads.
    return TestClient(create_app(config), client=(_PROXY, 51234))


def test_e18_an_unmapped_forwarded_subject_is_refused(tmp_path: Path) -> None:
    """A subject the config never bound must not be served as root."""
    config = _config(tmp_path, subjects=True)
    with _client(config) as client:
        resp = client.get(
            "/v1/sources",
            headers={"X-Forwarded-User": "spiffe://mesh/ns/prod/sa/analsyt"},  # typo
        )

    assert resp.status_code == 401, (
        f"an unmapped forwarded subject was served with agent_id=None and every "
        f"capability -- it can name any agent and call the governance routes. "
        f"Got {resp.status_code}: {resp.text[:300]}"
    )
    assert "subject" in resp.text.lower(), (
        f"the refusal has to say what was wrong, or an operator cannot tell it "
        f"from a proxy misconfiguration: {resp.text[:300]}"
    )


def test_e18_an_unmapped_subject_cannot_reach_a_governance_route(tmp_path: Path) -> None:
    """The capability set is the real prize, so it gets its own pin.

    ``/v1/rules/{name}/retract`` needs ``govern``. An unbound caller held it.
    """
    config = _config(tmp_path, subjects=True)
    with _client(config) as client:
        resp = client.post(
            "/v1/rules/some-rule/retract",
            headers={"X-Forwarded-User": "spiffe://mesh/ns/prod/sa/nobody"},
            json={},
        )

    assert resp.status_code == 401, (
        f"an unmapped subject reached a govern-gated route: {resp.status_code}"
    )


def test_e18_a_mapped_subject_still_works(tmp_path: Path) -> None:
    """Control. The refusal must be about being unmapped, not about proxy_trust."""
    config = _config(tmp_path, subjects=True)
    with _client(config) as client:
        resp = client.get(
            "/v1/sources",
            headers={"X-Forwarded-User": "spiffe://mesh/ns/prod/sa/analyst"},
        )

    assert resp.status_code == 200, resp.text
    assert [s["id"] for s in resp.json()["sources"]] == ["orders"], resp.json()


def test_e18_a_deployment_that_binds_nobody_is_unchanged(tmp_path: Path) -> None:
    """Control. Fail closed on stated intent, not on the absence of any.

    With no ``subject`` anywhere the operator has bound nothing, and refusing
    every caller would break that deployment for a config it never wrote.
    """
    config = _config(tmp_path, subjects=False)
    with _client(config) as client:
        resp = client.get("/v1/sources", headers={"X-Forwarded-User": "anyone-at-all"})

    assert resp.status_code == 200, resp.text


def test_e18_an_untrusted_peer_is_still_refused(tmp_path: Path) -> None:
    """Control. The pre-existing peer check keeps working."""
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    config = _config(tmp_path, subjects=True)
    with TestClient(create_app(config), client=("10.99.99.99", 51234)) as client:
        resp = client.get(
            "/v1/sources",
            headers={"X-Forwarded-User": "spiffe://mesh/ns/prod/sa/analyst"},
        )

    assert resp.status_code == 401, resp.text
    assert "trusted proxy" in resp.text.lower(), resp.text
