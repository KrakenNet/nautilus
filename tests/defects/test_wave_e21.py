# pyright: reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false
# pyright: reportAttributeAccessIssue=false
"""WAVE E21 — a permanent condition answered with a transient status.

``GET /v1/adapters/{name}/schema`` declares a 501 for an adapter that does not
support schema introspection. The guard was ``hasattr(adapter, "get_schema")``,
and the ``Adapter`` protocol *defines* ``get_schema`` with a body that raises
``NotImplementedError``. So ``hasattr`` is true for every adapter ever written
against the SDK, the 501 branch was unreachable, and an unimplemented
``get_schema`` fell through to the catch-all as::

    503 Schema fetch failed: AC-21.b: this adapter must implement get_schema()

503 means "try again later". This never succeeds later. A client honouring the
status retries forever against a method that does not exist.

Every shipped adapter implements ``get_schema``, so this is only reachable by a
third-party adapter -- which is exactly who the documented 501 is written for.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

_AUTH = {"X-API-Key": "secret-key"}


def _config(path: Path) -> str:
    document: dict[str, Any] = {
        "sources": [
            {
                "id": "orders",
                "type": "static",
                "description": "order rows",
                "classification": "unclassified",
                "data_types": ["orders"],
                "rows": [{"order_id": 1}],
            }
        ],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(path / "audit.jsonl")},
        "api": {"keys": ["secret-key"]},
    }
    config = path / "nautilus.yaml"
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(config)


class _NoSchema:
    """A third-party adapter that never overrode the protocol's default."""

    async def get_schema(self) -> Any:
        raise NotImplementedError("AC-21.b: this adapter must implement get_schema() (task-006)")


class _NotEvenAnAttribute:
    """A duck-typed object with no ``get_schema`` at all — the hasattr branch."""


def _client_with(config: str, adapter: object) -> Any:
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    app = create_app(config)
    client = TestClient(app)
    client.__enter__()  # runs lifespan, which builds the broker
    app.state.broker._adapters["orders"] = adapter
    return client


def test_e21_an_unimplemented_get_schema_is_501_not_503(tmp_path: Path) -> None:
    """The pin. A permanent 'this adapter does not do that' must not read as transient."""
    client = _client_with(_config(tmp_path), _NoSchema())
    try:
        resp = client.get("/v1/adapters/orders/schema", headers=_AUTH)
    finally:
        client.__exit__(None, None, None)

    assert resp.status_code == 501, (
        f"an adapter that never implemented get_schema answered "
        f"{resp.status_code}, so a client honouring the status retries a method "
        f"that will never exist: {resp.text[:300]}"
    )
    assert "schema introspection" in resp.text, resp.text


def test_e21_an_object_without_the_attribute_is_still_501(tmp_path: Path) -> None:
    """Control. The hasattr branch stays reachable for a genuinely duck-typed object."""
    client = _client_with(_config(tmp_path), _NotEvenAnAttribute())
    try:
        resp = client.get("/v1/adapters/orders/schema", headers=_AUTH)
    finally:
        client.__exit__(None, None, None)

    assert resp.status_code == 501, resp.text


def test_e21_a_real_fetch_failure_is_still_503(tmp_path: Path) -> None:
    """Control. A backend that is down *is* transient and must stay 503."""

    class _Down:
        async def get_schema(self) -> Any:
            raise ConnectionError("connection refused")

    client = _client_with(_config(tmp_path), _Down())
    try:
        resp = client.get("/v1/adapters/orders/schema", headers=_AUTH)
    finally:
        client.__exit__(None, None, None)

    assert resp.status_code == 503, resp.text
    assert "Schema fetch failed" in resp.text, resp.text


def test_e21_a_shipped_adapter_still_answers(tmp_path: Path) -> None:
    """Control. The 501 must be about the adapter, not about the route.

    The request first is not decoration: adapters connect lazily, and
    ``get_schema`` on a cold one raises ``AdapterError`` -- correctly a 503,
    because it *is* transient. Asking cold would have proved nothing.
    """
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    with TestClient(create_app(_config(tmp_path))) as client:
        warm = client.post(
            "/v1/request",
            headers=_AUTH,
            json={"agent_id": "analyst", "intent": "list the orders"},
        )
        assert warm.status_code == 200, warm.text
        resp = client.get("/v1/adapters/orders/schema", headers=_AUTH)

    assert resp.status_code == 200, resp.text
