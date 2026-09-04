# pyright: reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false
"""WAVE ops13 — the path that FAILS a request did not name what broke.

``ErrorRecord.endpoint`` was filled for sources and left ``null`` for every
``source_id: "<broker>"`` record, so "the request failed" and "here is the host
that failed it" were mutually exclusive observations:

* a dead **source** answers ``200`` with ``sources_errored[0].endpoint ==
  "postgresql://172.31.240.40:5432"`` and a ``WARNING`` naming the same address;
* a wedged **session store** answers ``503`` with
  ``{"source_id": "<broker>", "error_type": "BrokerBusyError", "endpoint": null}``
  and nothing on any ``nautilus.*`` logger at all. ``/readyz`` — which the 503
  body itself told the operator to call — answers ``reason:
  session_store_timeout``, a reason and not an address.

An operator paged by that 503 had to open ``nautilus.yaml`` to learn which host
the session store is, which is the one thing the audit trail exists to avoid.

What these pin:

* a broker-level failure that has a remote dependency carries that
  dependency's ``scheme://host[:port]`` into the response body, the durable
  audit entry and one ``WARNING`` on the broker's own logger;
* it is built by allowlist (:func:`~nautilus.config.models.redact_connection`),
  so the DSN password in ``nautilus.yaml`` reaches none of those three;
* the 503 body no longer sends the operator to ``/readyz`` — the probe that has
  just failed — while still refusing to guess between the two causes the
  timeout genuinely does not distinguish;
* a session-token rejection, verified in-process against the key ring, still
  carries ``endpoint: null``: it dials nothing, and inventing an address there
  would be worse than none.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest
import yaml

from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.core.session_pg import PostgresSessionStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator
    from pathlib import Path

pytestmark = [pytest.mark.integration]

_AUTH = {"X-API-Key": "ops13-api-key"}
# A password in the config, so "the endpoint carries no credential" is measured
# against a real one and not against an empty string.
_DSN_PASSWORD = "ops13-dsn-password"  # noqa: S105 — fixture value, not a credential
_STORE_HOST_PORT = "sessions.example.invalid:5432"
_STORE_DSN = f"postgresql://nautilus:{_DSN_PASSWORD}@{_STORE_HOST_PORT}/nautilus"
_STORE_ENDPOINT = f"postgresql://{_STORE_HOST_PORT}"


def _config(tmp_path: Path) -> str:
    document: dict[str, Any] = {
        "sources": [
            {
                "id": "orders",
                "type": "static",
                "classification": "unclassified",
                "data_types": ["orders"],
                "rows": [{"order_id": 1}],
            }
        ],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "api": {"keys": ["ops13-api-key"]},
        "session_store": {
            "backend": "postgres",
            "dsn": _STORE_DSN,
            "on_failure": "fail_closed",
            # Small enough that the wedged store is measured, not waited out.
            "lock_timeout_s": 0.05,
        },
    }
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


@contextlib.contextmanager
def _wedged_store() -> Iterator[None]:
    """A reachable-looking Postgres store whose ledger lock never returns.

    This is what ``docker pause`` on the store container looks like from the
    broker: the pool exists, and the advisory lock the exposure ledger needs
    simply never comes back. Everything the request touches below the patch —
    the DSN, ``_busy_message``, ``_broker_error``, the audit sink and the 503
    handler — is the shipped code path.
    """

    async def _setup(self: PostgresSessionStore) -> None:
        return None

    @contextlib.asynccontextmanager
    async def _never(self: PostgresSessionStore, keys: list[str]) -> AsyncIterator[None]:
        await asyncio.sleep(30)
        yield

    async def _aclose(self: PostgresSessionStore) -> None:
        return None

    with (
        mock.patch.object(PostgresSessionStore, "setup", _setup),
        mock.patch.object(PostgresSessionStore, "alock_all", _never),
        mock.patch.object(PostgresSessionStore, "aclose", _aclose),
    ):
        yield


def _ask(tmp_path: Path) -> tuple[Any, list[dict[str, Any]]]:
    """One ``POST /v1/request`` against a wedged store; response + audit entries."""
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    with _wedged_store(), TestClient(create_app(_config(tmp_path))) as client:
        response = client.post(
            "/v1/request",
            json={"agent_id": "analyst", "intent": "list orders"},
            headers=_AUTH,
        )
    audit = tmp_path / "audit.jsonl"
    entries = [
        json.loads(json.loads(line)["metadata"][NAUTILUS_METADATA_KEY])
        for line in audit.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return response, entries


def _broker_records(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        record
        for entry in entries
        for record in entry.get("error_records") or []
        if record.get("source_id") == "<broker>"
    ]


# ---------------------------------------------------------------------------
# 1. The failing path names the dependency.
# ---------------------------------------------------------------------------


def test_ops13_a_wedged_session_store_is_named_in_the_audit_record(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The pin. A 503 must say which host it could not reach."""
    with caplog.at_level(logging.WARNING, logger="nautilus.core.broker"):
        response, entries = _ask(tmp_path)

    assert response.status_code == 503, f"expected backpressure, got {response.text}"
    records = _broker_records(entries)
    assert records, f"no <broker> error record in the audit trail: {entries}"
    busy = [r for r in records if r["error_type"] == "BrokerBusyError"]
    assert busy, f"the ledger timeout was not recorded as BrokerBusyError: {records}"
    assert busy[0]["endpoint"] == _STORE_ENDPOINT, (
        f"the audit record for a failed request does not name the dependency "
        f"that failed it: endpoint={busy[0]['endpoint']!r}, expected "
        f"{_STORE_ENDPOINT!r}. An operator paged by this 503 has to open "
        f"nautilus.yaml to learn which host the session store is."
    )
    assert _STORE_ENDPOINT in response.text, f"the 503 body names no address:\n{response.text}"
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any(_STORE_ENDPOINT in message for message in warnings), (
        f"a source that dies leaves a WARNING naming its endpoint; a broker-level "
        f"failure left nothing on the broker's own logger: {warnings}"
    )


def test_ops13_the_dsn_password_reaches_none_of_the_three_audiences(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``endpoint`` is built by allowlist, so the DSN's password cannot ride out.

    The three audiences are strictly wider than the one that reads
    ``nautilus.yaml``: the process log, the durable audit trail, and the
    requesting agent.
    """
    with caplog.at_level(logging.DEBUG):
        response, entries = _ask(tmp_path)

    stdout = "\n".join(record.getMessage() for record in caplog.records)
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    for name, blob in (
        ("the process log", stdout),
        ("audit.jsonl", audit_text),
        ("the response body", response.text),
    ):
        assert _DSN_PASSWORD not in blob, f"the session store password leaked into {name}"
        assert "nautilus:" not in blob, f"DSN userinfo leaked into {name}"
    # And the address itself did arrive, in all three — a redactor that drops
    # everything passes the assertions above for the wrong reason.
    for name, blob in (
        ("the process log", stdout),
        ("audit.jsonl", audit_text),
        ("the response body", response.text),
    ):
        assert _STORE_HOST_PORT in blob, f"{name} names no host for the failed request"
    assert entries, "no audit entry was written for the failed request"


# ---------------------------------------------------------------------------
# 2. The 503 body's own advice.
# ---------------------------------------------------------------------------


def test_ops13_the_busy_message_does_not_send_the_operator_to_readyz() -> None:
    """``/readyz`` is the probe that has just failed, not the tiebreaker.

    On the failure this message is actually produced by, ``/readyz`` answers
    ``{"status": "not_ready", "reason": "session_store_timeout"}`` — a reason,
    not an address — and its first response after the store wedges takes 12.0s
    against a documented 4s ceiling. Advice an operator can act on has to come
    from the message itself.
    """
    from nautilus.core.broker import _busy_message

    message = _busy_message("session-1, principal:abc", 30.0, _STORE_ENDPOINT)
    assert "/readyz" not in message, (
        f"the 503 body sends the operator to the probe that just failed:\n{message}"
    )
    assert _STORE_ENDPOINT in message, (
        f"the message asks the operator to tell two causes apart and gives no "
        f"address to check:\n{message}"
    )
    # Both causes stay named: the timeout genuinely does not distinguish them.
    assert "another request from this caller" in message, message
    assert "unreachable" in message, message
    # And with no dialable store (memory / sqlite / a keyword DSN) it says so
    # rather than printing "None".
    blank = _busy_message("session-1", 30.0, None)
    assert "None" not in blank, f"a missing endpoint rendered as a literal None:\n{blank}"
    assert "session_store" in blank, blank


# ---------------------------------------------------------------------------
# 3. Where there is no remote dependency, endpoint stays null.
# ---------------------------------------------------------------------------


def test_ops13_a_rejected_session_token_names_no_endpoint(tmp_path: Path) -> None:
    """Signature verification is in-process against the key ring.

    It dials nothing, so there is no ``scheme://host[:port]`` to record. A
    fabricated one would be worse than ``null``.
    """
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    document: dict[str, Any] = {
        "sources": [
            {
                "id": "orders",
                "type": "static",
                "classification": "unclassified",
                "data_types": ["orders"],
                "rows": [{"order_id": 1}],
            }
        ],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "api": {"keys": ["ops13-api-key"]},
        "session_tokens": {"enabled": True},
    }
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    with TestClient(create_app(str(path))) as client:
        response = client.post(
            "/v1/request",
            json={
                "agent_id": "analyst",
                "intent": "list orders",
                "context": {"session_token": "not.a.real.token"},
            },
            headers=_AUTH,
        )
    assert response.status_code == 401, response.text
    entries = [
        json.loads(json.loads(line)["metadata"][NAUTILUS_METADATA_KEY])
        for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    records = _broker_records(entries)
    assert records, f"the rejected token left no <broker> record: {entries}"
    assert all(record["endpoint"] is None for record in records), (
        f"an in-process signature check was given a remote address: {records}"
    )


# ---------------------------------------------------------------------------
# 4. One redactor, not two.
# ---------------------------------------------------------------------------


def test_ops13_the_store_endpoint_is_scheme_host_port_and_nothing_else() -> None:
    """Whatever names the store copies out an allowlist, not a regex.

    ``postgresql://user:pw@host:5432/db?password=other`` has the secret in two
    places; a redactor that partitions on ``@`` keeps the second one.
    """
    leaky = f"postgresql://nautilus:{_DSN_PASSWORD}@db.example.invalid:5432/app?password=second"
    store = PostgresSessionStore(leaky)
    assert store.endpoint == "postgresql://db.example.invalid:5432", store.endpoint
    assert _DSN_PASSWORD not in store._sanitized_dsn(), store._sanitized_dsn()
    assert "second" not in store._sanitized_dsn(), (
        f"a query-string password survived into the store's own error messages: "
        f"{store._sanitized_dsn()}"
    )
    # A libpq keyword DSN has no host to copy out, so nothing is guessed.
    assert PostgresSessionStore("host=db password=pw").endpoint is None


def test_ops13_a_store_outage_is_named_by_the_same_choke_point() -> None:
    """The sibling failure, through the one place that fills the field.

    ``BrokerBusyError`` is the store being *slow*; ``SessionStoreUnavailableError``
    is the store being *gone*. Both end a request, both reach the audit trail
    through ``_broker_error``, and it reads the address off the exception rather
    than guessing — so a store failure raised anywhere inside the store names
    the store without a guard at the raise site.
    """
    from nautilus.core.broker import _broker_error
    from nautilus.core.session_pg import SessionStoreUnavailableError

    store = PostgresSessionStore(_STORE_DSN)
    with pytest.raises(SessionStoreUnavailableError) as raised:
        asyncio.run(store.aget("session-1"))  # no setup(): there is no pool

    record = _broker_error(raised.value, "trace-1")
    assert record.source_id == "<broker>"
    assert record.endpoint == _STORE_ENDPOINT, (
        f"a store outage recorded endpoint={record.endpoint!r}"
    )
    assert _DSN_PASSWORD not in record.message, record.message
