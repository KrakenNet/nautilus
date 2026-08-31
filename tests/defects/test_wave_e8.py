"""WAVE E8 — under load and mid-rollout, the broker says nothing true.

Three majors from the live-fire audit, measured against a running server.

1. **The exposure-ledger lock wraps the whole pipeline, and the wait is
   unbudgeted.** ``principal_id`` is derived from the caller, so every request
   from one caller takes the same lock — including the seconds spent waiting on
   the data source. One agent issuing 16 concurrent requests against a 2-second
   source measured 0.50 rps and a 32-second p50; the same 16 split across 16
   agent ids measured 4.92 rps against the same source. The serialisation is
   the point (two concurrent requests must not both read the ledger empty and
   both be allowed past a cumulative cap), but ``SourceConfig.timeout_s`` is
   entered *inside* ``_run_source``, i.e. only after the lock is won, so the
   queueing is outside every budget the config has. The caller gets HTTP 200,
   ``outcome: allowed``, empty ``sources_errored``, 32 seconds later.

2. **No admission control.** ``nautilus serve`` runs one uvicorn worker with no
   concurrency limit, and throughput is flat at ~78 rps from 1 client to 512
   while latency grows linearly (12 ms → 96 → 422 → 1834 → 8470). At 512
   concurrent clients every request returned 200, some after 17 seconds. Not
   one 503, not one 429, no ``Retry-After``, no server-side deadline — so a
   load balancer or agent framework in front of this gets no signal that the
   broker is saturated, and retries pile onto a queue that only grows.

3. **Mid-rollout the replicas enforce different policy, and a caller can turn a
   deny into an allow by retrying.** Start replica A, add a rule file to
   ``rules.user_rules_dirs``, start replica B: different ``ruleset_hash``, 6
   rules against 7 — the state every rolling deploy passes through. The
   identical request then alternated ``allowed`` / ``denied`` on consecutive
   calls through the load balancer. Nothing surfaced the split:
   ``BrokerResponse`` carries no ruleset hash, both probes said ok, ``/metrics``
   exposed no ruleset gauge, and the one place the hash *is* exposed
   (``GET /v1/rules``) is itself load-balanced, so polling it just made the hash
   flap with no way to tell "two replicas disagree" from "someone changed the
   rules".
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from nautilus.core.models import BrokerResponse

pytestmark = [pytest.mark.integration]

_KEY = "e8-key"
_SLOW_S = 0.4


def _write(tmp_path: Path, **extra: Any) -> str:
    document: dict[str, Any] = {
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
        "api": {"keys": [_KEY]},
    }
    document.update(extra)
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


@pytest.fixture
def slow_source(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the one configured source take real time, as a database does.

    The pins below are about how long a caller waits for a *lock*, which is
    only visible when the work inside the lock is not instantaneous. A static
    source answers in microseconds, so the queue never forms. The adapter is a
    collaborator here, not the thing under test.
    """
    from nautilus.adapters.static import StaticAdapter

    original = StaticAdapter.execute

    async def slow(self: Any, *args: Any, **kwargs: Any) -> Any:
        await asyncio.sleep(_SLOW_S)
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(StaticAdapter, "execute", slow)


async def _ask(broker: Any, session_id: str = "s") -> BrokerResponse:
    return await broker.arequest(
        "a1", "list recent orders", {"purpose": "analytics", "session_id": session_id}
    )


# ---------------------------------------------------------------------------
# 1. The ledger lock keeps its guarantee, and stops queueing without a budget.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e8_a_caller_is_not_queued_on_the_ledger_lock_without_a_budget(
    tmp_path: Path, slow_source: None
) -> None:
    """Waiting for the lock has to be inside some deadline the config names.

    Every request from one caller takes the same lock and holds it across the
    source query, so N concurrent requests take N times as long — and no
    timeout applies, because ``timeout_s`` starts after the lock is won. A
    caller sat there for 32 seconds and got a 200.
    """
    config = _write(tmp_path, session_store={"lock_timeout_s": 0.2})

    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(config)
    try:
        started = time.perf_counter()
        results = await asyncio.gather(*(_ask(broker) for _ in range(4)), return_exceptions=True)
        elapsed = time.perf_counter() - started
    finally:
        await broker.aclose()

    refused = [r for r in results if isinstance(r, BaseException)]
    assert refused, (
        f"4 concurrent requests from one caller against a {_SLOW_S}s source all "
        f"succeeded in {elapsed:.2f}s with lock_timeout_s=0.2 — the wait for the "
        f"ledger lock is outside every budget the config has"
    )
    assert all("busy" in str(r).lower() or "lock" in str(r).lower() for r in refused), (
        f"the refusal does not say the caller was queued: {[str(r) for r in refused]}"
    )


@pytest.mark.asyncio
async def test_e8_the_ledger_lock_still_serialises_one_callers_requests(
    tmp_path: Path, slow_source: None
) -> None:
    """Control: bounding the wait must not delete the serialisation.

    Two concurrent requests from one caller must not both read the ledger
    empty. Without this pin, removing the lock outright would also make the pin
    above pass — and cumulative-exposure caps would silently stop firing.
    """
    config = _write(tmp_path, session_store={"lock_timeout_s": 30.0})

    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(config)
    try:
        started = time.perf_counter()
        await asyncio.gather(*(_ask(broker) for _ in range(3)))
        elapsed = time.perf_counter() - started
    finally:
        await broker.aclose()

    assert elapsed >= _SLOW_S * 2, (
        f"3 concurrent requests from one caller finished in {elapsed:.2f}s, which "
        f"is less than two turns of a {_SLOW_S}s source: they ran in parallel, so "
        f"they read the same exposure ledger and every cumulative cap under-fires"
    )


# ---------------------------------------------------------------------------
# 2. A saturated broker says so.
# ---------------------------------------------------------------------------


async def _client(config: str) -> Any:
    """An in-process HTTP client with the lifespan primed, as the harness does."""
    from httpx import ASGITransport, AsyncClient

    from nautilus.core.broker import Broker
    from nautilus.transport.fastapi_app import create_app

    broker = await Broker.afrom_config(config)
    await broker.setup()
    app = create_app(None, existing_broker=broker)
    app.state.broker = broker
    app.state.ready = True
    # ``ASGITransport`` does not fire the lifespan, which is what normally
    # primes these — the latency harness does the same.
    app.state.api_keys = list(broker.config.api.keys)
    app.state.auth_mode = "api_key"
    return broker, AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


def _body() -> dict[str, Any]:
    return {
        "agent_id": "a1",
        "intent": "list recent orders",
        "context": {"purpose": "analytics", "session_id": "s"},
    }


@pytest.mark.asyncio
async def test_e8_a_saturated_broker_answers_503_not_a_longer_queue(
    tmp_path: Path, slow_source: None
) -> None:
    """Past the limit a caller gets a refusal it can act on, not a longer wait.

    512 concurrent clients measured an 8.5-second p50 and a 100% success rate.
    An agent framework reading only status codes cannot tell that apart from a
    healthy broker, so it retries, and the retries join the same queue.
    """
    config = _write(tmp_path, api={"keys": [_KEY], "max_concurrent_requests": 1})
    broker, client = await _client(config)
    try:
        responses = await asyncio.gather(
            *(
                client.post("/v1/request", headers={"X-API-Key": _KEY}, json=_body())
                for _ in range(4)
            )
        )
    finally:
        await client.aclose()
        await broker.aclose()

    codes = sorted(r.status_code for r in responses)
    assert 503 in codes, (
        f"4 concurrent requests at max_concurrent_requests=1 all got {codes}; "
        f"nothing tells the caller the broker is saturated"
    )
    refused = next(r for r in responses if r.status_code == 503)
    assert refused.headers.get("retry-after"), (
        "the 503 carries no Retry-After, so a client has nothing to pace against"
    )


@pytest.mark.asyncio
async def test_e8_probes_answer_while_the_broker_is_saturated(
    tmp_path: Path, slow_source: None
) -> None:
    """A full request queue must not take the pod out of rotation.

    ``/healthz`` and ``/readyz`` are how the Deployment decides the pod is
    alive. Gating them behind the same limit as ``/v1/request`` would turn
    saturation into a restart loop.
    """
    config = _write(tmp_path, api={"keys": [_KEY], "max_concurrent_requests": 1})
    broker, client = await _client(config)
    try:
        in_flight = asyncio.create_task(
            client.post("/v1/request", headers={"X-API-Key": _KEY}, json=_body())
        )
        await asyncio.sleep(_SLOW_S / 2)
        probes = [
            (await client.get("/healthz")).status_code,
            (await client.get("/readyz")).status_code,
        ]
        await in_flight
    finally:
        await client.aclose()
        await broker.aclose()

    assert probes == [200, 200], f"probes answered {probes} while one request was in flight"


@pytest.mark.asyncio
async def test_e8_requests_within_the_limit_are_all_served(
    tmp_path: Path, slow_source: None
) -> None:
    """Control: the limit must bound the queue, not the deployment.

    Without this, a gate that refused everything would also satisfy the pin
    above.
    """
    config = _write(tmp_path, api={"keys": [_KEY], "max_concurrent_requests": 8})
    broker, client = await _client(config)
    try:
        responses = await asyncio.gather(
            *(
                client.post("/v1/request", headers={"X-API-Key": _KEY}, json=_body())
                for _ in range(4)
            )
        )
    finally:
        await client.aclose()
        await broker.aclose()

    assert all(r.status_code == 200 for r in responses), (
        f"4 concurrent requests under a limit of 8 got {[r.status_code for r in responses]}"
    )


@pytest.mark.asyncio
async def test_e8_a_ledger_queue_answers_503_not_500(tmp_path: Path, slow_source: None) -> None:
    """Giving up on the lock is backpressure, and has to read as backpressure.

    A 500 says something broke and a client should stop; this is the one case
    where the same request will work if it comes back. It leaves the broker as
    an exception, so without a mapping at the transport boundary the caller
    reads an internal error.
    """
    config = _write(
        tmp_path,
        api={"keys": [_KEY], "max_concurrent_requests": 64},
        session_store={"lock_timeout_s": 0.05},
    )
    broker, client = await _client(config)
    try:
        responses = await asyncio.gather(
            *(
                client.post("/v1/request", headers={"X-API-Key": _KEY}, json=_body())
                for _ in range(4)
            )
        )
    finally:
        await client.aclose()
        await broker.aclose()

    codes = sorted(r.status_code for r in responses)
    assert 500 not in codes, (
        f"a request that gave up waiting for the ledger lock answered 500: {codes}"
    )
    assert 503 in codes, f"nothing reported the queue: {codes}"
    assert next(r for r in responses if r.status_code == 503).headers.get("retry-after")


# ---------------------------------------------------------------------------
# 3. Say which policy answered.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e8_the_response_names_the_ruleset_that_answered(tmp_path: Path) -> None:
    """Two replicas mid-rollout enforce different policy; the reply must say which.

    The identical request alternated allowed / denied through the load
    balancer, so a caller who is denied retries and is allowed. The audit entry
    has carried ``ruleset_hash`` all along; the response a caller actually
    reads has not.
    """
    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(_write(tmp_path))
    try:
        response = await _ask(broker)
        expected = broker.ruleset_hash
    finally:
        await broker.aclose()

    assert response.ruleset_hash == expected, (
        f"the response reports ruleset_hash={response.ruleset_hash!r}, the broker "
        f"is running {expected!r}. A caller cannot tell which of two replicas' "
        f"policies answered."
    )


def test_e8_metrics_name_the_ruleset_this_replica_runs(tmp_path: Path) -> None:
    """An operator has to be able to alert on "the replicas disagree".

    ``GET /v1/rules`` exposes the hash but is itself load-balanced, so polling
    the Service just makes it flap. A per-replica scrape target is what
    distinguishes a split fleet from a policy change.
    """
    from fastapi.testclient import TestClient

    from nautilus.core.broker import Broker
    from nautilus.transport.fastapi_app import create_app

    broker = Broker.from_config(_write(tmp_path))
    try:
        with TestClient(create_app(None, existing_broker=broker)) as client:
            scrape = client.get("/metrics")
        assert scrape.status_code == 200, scrape.text
        assert broker.ruleset_hash in scrape.text, (
            "nothing in /metrics names the ruleset this replica loaded, so a "
            "fleet running two policies looks exactly like one running one"
        )
    finally:
        broker.close()
