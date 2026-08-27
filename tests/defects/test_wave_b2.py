"""One pin per Wave B2 item — what a deployment does when it is under load.

Wave B2 is the scale half of the readiness review. Three of its findings are
about *unbounded* things: a connection pool with no declared size and no
acquire timeout, a source that has stopped answering and is re-dialled on every
request anyway, and adapters that materialize an entire upstream body before
the row cap that was supposed to bound it.

Measured, not assumed: with the default pool, ten concurrently-held ledger
locks exhaust it and the eleventh waits forever. A request holds two, so the
ceiling is five concurrent requests, and the failure is a hang with no error.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from nautilus.core.models import IntentAnalysis

pytestmark = pytest.mark.defect

_INTENT = IntentAnalysis(raw_intent="read the source", data_types_needed=["docs"], entities=[])


# ===========================================================================
# B2a -- the pool has a declared size, and running out of it is an error
# ===========================================================================


def test_b2a_exhausting_the_session_pool_raises_instead_of_hanging(pg_dsn: str) -> None:
    """A pool with no ``max_size`` and no ``acquire`` timeout hangs forever.

    Every in-flight request holds two pooled connections for the whole
    pipeline — one advisory lock for its declared session, one for the caller's
    principal — so the asyncpg default of ten is a hard ceiling of five
    concurrent requests. Past it, ``pool.acquire()`` waits with no deadline:
    the request never completes, never errors and never appears in the audit
    log.

    The control is the request that fits: with two connections available, two
    concurrently-held locks must still work.
    """
    from nautilus.core.session_pg import PostgresSessionStore, SessionStoreUnavailableError

    async def _hold(store: PostgresSessionStore, n: int) -> None:
        """Hold ``n`` locks at once, each on its own pooled connection.

        The last one is taken inline so its failure propagates here rather than
        into a task nobody is awaiting.
        """
        release = asyncio.Event()
        tasks: list[asyncio.Task[None]] = []

        async def one(key: str, ready: asyncio.Event) -> None:
            async with store.alock(key):
                ready.set()
                await release.wait()

        try:
            for i in range(n - 1):
                ready = asyncio.Event()
                tasks.append(asyncio.create_task(one(f"k{i}", ready)))
                await asyncio.wait_for(ready.wait(), timeout=15)
            async with store.alock(f"k{n - 1}"):
                pass
        finally:
            release.set()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _go() -> None:
        store = PostgresSessionStore(
            pg_dsn,
            on_failure="fail_closed",
            pool_max_size=2,
            acquire_timeout_s=2.0,
        )
        await store.setup()
        try:
            # Control: a load that fits in the declared pool.
            await _hold(store, 2)
            with pytest.raises(SessionStoreUnavailableError, match="pool"):
                await _hold(store, 3)
        finally:
            await store.aclose()

    asyncio.run(_go())


def test_b2a_the_configured_pool_size_is_the_pool_size(pg_dsn: str) -> None:
    """An operator sizing the pool must be able to see the size take effect.

    The ceiling above is only actionable if it can be raised. ``asyncpg``'s
    default (10/10) was accepted implicitly, so no config could move it.
    """
    from nautilus.core.session_pg import PostgresSessionStore

    async def _go() -> tuple[int, int]:
        store = PostgresSessionStore(pg_dsn, on_failure="fail_closed", pool_max_size=4)
        await store.setup()
        try:
            pool: Any = store._pool  # noqa: SLF001 # pyright: ignore[reportPrivateUsage]
            return (pool.get_min_size(), pool.get_max_size())
        finally:
            await store.aclose()

    _min_size, max_size = asyncio.run(_go())
    assert max_size == 4, f"session_store.pool_max_size=4 produced a pool of {max_size}"


# ===========================================================================
# B2b -- a source that is not answering is not re-dialled every request
# ===========================================================================


def _config(tmp_path: Path, **source_overrides: Any) -> str:
    source: dict[str, Any] = {
        "id": "dead",
        "type": "postgres",
        "description": "a source that is not there",
        "classification": "unclassified",
        "data_types": ["patients"],
        "allowed_purposes": ["care"],
        # RFC 5737 TEST-NET-1: routed nowhere, so the connect hangs rather than
        # being refused — which is what a source that has gone away looks like.
        "connection": "postgresql://192.0.2.1:5432/none",
        "table": "public.t",
        "timeout_s": 1.0,
    }
    source.update(source_overrides)
    config: dict[str, Any] = {
        "sources": [source],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "attestation": {"enabled": False},
        "rules": {"packs": [], "user_rules_dirs": []},
    }
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return str(path)


def test_b2b_an_unreachable_source_is_not_re_dialled_on_every_request(tmp_path: Path) -> None:
    """One dead source must not cost every later request its whole timeout.

    ``connect()`` runs inside the per-source task on every request, so a source
    that has gone away charges its ``timeout_s`` — 15 s by default — to each
    one, for as long as it stays away. Nothing remembers that the last attempt
    failed.

    The control is the first request, which must still pay the timeout: a fix
    that stopped connecting altogether would pass a "second request is fast"
    assertion while breaking recovery.
    """
    from nautilus import Broker

    async def _timings() -> tuple[float, float]:
        broker = Broker.from_config(_config(tmp_path))
        try:
            started = time.perf_counter()
            await broker.arequest("analyst", "patients", {"purpose": "care"})
            first = time.perf_counter() - started
            started = time.perf_counter()
            await broker.arequest("analyst", "patients", {"purpose": "care"})
            second = time.perf_counter() - started
            return first, second
        finally:
            await broker.aclose()

    first, second = asyncio.run(_timings())
    assert first >= 0.5, (
        f"the first request to an unroutable host returned in {first:.2f}s, so it "
        f"never waited on a connect and this pin measures nothing"
    )
    assert second < first / 2, (
        f"the second request to the same dead source took {second:.2f}s against "
        f"the first's {first:.2f}s: every request pays the full connect timeout "
        f"for as long as the source stays away"
    )


def test_b2b_the_cooldown_expires_so_a_recovered_source_is_used(tmp_path: Path) -> None:
    """A remembered failure that never expires is an outage, not a circuit breaker.

    The control for the pin above: after the cooldown elapses the broker must
    dial the source again, which is observable as the request paying the
    connect timeout a second time.
    """
    from nautilus import Broker

    async def _timings() -> tuple[float, float]:
        broker = Broker.from_config(_config(tmp_path))
        broker.connect_cooldown_s = 0.2
        try:
            started = time.perf_counter()
            await broker.arequest("analyst", "patients", {"purpose": "care"})
            first = time.perf_counter() - started
            await asyncio.sleep(0.4)
            started = time.perf_counter()
            await broker.arequest("analyst", "patients", {"purpose": "care"})
            after = time.perf_counter() - started
            return first, after
        finally:
            await broker.aclose()

    first, after = asyncio.run(_timings())
    assert after >= first / 2, (
        f"after the cooldown expired the request returned in {after:.2f}s against "
        f"the first's {first:.2f}s: the source was never re-dialled, so a source "
        f"that came back would stay dead"
    )


# ===========================================================================
# B2c -- an upstream body is bounded before it is materialized
# ===========================================================================


def test_b2c_a_rest_response_is_bounded_before_it_is_parsed() -> None:
    """The 1000-row cap bounds the rows, not the bytes read to produce them.

    ``response.json()`` materializes the entire upstream body first, so a
    source that answers with a gigabyte does a gigabyte of allocation inside
    the broker before any cap applies. The row limit is the wrong instrument:
    it runs after the damage.

    Served by a real HTTP server on loopback — an adapter asserted against a
    fake client proves nothing about what the adapter reads.
    """
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from nautilus.adapters.base import AdapterError
    from nautilus.adapters.rest import MAX_RESPONSE_BYTES, RestAdapter
    from nautilus.config.models import SourceConfig

    # One row per 100 bytes or so, enough of them to pass the ceiling.
    row = {"id": 1, "blob": "x" * 512}
    count = (MAX_RESPONSE_BYTES // 512) + 64
    payload = json.dumps([row] * count).encode("utf-8")
    assert len(payload) > MAX_RESPONSE_BYTES, "the fixture body is under the ceiling"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's name
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            """Silence the default stderr access log."""

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    async def _go() -> None:
        adapter = RestAdapter()
        config = SourceConfig.model_validate(
            {
                "id": "big",
                "type": "rest",
                "description": "an endpoint that answers with too much",
                "classification": "unclassified",
                "data_types": ["patients"],
                "allowed_purposes": ["care"],
                # A hostname, not an IP literal: the adapter refuses
                # loopback *literals* as an SSRF guard, which is not what this
                # pin is about.
                "connection": f"http://localhost:{port}",
            }
        )
        await adapter.connect(config)
        try:
            with pytest.raises(AdapterError, match="bytes"):
                await adapter.execute(_INTENT, [], {})
        finally:
            await adapter.close()

    try:
        asyncio.run(_go())
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_b2c_an_oversized_s3_object_is_refused_not_materialized(
    minio_endpoint: tuple[str, str, str],
) -> None:
    """``_get_object`` read the whole body into memory before anything capped it.

    An exact-key constraint against a large object allocates the object and
    decodes it to ``str``, so a multi-gigabyte object is a multi-gigabyte
    allocation inside the broker; the 1000-row cap has nothing to say about it.

    The control is the small object under the same ceiling, which must still
    come back in full.
    """
    import contextlib

    from aiobotocore.session import AioSession  # pyright: ignore[reportMissingTypeStubs]

    from nautilus.adapters.base import AdapterError
    from nautilus.adapters.s3 import MAX_OBJECT_BYTES, S3Adapter
    from nautilus.config.models import SourceConfig
    from nautilus.core.models import ScopeConstraint

    endpoint, access, secret = minio_endpoint
    bucket = "b2-ceiling"
    big = b"x" * (MAX_OBJECT_BYTES + 4096)
    small = b"small enough"

    async def _seed() -> None:
        session: Any = AioSession()
        async with session.create_client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access,
            aws_secret_access_key=secret,
            region_name="us-east-1",
        ) as s3:
            with contextlib.suppress(Exception):  # already exists
                await s3.create_bucket(Bucket=bucket)
            await s3.put_object(Bucket=bucket, Key="big.bin", Body=big)
            await s3.put_object(Bucket=bucket, Key="small.txt", Body=small)

    config = SourceConfig.model_validate(
        {
            "id": "objects",
            "type": "s3",
            "description": "a bucket of documents",
            "classification": "unclassified",
            "data_types": ["docs"],
            "allowed_purposes": ["care"],
            "connection": endpoint,
            "table": bucket,
            "auth": {"type": "basic", "username": access, "password": secret},
        }
    )
    intent = _INTENT

    async def _read(key: str) -> Any:
        adapter = S3Adapter()
        await adapter.connect(config)
        try:
            scope = [ScopeConstraint(source_id="objects", field="key", operator="=", value=key)]
            return await adapter.execute(intent, scope, {})
        finally:
            await adapter.close()

    asyncio.run(_seed())

    result = asyncio.run(_read("small.txt"))
    assert result.rows, "the control object came back empty, so this pin proves nothing"

    with pytest.raises(AdapterError, match="bytes"):
        asyncio.run(_read("big.bin"))
