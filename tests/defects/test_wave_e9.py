# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportMissingTypeStubs=false
"""WAVE E9 — a response is capped at 1000 rows and at no number of bytes.

Measured against a broker running under the shipped manifest's own memory
limit. ``PostgresAdapter._DEFAULT_LIMIT`` bounds a result to 1000 rows and
nothing bounds it in bytes, so a table with wide values turns one request into
a 65 MB response and about 115 MB of process memory -- the rows, plus
``compute_response_hash`` canonicalising the whole payload with ``json.dumps``
twice per request, plus the transport's own serialisation::

    one request:  http=200 size=65609644 t=0.68   worker RSS 147 MB -> 215 MB
    conc 4:  200 x4, container alive
    conc 8:  ServerDisconnectedError x4, ClientPayloadError x4
             docker inspect -> exited OOMKilled=true 137
             /healthz, /readyz -> ClientConnectorError (the process is gone)

Eight concurrent requests take the pod from ~150 MB to SIGKILL under
``deploy/deployment.yaml``'s ``limits.memory: 1Gi``. Clients get a dropped
socket -- not a 413, not a 503, not an error response -- and both probes go
unreachable because there is no process left to answer them. ``grep`` over
``nautilus/`` for ``max_rows|max_response|row_limit|max_bytes`` returned
nothing outside the MCP transport: an operator had no knob.

The row cap is honest about rows and blind to bytes. These pins put a byte
budget beside it, enforce it while the rows are being read rather than after
they are all in memory, and stop the hash from materialising a second and third
full-size copy of every payload it digests.
"""

from __future__ import annotations

import json
import tracemalloc
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

# Wide enough that a byte budget bites well before the 1000-row cap does, small
# enough to run in the unit lane. The shipped defect needed 64 KB x 1000; the
# contract it breaks is the same at any scale.
_ROW_BYTES = 4096
_ROWS = 200


def _wide_rows(count: int = _ROWS) -> list[dict[str, Any]]:
    return [{"id": i, "blob": "x" * _ROW_BYTES} for i in range(count)]


def _write(tmp_path: Path, **source_extra: Any) -> str:
    source: dict[str, Any] = {
        "id": "wide_db",
        "type": "static",
        "classification": "unclassified",
        "data_types": ["orders"],
        "rows": _wide_rows(),
    }
    source.update(source_extra)
    document: dict[str, Any] = {
        "sources": [source],
        "agents": {"a1": {"id": "a1", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
    }
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


async def _ask(config: str) -> Any:
    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(config)
    try:
        return await broker.arequest(
            "a1", "list recent orders", {"purpose": "analytics", "session_id": "s"}
        )
    finally:
        await broker.aclose()


def _response_bytes(response: Any) -> int:
    return len(json.dumps(response.data, default=str))


# ---------------------------------------------------------------------------
# A byte budget exists, and it is what bounds the reply.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e9_a_source_is_bounded_in_bytes_not_only_in_rows(tmp_path: Path) -> None:
    """1000 rows is not a bound when a row can be any size.

    The one cap in the code is a row count, so the reply's size is whatever the
    operator's schema happens to make it. Eight concurrent requests against a
    table of wide text values SIGKILLed the pod under the shipped memory limit,
    and the clients got a dropped socket rather than any error at all.
    """
    config = _write(tmp_path, max_response_bytes=64_000)
    response = await _ask(config)

    size = _response_bytes(response)
    assert size <= 64_000 * 2, (
        f"the reply carries {size} bytes from a source configured with "
        f"max_response_bytes=64000; nothing bounds a response in bytes"
    )


@pytest.mark.asyncio
async def test_e9_a_byte_bound_says_it_truncated(tmp_path: Path) -> None:
    """A subset presented as the whole set is the harm, not the subset.

    ``truncated_sources`` already carries exactly this signal for the row cap.
    A byte budget that silently drops rows would be worse than no budget.
    """
    config = _write(tmp_path, max_response_bytes=64_000)
    response = await _ask(config)

    assert response.truncated_sources == ["wide_db"], (
        f"rows were dropped to fit a byte budget and truncated_sources is "
        f"{response.truncated_sources}"
    )


@pytest.mark.asyncio
async def test_e9_the_default_bounds_a_source_no_one_configured(tmp_path: Path) -> None:
    """The operator who hit this had no knob, and no default either.

    A bound that only applies when someone already knew to set it would not
    have saved the pod that died.
    """
    from nautilus.config.loader import load_config

    config = load_config(_write(tmp_path))
    bound = config.sources[0].max_response_bytes
    assert bound is not None and bound > 0, (
        f"a source that configures nothing gets max_response_bytes={bound!r}"
    )


@pytest.mark.asyncio
async def test_e9_a_response_within_the_budget_is_untouched(tmp_path: Path) -> None:
    """Control: the budget must bound the outliers, not trim every reply.

    Without this, a bound that always truncated would satisfy every pin above.
    """
    config = _write(tmp_path, rows=[{"id": 1, "blob": "x" * 10}])
    response = await _ask(config)

    assert response.truncated_sources == [], response.model_dump()
    assert len(response.data["wide_db"]) == 1, response.data


# ---------------------------------------------------------------------------
# The budget is enforced while the rows are read, not after.
# ---------------------------------------------------------------------------


@pytest.mark.docker
@pytest.mark.asyncio
async def test_e9_postgres_stops_reading_once_the_budget_is_met(
    tmp_path: Path, pg_container: str
) -> None:
    """Trimming after ``fetch`` has already paid the memory the pod died of.

    ``conn.fetch`` materialises every row the query matched before a single
    byte budget can be applied, so a bound checked afterwards leaves the peak
    exactly where it was -- which is the number that mattered: 8 concurrent
    requests, 65 MB each, one SIGKILL. The adapter has to stop pulling.
    """
    import asyncpg

    conn = await asyncpg.connect(pg_container)
    try:
        await conn.execute("DROP TABLE IF EXISTS e9_wide")
        await conn.execute("CREATE TABLE e9_wide (id int, blob text)")
        await conn.executemany(
            "INSERT INTO e9_wide VALUES ($1, $2)",
            [(i, "x" * _ROW_BYTES) for i in range(_ROWS)],
        )
    finally:
        await conn.close()

    document: dict[str, Any] = {
        "sources": [
            {
                "id": "wide_db",
                "type": "postgres",
                "classification": "unclassified",
                "data_types": ["orders"],
                "connection": pg_container,
                "table": "public.e9_wide",
                "max_response_bytes": 64_000,
            }
        ],
        "agents": {"a1": {"id": "a1", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
    }
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    # The adapter directly, not through the broker: a backstop that trims after
    # the fact would satisfy an end-to-end assertion while leaving the peak
    # memory exactly where it was, which is the number the pod died of.
    from nautilus.adapters.postgres import PostgresAdapter
    from nautilus.config.loader import load_config
    from nautilus.core.models import IntentAnalysis

    adapter = PostgresAdapter()
    source = load_config(str(path)).sources[0]
    await adapter.connect(source)
    try:
        result = await adapter.execute(
            IntentAnalysis(
                raw_intent="list recent orders",
                data_types_needed=["orders"],
                entities=[],
            ),
            [],
            {},
        )
    finally:
        await adapter.close()

    assert 0 < len(result.rows) < _ROWS, (
        f"the adapter returned {len(result.rows)} of {_ROWS} rows against a "
        f"64000-byte budget; it read the whole table before anything bounded it"
    )
    assert result.truncated, "the adapter dropped rows without saying so"

    response = await _ask(str(path))
    assert response.truncated_sources == ["wide_db"], response.truncated_sources


# ---------------------------------------------------------------------------
# Hashing must not cost another copy of the payload.
# ---------------------------------------------------------------------------


def test_e9_hashing_does_not_materialise_the_whole_payload() -> None:
    """58% of broker CPU was ``json.dumps`` of the response, run twice.

    It is also two full-size string allocations on top of the rows themselves,
    which is most of the gap between a 65 MB reply and 115 MB of process
    memory. The digest must be streamed into the hash, not built first.
    """
    from nautilus.core.attestation_payload import compute_response_hash

    payload = _wide_rows(400)  # ~1.6 MB of canonical JSON
    encoded = len(json.dumps(payload))

    tracemalloc.start()
    try:
        compute_response_hash(payload)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < encoded, (
        f"hashing a {encoded}-byte payload peaked at {peak} bytes of new "
        f"allocation -- the canonical JSON is being materialised in full"
    )


def test_e9_the_hash_is_unchanged_by_streaming_it() -> None:
    """Control: the digest is a documented, verifiable value.

    ``docs/how-to/verify-a-token.md`` tells a caller how to recompute it. A
    cheaper implementation that changed the number would silently invalidate
    every published verification.
    """
    import hashlib
    import random
    from datetime import date, datetime
    from decimal import Decimal
    from uuid import UUID

    from pydantic_core import to_jsonable_python

    from nautilus.core.attestation_payload import compute_response_hash

    def expected(value: Any) -> str:
        canonical = json.dumps(
            to_jsonable_python(value, fallback=str), sort_keys=True, separators=(",", ":")
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    leaves: list[Any] = [
        1,
        2.5,
        "a",
        "",
        "é中",
        None,
        True,
        10**30,
        datetime(2026, 1, 2, 3, 4, 5),  # noqa: DTZ001 — a naive value is the point
        date(2026, 1, 2),
        Decimal("1.25"),
        UUID(int=99),
        b"bytes",
        {1: "a non-string key"},
    ]
    random.seed(19)

    def sample(depth: int = 0) -> Any:
        roll = random.random()
        if depth > 3 or roll < 0.3:
            return random.choice(leaves)
        if roll < 0.65:
            return [sample(depth + 1) for _ in range(random.randint(0, 4))]
        return {
            random.choice(["a", "b", "z", "", "é"]): sample(depth + 1)
            for _ in range(random.randint(0, 4))
        }

    shapes: list[Any] = [
        [],
        {},
        [{"a": 1}],
        {"src": [{"id": 1, "b": "x"}]},
        {"src": [], "other": [{"z": None}]},
        {"a": {"b": {"c": [1, 2, 3]}}},
        *[sample() for _ in range(500)],
    ]
    mismatched = [v for v in shapes if compute_response_hash(v) != expected(v)]
    assert not mismatched, (
        f"{len(mismatched)} of {len(shapes)} payloads hash differently than the "
        f"documented scheme; first: {mismatched[0]!r:.200}"
    )
