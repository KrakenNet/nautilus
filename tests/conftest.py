"""Shared pytest fixtures for Nautilus test suite.

Phase-1 MVP fixtures land here. The ``pg_container`` fixture boots a
``pgvector/pgvector:pg17`` testcontainer once per session, enables the
``vector`` extension, and loads ``tests/fixtures/seed.sql`` so both the
``PostgresAdapter`` and ``PgVectorAdapter`` integration paths can share a
single database (design §13.3 / §15 step 13).

``poc_tmp_cleanup`` (autouse, session-scoped) sweeps any stray
``/tmp/poc-*.jsonl`` artifacts left behind by earlier runs so the Task 1.15
POC gate starts each session on a clean slate. Windows hosts (no ``/tmp``)
no-op silently.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from testcontainers.postgres import PostgresContainer  # pyright: ignore[reportMissingTypeStubs]


@pytest.fixture(scope="session", autouse=True)
def poc_tmp_cleanup() -> Iterator[None]:
    """Sweep stray ``/tmp/poc-*.jsonl`` artifacts at session start/end.

    The Task 1.15 POC spec nominally writes attestation to
    ``/tmp/poc-attestation.jsonl``; the integration test redirects under
    ``tmp_path`` but if any earlier run (or hand-invoked verify step) leaked
    files onto ``/tmp``, clear them so assertions are never cross-contaminated.
    """
    tmp_dir = Path("/tmp")
    if tmp_dir.exists():
        for stale in tmp_dir.glob("poc-*.jsonl"):
            stale.unlink(missing_ok=True)
    yield
    if tmp_dir.exists():
        for stale in tmp_dir.glob("poc-*.jsonl"):
            stale.unlink(missing_ok=True)


# Resolve the seed SQL alongside this conftest so the file stays portable
# regardless of the pytest invocation cwd.
_SEED_SQL_PATH: Path = Path(__file__).parent / "fixtures" / "seed.sql"


@pytest.fixture(scope="session")
def fake_intent_analyzer() -> Any:
    """Returns a stand-in intent analyzer.

    Real implementation (Task 1.10) will return a Protocol impl producing a
    fixed `IntentAnalysis`. For now we return `None` so importing conftest
    does not depend on types that do not yet exist.
    """
    return None


@pytest.fixture(scope="session")
def in_memory_audit_sink() -> list[Any]:
    """Collect audit entries into a list for assertions.

    Real implementation (Task 1.16) collects `AuditEntry` instances; the
    list API is stable so tests can append/read today.
    """
    return []


@pytest.fixture(scope="session")
def fake_adapter() -> Callable[..., Any]:
    """Callable-configurable fake adapter factory.

    Real implementation (Task 1.14) returns an `Adapter` whose `.query()`
    either returns a configured `AdapterResult` or raises a configured
    exception. For now we expose a factory that echoes its arguments so
    tests can verify wiring without depending on unbuilt types.
    """

    def _factory(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"args": args, "kwargs": kwargs}

    return _factory


@pytest.fixture(scope="session")
def pg_container() -> Iterator[str]:
    """Session-scoped ``pgvector/pgvector:pg17`` container (design §15 step 13).

    Steps on startup:
    1. Launch the container (``driver=None`` so the URL is a plain
       ``postgresql://`` DSN that ``asyncpg`` accepts natively).
    2. Connect once via psycopg / asyncpg to ``CREATE EXTENSION vector``
       and execute ``tests/fixtures/seed.sql``.
    3. Export ``TEST_PG_DSN`` and ``TEST_PGV_DSN`` into ``os.environ`` —
       both point to the same container database. The ``nautilus.yaml``
       fixture uses two distinct tables (``vulns`` and ``vuln_embeddings``)
       inside the single DB.

    Yields the asyncpg-compatible DSN for callers that want it directly
    (most integration tests consume it via the env vars above).
    """
    import asyncio

    import asyncpg  # pyright: ignore[reportMissingTypeStubs]

    container = PostgresContainer("pgvector/pgvector:pg17", driver=None)
    container.start()
    try:
        dsn: str = container.get_connection_url()
        seed_sql = _SEED_SQL_PATH.read_text(encoding="utf-8")

        async def _init() -> None:
            conn: Any = await asyncpg.connect(dsn=dsn)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType, reportAny]
            try:
                # ``CREATE EXTENSION`` cannot run inside an asyncpg "simple
                # query" if the seed file also starts with it, so issue it
                # once here explicitly and let the seed ``IF NOT EXISTS``
                # guard handle idempotence.
                await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")  # pyright: ignore[reportUnknownMemberType]
                await conn.execute(seed_sql)  # pyright: ignore[reportUnknownMemberType]
            finally:
                await conn.close()  # pyright: ignore[reportUnknownMemberType]

        asyncio.run(_init())

        os.environ["TEST_PG_DSN"] = dsn
        os.environ["TEST_PGV_DSN"] = dsn
        yield dsn
    finally:
        os.environ.pop("TEST_PG_DSN", None)
        os.environ.pop("TEST_PGV_DSN", None)
        container.stop()


# ---------------------------------------------------------------------------
# nautilus-update-1 / Task 47 — Nautobot testcontainer fixture (TD-9).
#
# Hybrid strategy: by default tests replay VCR cassettes (``VCR_MODE=replay``,
# < 60s in branch CI, no Docker needed). Setting ``VCR_MODE=record`` and
# selecting ``-m nautobot_live`` spins a fresh ``networktocode/nautobot:3.1``
# container (~60-90s cold start), seeds it via the bundled fixture data,
# re-records the four happy-path cassettes under ``tests/fixtures/nautobot/``,
# and tears down. Branch CI never runs the live mode.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def nautobot_container() -> Iterator[dict[str, str]]:
    """Spin a session-scoped Nautobot 3.1 testcontainer (live record mode).

    Skipped automatically unless ``VCR_MODE=record`` is set in the environment
    AND the test is collected with ``-m nautobot_live``. Returns the resolved
    ``url`` + ``token`` for the container.
    """
    if os.environ.get("VCR_MODE", "replay") != "record":
        pytest.skip("nautobot_container fixture only spins in VCR_MODE=record")
    try:
        from testcontainers.compose import DockerCompose  # pyright: ignore[reportMissingTypeStubs]
    except ImportError:
        pytest.skip("testcontainers compose extra is not installed")

    fixtures_dir = Path(__file__).parent / "fixtures" / "nautobot"
    compose_file = fixtures_dir / "docker-compose.nautobot.yml"
    if not compose_file.exists():
        pytest.skip(
            f"nautobot compose file not present at {compose_file}; "
            "supply it before running ``-m nautobot_live``"
        )
    project = DockerCompose(str(fixtures_dir), compose_file_name=compose_file.name)
    project.start()
    try:
        host = project.get_service_host("nautobot", 8080)
        port = project.get_service_port("nautobot", 8080)
        url = f"http://{host}:{port}"
        # Token must be seeded by the compose stack's bootstrap step. Tests
        # rely on ``NAUTOBOT_TOKEN`` env var so production-style flow is
        # exercised end-to-end.
        token = os.environ.get("NAUTOBOT_TOKEN", "0123456789abcdef0123456789abcdef01234567")
        os.environ.setdefault("NAUTOBOT_URL", url)
        os.environ.setdefault("NAUTOBOT_TOKEN", token)
        yield {"url": url, "token": token}
    finally:
        project.stop()
