"""Live-backend fixtures for the journey suite.

Journey tests assert what the documentation promises a user gets, end to end,
against real backends. Nothing here mocks the subject under test: the whole
point of this suite is that a query reaches a real engine and the engine's
answer is what gets asserted.

Every backend fixture is session-scoped and lazy -- a container starts only
when a test actually requests it -- and every one skips rather than fails when
Docker is unavailable, so a contributor without a daemon can still run the
pure-function unit tests.

``pytest_collection_modifyitems`` in the root conftest marks anything touching
a container fixture with ``docker`` so CI can select on it.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml


def _docker_available() -> bool:
    """True when a Docker daemon is reachable, not merely when the CLI exists."""
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(("docker", "info"), capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(), reason="needs a running Docker daemon"
)


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    """Postgres 16 with pgvector, seeded with the journey schema.

    The image carries the extension so the vector journey and the plain SQL
    journey can share one container.
    """
    if not _docker_available():
        pytest.skip("needs a running Docker daemon")
    import asyncio

    import asyncpg
    from testcontainers.postgres import PostgresContainer  # pyright: ignore[reportMissingTypeStubs]

    container = PostgresContainer("pgvector/pgvector:pg16", driver=None)
    container.start()
    try:
        dsn: str = container.get_connection_url()

        async def _seed() -> None:
            conn: Any = await asyncpg.connect(dsn=dsn)
            try:
                await conn.execute(_JOURNEY_SCHEMA)
            finally:
                await conn.close()

        asyncio.run(_seed())
        yield dsn
    finally:
        container.stop()


@pytest.fixture(scope="session")
def es_url() -> Iterator[str]:
    """Elasticsearch with **default dynamic mapping**.

    Deliberately not a hand-pinned ``keyword`` mapping. Pinning the mapping is
    what let the adapter's term-query defect survive the previous suite: a
    string field ES maps on its own is ``text`` + ``.keyword``, and that is
    what a user who just indexes documents actually gets.
    """
    if not _docker_available():
        pytest.skip("needs a running Docker daemon")
    from testcontainers.elasticsearch import (  # pyright: ignore[reportMissingTypeStubs]
        ElasticSearchContainer,
    )

    container = ElasticSearchContainer("elasticsearch:8.15.0", mem_limit="2G")
    container.start()
    try:
        host = container.get_container_host_ip()
        yield f"http://{host}:{container.get_exposed_port(9200)}"
    finally:
        container.stop()


@pytest.fixture(scope="session")
def neo4j_bolt() -> Iterator[tuple[str, str, str]]:
    """Neo4j 5. Yields ``(bolt_url, user, password)``."""
    if not _docker_available():
        pytest.skip("needs a running Docker daemon")
    from testcontainers.neo4j import Neo4jContainer  # pyright: ignore[reportMissingTypeStubs]

    container = Neo4jContainer("neo4j:5")
    container.start()
    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(7687)
        yield (f"bolt://{host}:{port}", "neo4j", container.password)
    finally:
        container.stop()


def _wait_http(url: str, timeout: float = 90.0) -> None:
    """Poll ``url`` until it answers, rather than scraping container logs."""
    import time
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2).read()  # noqa: S310
            return
        except urllib.error.HTTPError:
            return
        except OSError:
            time.sleep(0.5)
    raise TimeoutError(f"{url} never answered within {timeout}s")


@pytest.fixture(scope="session")
def minio_endpoint() -> Iterator[tuple[str, str, str]]:
    """MinIO over the S3 API. Yields ``(endpoint_url, access_key, secret_key)``."""
    if not _docker_available():
        pytest.skip("needs a running Docker daemon")
    from testcontainers.core.container import (  # pyright: ignore[reportMissingTypeStubs]
        DockerContainer,
    )

    container = (
        DockerContainer("minio/minio")
        .with_command("server /data")
        .with_env("MINIO_ROOT_USER", "nautilus")
        .with_env("MINIO_ROOT_PASSWORD", "nautilus123")
        .with_exposed_ports(9000)
    )
    container.start()
    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(9000)
        endpoint = f"http://{host}:{port}"
        _wait_http(f"{endpoint}/minio/health/live")
        yield (endpoint, "nautilus", "nautilus123")
    finally:
        container.stop()


@pytest.fixture(scope="session")
def influx() -> Iterator[tuple[str, str, str, str]]:
    """InfluxDB 2. Yields ``(url, org, bucket, token)``."""
    if not _docker_available():
        pytest.skip("needs a running Docker daemon")
    from testcontainers.core.container import (  # pyright: ignore[reportMissingTypeStubs]
        DockerContainer,
    )

    token = "journey-token"
    container = (
        DockerContainer("influxdb:2")
        .with_env("DOCKER_INFLUXDB_INIT_MODE", "setup")
        .with_env("DOCKER_INFLUXDB_INIT_USERNAME", "nautilus")
        .with_env("DOCKER_INFLUXDB_INIT_PASSWORD", "nautilus123")
        .with_env("DOCKER_INFLUXDB_INIT_ORG", "nautilus")
        .with_env("DOCKER_INFLUXDB_INIT_BUCKET", "journey")
        .with_env("DOCKER_INFLUXDB_INIT_ADMIN_TOKEN", token)
        .with_exposed_ports(8086)
    )
    container.start()
    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(8086)
        url = f"http://{host}:{port}"
        # "Listening" reaches the log before the write endpoint accepts
        # connections, so probe /health rather than scraping logs.
        _wait_http(f"{url}/health")
        yield (url, "nautilus", "journey", token)
    finally:
        container.stop()


# ---------------------------------------------------------------------------
# Config authoring
# ---------------------------------------------------------------------------


@pytest.fixture
def write_config(tmp_path: Path) -> Any:
    """Write a ``nautilus.yaml`` and return its path.

    Journey tests build the config a user would write, rather than reaching
    into ``Broker.__init__``, so the config schema is exercised on every run.
    Paths default to ``tmp_path`` so a journey never writes into the repo.
    """

    def _write(config: dict[str, Any], name: str = "nautilus.yaml") -> str:
        config = dict(config)
        config.setdefault("audit", {"path": str(tmp_path / "audit.jsonl")})
        config.setdefault("attestation", {"enabled": True})
        config.setdefault("rules", {"packs": [], "user_rules_dirs": []})
        path = tmp_path / name
        path.write_text(yaml.safe_dump(config), encoding="utf-8")
        return str(path)

    return _write


_JOURNEY_SCHEMA = """
CREATE SCHEMA IF NOT EXISTS journey;

CREATE TABLE IF NOT EXISTS journey.patients (
    id serial PRIMARY KEY,
    name text NOT NULL,
    ssn text NOT NULL,
    region text NOT NULL,
    severity int NOT NULL,
    diagnosis text NOT NULL
);

CREATE TABLE IF NOT EXISTS journey.vulns (
    id serial PRIMARY KEY,
    cve text NOT NULL,
    region text NOT NULL,
    severity int NOT NULL,
    title text NOT NULL
);

TRUNCATE journey.patients, journey.vulns;

INSERT INTO journey.patients (name, ssn, region, severity, diagnosis) VALUES
    ('Alice',  '111-22-3333', 'us-east', 1, 'hypertension'),
    ('Bob',    '222-33-4444', 'us-west', 3, 'diabetes'),
    ('Carol',  '333-44-5555', 'eu-west', 5, 'asthma'),
    -- deliberately hostile values: a scope constraint that reaches the
    -- backend unescaped changes which of these rows come back.
    ('Mallory', '444-55-6666', 'us-east'' OR ''1''=''1', 2, 'quote injection'),
    ('Trudy',   '555-66-7777', E'us-east\\\\', 4, 'backslash');

INSERT INTO journey.vulns (cve, region, severity, title) VALUES
    ('CVE-2026-0001', 'us-east', 9, 'remote code execution'),
    ('CVE-2026-0002', 'us-west', 4, 'information disclosure'),
    ('CVE-2026-0003', 'eu-west', 7, 'privilege escalation');
"""
