"""Journey: the three integration shapes the README advertises.

"As a library" is covered by every other journey. This file covers the two
served shapes -- REST sidecar and MCP -- plus the CLI, since those are what a
deployment actually exposes and where the identity boundary lives.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.journey

API_KEY = "journey-key"


@pytest.fixture
def deployment(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> str:
    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    return write_config(
        {
            "sources": [
                {
                    "id": "patients",
                    "type": "postgres",
                    "description": "patient records",
                    "classification": "confidential",
                    "data_types": ["patients"],
                    "allowed_purposes": ["care"],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.patients",
                },
                {
                    "id": "classified",
                    "type": "postgres",
                    "description": "classified records",
                    "classification": "secret",
                    "data_types": ["patients"],
                    "allowed_purposes": ["care"],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.patients",
                },
            ],
            "agents": {"analyst": {"id": "analyst", "clearance": "confidential"}},
            "api": {"keys": [API_KEY]},
            "audit": {"path": str(tmp_path / "audit.jsonl")},
        }
    )


@pytest.fixture
def client(deployment: str) -> Any:
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    with TestClient(create_app(deployment), headers={"X-API-Key": API_KEY}) as c:
        yield c


_BODY: dict[str, Any] = {
    "agent_id": "analyst",
    "intent": "patient records",
    "context": {"purpose": "care", "session_id": "rest"},
}


# ---------------------------------------------------------------------------
# REST
# ---------------------------------------------------------------------------


def test_rest_returns_the_same_decision_the_library_does(client: Any, deployment: str) -> None:
    """The sidecar must not be a second, differently-behaved policy engine."""
    import asyncio

    from nautilus import Broker

    rest = client.post("/v1/request", json=_BODY)
    assert rest.status_code == 200, rest.text
    rest_body = rest.json()

    async def _library() -> Any:
        broker = Broker.from_config(deployment)
        try:
            return await broker.arequest(_BODY["agent_id"], _BODY["intent"], dict(_BODY["context"]))
        finally:
            await broker.aclose()

    lib = asyncio.run(_library())
    assert sorted(rest_body["sources_queried"]) == sorted(lib.sources_queried)
    assert sorted(rest_body["sources_denied"]) == sorted(lib.sources_denied)


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({}, 401),
        ({"X-API-Key": "wrong-key"}, 401),
        ({"X-API-Key": API_KEY}, 200),
    ],
)
def test_rest_requires_a_configured_api_key(
    deployment: str, headers: dict[str, str], expected: int
) -> None:
    """The transport is the identity boundary: ``agent_id`` is taken verbatim."""
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    with TestClient(create_app(deployment)) as c:
        assert c.post("/v1/request", json=_BODY, headers=headers).status_code == expected


def test_rest_health_and_readiness_probes_answer(client: Any) -> None:
    """Both probes are documented deployment surface."""
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code in (200, 503)


def test_rest_denies_a_source_above_the_agents_clearance(client: Any) -> None:
    """The clearance ladder holds over HTTP, not just in-process."""
    body = client.post("/v1/request", json=_BODY).json()
    assert "classified" in body["sources_denied"]
    assert "classified" not in body["sources_queried"]
    assert "classified" not in json.dumps(body.get("data", {}))


# ---------------------------------------------------------------------------
# MCP (stdio)
# ---------------------------------------------------------------------------


def test_mcp_stdio_exposes_the_request_tool(deployment: str) -> None:
    """``nautilus serve --transport mcp`` must speak MCP over stdio.

    stdio is the mode with a real trust boundary -- the parent process owns
    the pipe. (HTTP mode's missing authentication is pinned as B4.)
    """
    proc = subprocess.Popen(
        [
            str(Path(".venv/bin/nautilus").resolve()),
            "serve",
            "--config",
            deployment,
            "--transport",
            "mcp",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        requests = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "journey", "version": "0"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
        assert proc.stdin is not None and proc.stdout is not None
        lines: list[str] = []
        for request in requests:
            proc.stdin.write(json.dumps(request) + "\n")
            proc.stdin.flush()
            if "id" not in request:
                continue
            # Read the matching reply before sending the next request; closing
            # stdin first shuts the server down before it can answer.
            line = proc.stdout.readline()
            lines.append(line)
            assert line, "the MCP server closed stdout mid-conversation"
    finally:
        proc.kill()
        _, stderr = proc.communicate(timeout=30)

    stdout = "".join(lines)
    assert "nautilus_request" in stdout, (
        f"the MCP server did not advertise the nautilus_request tool.\n"
        f"stdout={stdout[:2000]}\nstderr={stderr[-2000:]}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _nautilus(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(Path(".venv/bin/nautilus").resolve()), *args],
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_cli_health_fails_loudly_when_nothing_is_listening(tmp_path: Path) -> None:
    """``nautilus health`` probes a readiness URL; an unreachable one must be rc!=0.

    A health check that exits 0 when nothing answers is worse than none.
    """
    result = _nautilus("health", "--url", "http://127.0.0.1:1/readyz")
    assert result.returncode != 0, (
        f"`nautilus health` exited 0 against a port with nothing listening: "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_cli_rules_validate_accepts_the_shipped_rules() -> None:
    """The rules Nautilus ships must pass the validator Nautilus ships."""
    from nautilus.rules import BUILT_IN_RULES_DIR

    failures: list[str] = []
    # ``rules/`` holds the rulesets; hierarchies, templates, modules and
    # function definitions are different document kinds the validator does
    # not accept, by design.
    for path in sorted((Path(BUILT_IN_RULES_DIR) / "rules").glob("*.yaml")):
        result = _nautilus("rules", "validate", str(path))
        if result.returncode != 0:
            failures.append(f"{path.name}: {(result.stderr or result.stdout).strip()}")
    assert not failures, "shipped rules rejected by the shipped validator:\n" + "\n".join(failures)
