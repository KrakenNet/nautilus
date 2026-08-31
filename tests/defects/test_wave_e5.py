"""WAVE E5 — the two shipped deployment shapes, and what MCP hands a model.

Both findings were reproduced first-hand before a line of fix was written.

1. **Every request errors under a read-only config mount.** The schema-drift
   baseline store writes to ``<config dir>/.nautilus/adapters/fingerprints/``,
   and adapter registration happens inside the request path, so an unwritable
   config directory is not a startup failure — it is::

       outcome: errored
       error_type: PermissionError
       message: [Errno 13] Permission denied: '/config/.nautilus'

   on *every* request. Both shipped deployment shapes are exactly that:
   ``examples/full-showcase/docker-compose.yml`` mounts
   ``./nautilus.yaml:/config/nautilus.yaml:ro`` into an image that runs as
   UID 65532, and ``deploy/deployment.yaml`` mounts a ConfigMap at ``/config``
   with ``readOnly: true`` under ``readOnlyRootFilesystem: true``.

   Two things are wrong and both are fixed here. An unwritable baseline
   directory must degrade to memory-only with one warning rather than fail a
   request that policy already allowed — a drift *baseline* is not worth an
   outage. And the baselines need somewhere to live that is not the config
   mount, so ``state_dir`` says where. ``deploy/deployment.yaml`` already
   reserves ``/var/lib/nautilus`` for exactly this and the config that goes
   with it already writes the session key ring there; nothing pointed the
   baselines at it.

2. **The MCP tool result is unbounded.** Measured against a real stdio MCP
   session, one ``nautilus_request`` call over a 2000-row source::

       tool reply bytes: 1882758
       content text bytes: 970338
       truncated_sources: []

   An MCP tool result is read straight into a model's context window, and
   FastMCP returns the payload twice (``content[0].text`` and
   ``structuredContent``), so the wire cost is double what the broker
   produced. Adapters cap at 1000 rows *each*, so a config with several
   sources multiplies from there. REST has no equivalent problem: an HTTP
   client streams to a file.

   The bound truncates whole rows and names every source it touched in
   ``truncated_sources`` — the same field the adapter row cap already uses,
   because from the caller's side both mean "you were given a subset".
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from nautilus.core.broker import Broker

pytestmark = [pytest.mark.integration]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_NAUTILUS = str((_REPO_ROOT / ".venv" / "bin" / "nautilus").resolve())

_AGENTS: dict[str, Any] = {"a1": {"id": "a1", "clearance": "unclassified"}}


def _source(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": "orders",
        "type": "static",
        "classification": "unclassified",
        "data_types": ["orders"],
        "rows": rows,
    }


# ---------------------------------------------------------------------------
# A read-only config mount.
# ---------------------------------------------------------------------------


def _read_only_config(tmp_path: Path, **overrides: Any) -> Path:
    """A config in a directory the process cannot write to.

    ``chmod 555`` on the directory reproduces the container case exactly: the
    file is readable, the directory is not writable, and the process is not
    the owner of the mount.
    """
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    document: dict[str, Any] = {
        "sources": [_source([{"id": 1, "region": "us-east"}])],
        "agents": _AGENTS,
        "audit": {"path": str(tmp_path / "audit.jsonl")},
    }
    document.update(overrides)
    path = config_dir / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    os.chmod(config_dir, 0o555)
    return path


@pytest.fixture
def _not_root() -> None:
    if os.geteuid() == 0:
        pytest.skip("root writes through a 0o555 directory; the mount case needs a real user")


# ``tests/conftest.py`` redirects every baseline into one shared tmp directory
# so ~20 tests sharing a fixture config do not quarantine each other. These
# pins are about *where* a baseline lands and what happens when it cannot be
# written, so they need the resolution the shipped code actually performs.
_REAL_FINGERPRINT_ROOT = Broker.__dict__["_fingerprint_root"]


@pytest.fixture(autouse=True)
def _use_the_real_baseline_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Broker, "_fingerprint_root", _REAL_FINGERPRINT_ROOT)


@pytest.mark.asyncio
@pytest.mark.usefixtures("_not_root")
async def test_e5_a_read_only_config_directory_still_serves_requests(tmp_path: Path) -> None:
    """A drift baseline it cannot persist must not fail the request.

    The baseline is a detection aid. Losing the ability to write one is worth
    a warning; it is not worth turning every allowed request into
    ``outcome: errored``, which is what both shipped deployment shapes do.
    """
    config = _read_only_config(tmp_path)
    broker = await Broker.afrom_config(str(config))
    try:
        response = await broker.arequest(
            "a1", "list recent orders", {"purpose": "analytics", "session_id": "s1"}
        )
    finally:
        await broker.aclose()

    assert response.outcome == "allowed", (
        f"a read-only config directory produced outcome={response.outcome!r}: "
        f"{[e.model_dump() for e in response.sources_errored]}"
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("_not_root")
async def test_e5_state_dir_keeps_baselines_off_the_config_mount(tmp_path: Path) -> None:
    """``state_dir`` is where the baselines go when ``/config`` is read-only.

    Without somewhere writable to point them, the fix above leaves schema
    drift undetectable across a restart in every shipped deployment — the
    quarantine is only as good as the baseline it compares against.
    """
    state = tmp_path / "state"
    state.mkdir()
    config = _read_only_config(tmp_path, state_dir=str(state))

    broker = await Broker.afrom_config(str(config))
    try:
        await broker.arequest(
            "a1", "list recent orders", {"purpose": "analytics", "session_id": "s1"}
        )
    finally:
        await broker.aclose()

    baselines = sorted(state.rglob("*.json"))
    assert baselines, (
        f"state_dir={state} holds no schema baseline after a request; "
        f"found {sorted(p.name for p in state.rglob('*'))}"
    )


@pytest.mark.asyncio
async def test_e5_a_writable_config_directory_still_persists_baselines(tmp_path: Path) -> None:
    """Control: the default is unchanged where the config directory is writable.

    Degrading on failure must not become degrading always — a baseline that
    silently stops persisting is drift detection that silently stops working.
    """
    document: dict[str, Any] = {
        "sources": [_source([{"id": 1, "region": "us-east"}])],
        "agents": _AGENTS,
        "audit": {"path": str(tmp_path / "audit.jsonl")},
    }
    config = tmp_path / "nautilus.yaml"
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    broker = await Broker.afrom_config(str(config))
    try:
        await broker.arequest(
            "a1", "list recent orders", {"purpose": "analytics", "session_id": "s1"}
        )
    finally:
        await broker.aclose()

    assert sorted((tmp_path / ".nautilus").rglob("*.json")), (
        "a writable config directory stopped persisting schema baselines"
    )


def test_e5_the_shipped_kubernetes_config_puts_state_on_the_writable_volume() -> None:
    """The manifest mounts ``/config`` read-only; its config must not write there.

    ``deploy/deployment.yaml`` already declares a writable ``state`` volume at
    ``/var/lib/nautilus`` and the ConfigMap already writes the session key ring
    into it. The baselines were the one piece still aimed at the read-only
    mount.
    """
    configmap = yaml.safe_load((_REPO_ROOT / "deploy" / "configmap.yaml").read_text())
    shipped = yaml.safe_load(configmap["data"]["nautilus.yaml"])
    state_dir = shipped.get("state_dir")
    assert state_dir, (
        "deploy/configmap.yaml sets no state_dir, so the broker writes its "
        "schema baselines under /config — which deployment.yaml mounts "
        "readOnly: true beneath readOnlyRootFilesystem: true"
    )
    deployment = yaml.safe_load((_REPO_ROOT / "deploy" / "deployment.yaml").read_text())
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    writable = {m["mountPath"] for m in container["volumeMounts"] if not m.get("readOnly", False)}
    assert any(str(state_dir).startswith(m) for m in sorted(writable)), (
        f"state_dir={state_dir!r} is not under any writable volumeMount {sorted(writable)}"
    )


# ---------------------------------------------------------------------------
# What MCP hands a model.
# ---------------------------------------------------------------------------


def _mcp_call(config: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    """Run one ``tools/call`` against a real stdio MCP server and return the reply.

    Raw JSON-RPC over the pipe rather than the SDK client: this pin is about
    how many bytes cross that pipe, so measuring anything the SDK has already
    re-encoded would measure the wrong thing.
    """
    proc = subprocess.Popen(  # noqa: S603 — a fixed argv, no shell
        [_NAUTILUS, "serve", "--config", str(config), "--transport", "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(_REPO_ROOT),
    )
    requests: list[dict[str, Any]] = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "wave-e5", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "nautilus_request", "arguments": arguments},
        },
    ]
    lines: list[str] = []
    try:
        assert proc.stdin is not None and proc.stdout is not None  # noqa: S101
        for request in requests:
            proc.stdin.write(json.dumps(request) + "\n")
            proc.stdin.flush()
            if "id" not in request:
                continue
            line = proc.stdout.readline()
            assert line, "the MCP server closed stdout mid-conversation"  # noqa: S101
            lines.append(line)
    finally:
        proc.kill()
        _, stderr = proc.communicate(timeout=60)

    reply: dict[str, Any] = json.loads(lines[-1])
    assert "result" in reply, f"tools/call failed: {reply}\nstderr={stderr[-2000:]}"
    payload: dict[str, Any] = json.loads(reply["result"]["content"][0]["text"])
    return {"wire_bytes": len(lines[-1]), "payload": payload}


def _big_config(tmp_path: Path, rows: int, **overrides: Any) -> Path:
    document: dict[str, Any] = {
        "sources": [_source([{"id": i, "note": "x" * 400} for i in range(rows)])],
        "agents": _AGENTS,
        "audit": {"path": str(tmp_path / "audit.jsonl")},
    }
    document.update(overrides)
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


_ARGS: dict[str, Any] = {
    "agent_id": "a1",
    "intent": "list recent orders",
    "context": {"purpose": "analytics", "session_id": "s1"},
}
# The shipped default. A pin that invents its own bound proves nothing about
# what an operator who configured nothing actually gets.
_SHIPPED_MAX_RESPONSE_BYTES = 262_144


def test_e5_the_mcp_tool_result_is_bounded(tmp_path: Path) -> None:
    """One tool call must not put a megabyte into a model's context window.

    Measured at 1 882 758 bytes on the wire for a single 2000-row source,
    because FastMCP sends the payload twice. Adapters cap at 1000 rows each,
    so several sources multiply from there.
    """
    result = _mcp_call(_big_config(tmp_path, rows=2000), _ARGS)

    assert result["wire_bytes"] <= 4 * _SHIPPED_MAX_RESPONSE_BYTES, (
        f"one nautilus_request reply was {result['wire_bytes']} bytes on the "
        f"wire against a default bound of {_SHIPPED_MAX_RESPONSE_BYTES}"
    )


def test_e5_a_truncated_mcp_result_says_it_truncated(tmp_path: Path) -> None:
    """Silently dropping rows is worse than the size it saves.

    A model given 40 of 2000 orders with no signal reasons over the 40 as if
    they were all of them. ``truncated_sources`` is the field that already
    means "you were given a subset"; the transport bound has to use it.
    """
    result = _mcp_call(_big_config(tmp_path, rows=2000), _ARGS)
    payload = result["payload"]

    assert payload["outcome"] == "allowed", payload
    assert "orders" in payload.get("truncated_sources", []), (
        f"rows were dropped to fit the MCP bound without saying so: "
        f"data={ {k: len(v) for k, v in payload.get('data', {}).items()} }, "
        f"truncated_sources={payload.get('truncated_sources')}"
    )


def test_e5_a_small_mcp_result_is_returned_whole(tmp_path: Path) -> None:
    """Control: a response that fits is untouched, and says nothing truncated."""
    result = _mcp_call(_big_config(tmp_path, rows=5), _ARGS)
    payload = result["payload"]

    assert payload["outcome"] == "allowed", payload
    assert len(payload["data"]["orders"]) == 5, (
        f"a 5-row response came back with {len(payload['data']['orders'])} rows"
    )
    assert payload.get("truncated_sources") == [], (
        f"a response well under the bound reported "
        f"truncated_sources={payload.get('truncated_sources')}"
    )
