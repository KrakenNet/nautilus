# pyright: reportPrivateUsage=false
"""WAVE ops14 — a broker whose backends are gone reported itself healthy.

An operator given only ``docs/`` was told to reach the goal state *"when
something the service depends on goes away, the service names it"* over HTTP,
and could not: they had to stand up an adapter of their own instead.

**Nothing at HTTP level distinguished the two brokers.** ``GET /readyz`` probes
the audit sink and then the session store and never a source, so a broker whose
every source is unreachable answers ``200 {"status": "ok"}``. ``POST
/v1/request`` puts the failure in ``sources_errored`` inside a ``200`` — which
is right for the *caller*, and useless to an operator who is not one.

**The one route the documentation invited them to probe answered a false
green.** ``docs/reference/rest-api.md`` documents ``GET
/v1/adapters/{name}/schema`` as ``503 Schema fetch failed: <error>`` when the
introspection call fails. ``llm``, ``rest`` and ``s3`` return
``AdapterSchema.unknown()`` — a capability-only schema stamped ``fetched_at =
now()`` — without touching the backend at all, so the route answered ``200``
with a fresh timestamp against an endpoint that was not listening. Measured
before the fix, with nothing bound to the port::

    GET /v1/adapters/assistant/schema
    200 {"adapter_id":"llm","source_type":"llm","tables":[],
         "capability_flags":{},"fetched_at":"2026-09-02T11:10:10.670278Z"}

What these pin:

* readiness keeps its meaning — sources are a *partial* dependency and do not
  gate traffic — and the documentation says so, and names the surface that does
  answer for them;
* ``GET /v1/adapters?probe=true`` dials every source and reports which ones
  answer, with the address it dialled;
* the schema route refuses to describe an adapter whose backend is gone;
* the durability table's "lose the audit log and nothing else breaks" is true
  of the *file* and false of its *directory*, and the table says which.
"""

from __future__ import annotations

import contextlib
import shutil
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import yaml
from fastapi.testclient import TestClient

from nautilus.transport.fastapi_app import create_app

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = [pytest.mark.integration]

_AUTH = {"X-API-Key": "ops14-key"}
_AGENT = "analyst"


class _Quiet(BaseHTTPRequestHandler):
    """Answers `HEAD /` and says nothing on stderr."""

    def do_HEAD(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's spelling
        self.send_response(200)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


@contextlib.contextmanager
def _live_backend() -> Iterator[int]:
    """A backend that answers — the control for "unreachable".

    A bare listening socket is not one: the kernel completes the handshake for
    a process that has stopped reading, which is what a paused container looks
    like, and reporting that as healthy is the defect under test.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextlib.contextmanager
def _frozen_backend() -> Iterator[int]:
    """A listener that accepts and never answers — ``docker pause``, in-process."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    try:
        yield int(sock.getsockname()[1])
    finally:
        sock.close()


def _closed_port() -> int:
    """A port nothing is bound to: what a stopped container leaves behind."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _config(root: Path, llm_port: int) -> str:
    """One remote source (``llm``) and one local one (``static``).

    ``llm`` is the only built-in that may dial a loopback address, so it is the
    only one that can be pointed at a port this test controls without tripping
    the SSRF guard. ``static`` has no address at all and is the control for
    "there is nothing here to be gone".
    """
    document: dict[str, Any] = {
        "sources": [
            {
                "id": "assistant",
                "type": "llm",
                "classification": "unclassified",
                "data_types": ["summary"],
                "connection": f"http://127.0.0.1:{llm_port}/v1",
                "model": "ops14-model",
                "timeout_s": 2.0,
            },
            {
                "id": "orders",
                "type": "static",
                "classification": "unclassified",
                "data_types": ["orders"],
                "rows": [{"order_id": 1}],
            },
        ],
        "agents": {_AGENT: {"id": _AGENT, "clearance": "unclassified"}},
        "audit": {"path": str(root / "auditdir" / "audit.jsonl")},
        "api": {"keys": ["ops14-key"]},
        "analysis": {"keyword_map": {"summary": ["summary"], "orders": ["orders"]}},
    }
    (root / "auditdir").mkdir(exist_ok=True)
    config = root / "nautilus.yaml"
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(config)


# ---------------------------------------------------------------------------
# 1. A dead source is visible over HTTP, and readiness still means what it said.
# ---------------------------------------------------------------------------


def test_a_source_whose_backend_is_gone_is_named_over_http(tmp_path: Path) -> None:
    """The goal state. One unauthenticated-shaped GET names the dead backend.

    Before: ``/readyz`` said ``ok``, ``GET /v1/adapters`` said ``active``, and
    the only place the failure appeared was inside a caller's ``200``.
    """
    port = _closed_port()
    with TestClient(create_app(_config(tmp_path, port))) as client:
        ready = client.get("/readyz")
        probed = client.get("/v1/adapters", params={"probe": "true"}, headers=_AUTH)

    # Readiness is unchanged and deliberate: a source is a partial dependency.
    assert ready.status_code == 200, ready.text
    assert ready.json() == {"status": "ok"}

    assert probed.status_code == 200, probed.text
    adapters = {a["id"]: a for a in probed.json()["adapters"]}
    assert adapters["assistant"]["reachable"] is False, (
        f"a source pointed at a closed port reported {adapters['assistant']!r}; "
        f"nothing at HTTP level distinguishes it from a healthy one"
    )
    assert adapters["assistant"]["endpoint"] == f"http://127.0.0.1:{port}", adapters["assistant"]
    assert str(port) in (adapters["assistant"]["detail"] or ""), adapters["assistant"]
    # A source with no remote endpoint is not reported as reachable — nothing
    # was dialled, and a probe that answers for what it did not check is the
    # defect this test exists for.
    assert adapters["orders"]["reachable"] is None, adapters["orders"]
    assert adapters["orders"]["endpoint"] is None, adapters["orders"]


def test_a_source_whose_backend_answers_probes_reachable(tmp_path: Path) -> None:
    """Control. The probe must be able to come back true, or it proves nothing."""
    with _live_backend() as port, TestClient(create_app(_config(tmp_path, port))) as client:
        probed = client.get("/v1/adapters", params={"probe": "true"}, headers=_AUTH)

    assert probed.status_code == 200, probed.text
    adapters = {a["id"]: a for a in probed.json()["adapters"]}
    assert adapters["assistant"]["reachable"] is True, adapters["assistant"]
    assert adapters["assistant"]["detail"] is None, adapters["assistant"]


def test_a_backend_that_accepts_and_never_answers_is_not_reachable(tmp_path: Path) -> None:
    """A completed TCP handshake is not evidence anything is alive behind it.

    Measured against a real container: ``docker pause nautaudit-probe-pg`` and
    ``asyncio.open_connection`` still reported ``CONNECTED in 0.00s``, because
    the kernel finishes the handshake into a backlog the frozen process never
    drains. That is the shape of the failure the operator trial hit — an
    endpoint that was *paused*, not removed — so a probe that stops at connect
    would have reported it healthy.
    """
    with _frozen_backend() as port, TestClient(create_app(_config(tmp_path, port))) as client:
        probed = client.get("/v1/adapters", params={"probe": "true"}, headers=_AUTH)

    assert probed.status_code == 200, probed.text
    assistant = next(a for a in probed.json()["adapters"] if a["id"] == "assistant")
    assert assistant["reachable"] is False, assistant
    assert "within 2.0s" in (assistant["detail"] or ""), assistant


def test_the_unprobed_listing_is_byte_for_byte_what_it_documented(tmp_path: Path) -> None:
    """Control. The default answer is the cheap in-process listing it always was.

    ``nautilus adapters list --url`` reads this route; a probe on every call
    would put a dial on the critical path of a listing.
    """
    with TestClient(create_app(_config(tmp_path, _closed_port()))) as client:
        listed = client.get("/v1/adapters", headers=_AUTH)

    assert listed.status_code == 200, listed.text
    assert listed.json() == {
        "adapters": [
            {"id": "assistant", "type": "llm", "status": "active"},
            {"id": "orders", "type": "static", "status": "active"},
        ]
    }


# ---------------------------------------------------------------------------
# 2. The route documented to 503 on adapter failure does not answer a fresh 200.
# ---------------------------------------------------------------------------


def test_the_schema_route_refuses_an_adapter_whose_backend_is_gone(tmp_path: Path) -> None:
    """The (b) pin. ``llm`` never dialled, so ``fetched_at`` was a fresh lie."""
    port = _closed_port()
    with TestClient(create_app(_config(tmp_path, port))) as client:
        resp = client.get("/v1/adapters/assistant/schema", headers=_AUTH)

    assert resp.status_code == 503, (
        f"the route documented as '503 Schema fetch failed' answered "
        f"{resp.status_code} for an adapter whose endpoint is closed: {resp.text[:300]}"
    )
    detail = resp.json()["detail"]
    assert detail.startswith("Schema fetch failed: "), detail
    assert f"http://127.0.0.1:{port}" in detail, detail


def test_the_schema_route_still_answers_for_a_reachable_backend(tmp_path: Path) -> None:
    """Control. The 503 is about the backend, not about the route."""
    with _live_backend() as port, TestClient(create_app(_config(tmp_path, port))) as client:
        resp = client.get("/v1/adapters/assistant/schema", headers=_AUTH)

    assert resp.status_code == 200, resp.text
    assert resp.json()["source_type"] == "llm", resp.text


def test_the_schema_route_still_answers_for_a_source_with_no_address(tmp_path: Path) -> None:
    """Control. A ``static`` source has nothing to dial and must not be refused."""
    with TestClient(create_app(_config(tmp_path, _closed_port()))) as client:
        warm = client.post(
            "/v1/request",
            headers=_AUTH,
            json={"agent_id": _AGENT, "intent": "list the orders"},
        )
        assert warm.status_code == 200, warm.text
        resp = client.get("/v1/adapters/orders/schema", headers=_AUTH)

    assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# 3. "Lose the audit log and nothing else breaks" — true of the file, false of
#    the directory, and the table has to say which.
# ---------------------------------------------------------------------------


def test_losing_the_audit_file_alone_breaks_nothing_else(tmp_path: Path) -> None:
    """Control, and the half of the durability row that is true."""
    with TestClient(create_app(_config(tmp_path, _closed_port()))) as client:
        audit = tmp_path / "auditdir" / "audit.jsonl"
        client.post(
            "/v1/request",
            headers=_AUTH,
            json={"agent_id": _AGENT, "intent": "list the orders"},
        )
        assert audit.exists()
        audit.unlink()

        assert client.get("/readyz").status_code == 200
        served = client.post(
            "/v1/request",
            headers=_AUTH,
            json={"agent_id": _AGENT, "intent": "list the orders"},
        )
        assert served.status_code == 200, served.text
        assert audit.exists(), "the sink did not start a new file"


def test_losing_the_audit_directory_drains_the_broker(tmp_path: Path) -> None:
    """Control, and the half that is false. Fail-closed is correct — silently
    re-creating the directory would write the compliance trail to whatever is
    behind a mount that failed to attach."""
    with TestClient(create_app(_config(tmp_path, _closed_port()))) as client:
        shutil.rmtree(tmp_path / "auditdir")

        ready = client.get("/readyz")
        assert ready.status_code == 503, ready.text
        assert ready.json()["reason"] == (
            f"audit log directory {tmp_path / 'auditdir'} does not exist"
        )
        served = client.post(
            "/v1/request",
            headers=_AUTH,
            json={"agent_id": _AGENT, "intent": "list the orders"},
        )
        assert served.status_code == 503, served.text


def test_the_durability_table_says_the_directory_is_not_optional() -> None:
    """The (c) pin, on the document. The row said "Nothing else breaks"."""
    guide = Path("docs/how-to/operator-guide.md").read_text(encoding="utf-8")
    row = next(
        (line for line in guide.splitlines() if line.startswith("| Decision record |")),
        None,
    )
    assert row is not None, "the durability table has no Decision record row"
    assert "directory" in row.lower(), (
        f"the row claims losing the audit log breaks nothing else, and removing "
        f"its parent directory takes /readyz and every POST /v1/request to 503: {row}"
    )


def test_the_readyz_reference_says_it_does_not_probe_sources() -> None:
    """The gap, on the document: readiness must state what it excludes."""
    page = Path("docs/reference/rest-api.md").read_text(encoding="utf-8")
    section = page.split("### `GET /readyz`", 1)[1].split("### `GET /metrics`", 1)[0]
    assert "source" in section.lower(), (
        "the /readyz reference never mentions sources, so an operator cannot "
        "learn that a broker with every backend down still answers 200"
    )
    assert "probe=true" in section, (
        "the /readyz reference does not name the surface that does answer for a dead source"
    )
