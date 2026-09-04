# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false, reportPrivateUsage=false
"""WAVE E12 — the five blockers a live-fire re-run found after eleven fix waves.

Every one was reproduced against a running broker, by running it, before a line
of fix was written. None of them is visible from reading the code alone, which
is why eleven waves of static audit missed all five.

1. **``nautilus init`` writes a config that answers 401 to everything.**
   The template carries no ``api:`` block, ``api.keys`` defaults to empty, and
   empty fails closed. The command then prints ``next steps: nautilus serve``.
   Follow it exactly and ``/healthz`` says 200 while ``/v1/sources`` and
   ``/v1/request`` both say ``{"detail":"Not authenticated"}``. Nothing warns.

2. **``/readyz`` is green while the audit writer lock is held by someone else.**
   Wave E2 made the chained sink take its ``flock`` lazily, at first write, so
   read-only CLI surfaces can still build a Broker while the server runs.
   ``AuditLogger.probe()`` only calls ``os.access(W_OK)``, so a replica pointed
   at a log another process owns passes readiness, joins the load balancer, and
   returns a bare 500 to 100% of requests.

3. **``/readyz`` never answers when the session store is reachable but frozen.**
   ``acquire_timeout_s`` bounds the wait for a *new* pooled connection. The
   sentinel ``aget`` runs on a connection that is already open, and carries no
   query deadline. With the store paused the first probe did not return within
   60 s. Wave E1's "aget fails fast so /readyz answers" holds only once the
   pool is already dead.

4. **A session token asserts a purpose the policy refused.** Wave E11 bound the
   token's ``purpose`` claim to the request — but to the *requested* purpose,
   not the *granted* one. ``fathom_router`` refuses a purpose outside the
   agent's ``allowed_purposes``; the broker's ``_request_grant`` does not know
   that rule exists. So a request denied on every source still hands back a
   validly signed token claiming the refused purpose, and adapters forward it
   downstream in ``X-Nautilus-Session-Token``. ``POST /v1/sessions`` mints one
   outright for any string a caller types.

5. **The admin console's read pages ignore key capabilities.** Wave E3 gated
   ``/admin/api/query`` and only that. A key scoped to ``query`` reads the whole
   audit trail at ``/admin/audit`` and other agents' decision traces at
   ``/admin/decisions/{id}``, while ``/v1/audit`` refuses that same key for
   lacking ``audit_read``. Symmetrically an ``audit_read``-only key reads
   ``/admin/sources`` while ``/v1/sources`` refuses it.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

_KEY = "e12-key"
_SOURCE: dict[str, Any] = {
    "id": "orders",
    "type": "static",
    "classification": "unclassified",
    "data_types": ["orders"],
    "rows": [{"id": 1, "region": "us-east"}],
}


def _write_config(path: Path, **overrides: Any) -> str:
    document: dict[str, Any] = {
        "sources": [_SOURCE],
        "agents": {"a1": {"id": "a1", "clearance": "unclassified"}},
    }
    document.update(overrides)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _nautilus(*argv: str, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 — this interpreter, a literal argv
        [sys.executable, "-m", "nautilus", *argv],
        check=False,
        capture_output=True,
        cwd=str(cwd),
        timeout=120,
    )


class _Server:
    """A real ``nautilus serve`` on a free loopback port."""

    def __init__(self, config: str, cwd: Path) -> None:
        self.port = _free_port()
        self.log = cwd / f"serve-{self.port}.log"
        handle = self.log.open("wb")
        self._handle = handle
        self.proc = subprocess.Popen(  # noqa: S603 — this interpreter, a literal argv
            [
                sys.executable,
                "-m",
                "nautilus",
                "serve",
                "--config",
                config,
                "--bind",
                f"127.0.0.1:{self.port}",
            ],
            stdout=handle,
            stderr=subprocess.STDOUT,
            cwd=str(cwd),
            env={**os.environ},
        )

    def wait_for_port(self, timeout: float = 60.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                return False
            with socket.socket() as probe:
                probe.settimeout(0.5)
                if probe.connect_ex(("127.0.0.1", self.port)) == 0:
                    return True
            time.sleep(0.2)
        return False

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        self._handle.close()

    def output(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace")


def _get(url: str, **kwargs: Any) -> Any:
    import httpx

    return httpx.get(url, timeout=30.0, **kwargs)


def _post(url: str, **kwargs: Any) -> Any:
    import httpx

    return httpx.post(url, timeout=30.0, **kwargs)


# ---------------------------------------------------------------------------
# 1. The scaffold the CLI writes is one you can actually query.
# ---------------------------------------------------------------------------


def test_e12_init_then_serve_answers_a_request(tmp_path: Path) -> None:
    """``nautilus init`` then the command it tells you to run next must work.

    This is the whole first-hour path for a stranger: two commands, both
    printed by the tool itself. It ended in 401 on every route that does
    anything, with nothing on stdout or in the log to say why — ``api.keys``
    defaults to empty and empty fails closed, which is the right default and
    the wrong scaffold.
    """
    written = _nautilus("init", cwd=tmp_path)
    assert written.returncode == 0, written.stderr.decode("utf-8", "replace")
    config = tmp_path / "nautilus.yaml"

    document: dict[str, Any] = yaml.safe_load(config.read_text(encoding="utf-8"))
    keys = ((document.get("api") or {}).get("keys")) or []
    assert keys, (
        "nautilus init wrote a config with no api.keys. Empty fails closed, so "
        "the very next command it prints serves 401 on /v1/sources and "
        "/v1/request while /healthz says 200."
    )

    key = keys[0] if isinstance(keys[0], str) else keys[0]["key"]
    agent_id = next(iter(document["agents"]))
    server = _Server(str(config), tmp_path)
    try:
        assert server.wait_for_port(), f"serve never listened:\n{server.output()[-3000:]}"
        listing = _get(server.url("/v1/sources"), headers={"X-API-Key": key})
        answer = _post(
            server.url("/v1/request"),
            headers={"X-API-Key": key, "Content-Type": "application/json"},
            json={
                "agent_id": agent_id,
                "intent": "recent orders",
                "context": {"purpose": "support"},
            },
        )
    finally:
        server.close()

    assert listing.status_code == 200, f"GET /v1/sources → {listing.status_code}: {listing.text}"
    assert answer.status_code == 200, f"POST /v1/request → {answer.status_code}: {answer.text}"


def test_e12_an_empty_key_list_is_warned_about(tmp_path: Path) -> None:
    """Control: a hand-written config with no keys must say so at startup.

    Fixing the scaffold alone would leave every other empty-``api.keys``
    config with the same silent 401, and the scaffold is not the only way
    people write one.
    """
    config = _write_config(tmp_path / "nautilus.yaml", audit={"path": str(tmp_path / "a.jsonl")})
    server = _Server(config, tmp_path)
    try:
        assert server.wait_for_port(), f"serve never listened:\n{server.output()[-3000:]}"
        probe = _get(server.url("/v1/sources"))
        assert probe.status_code == 401, "the empty-key default stopped failing closed"
    finally:
        server.close()

    log = server.output().lower()
    assert "api.keys" in log and ("401" in log or "no api key" in log or "empty" in log), (
        f"a config with no api.keys started silently. Every data route answers "
        f"401 and nothing says why. Log:\n{server.output()[-3000:]}"
    )


# ---------------------------------------------------------------------------
# 2. Readiness tells the truth about the audit sink.
# ---------------------------------------------------------------------------


def _signing_key(tmp_path: Path) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pem = tmp_path / "att.pem"
    pem.write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return str(pem)


def test_e12_a_replica_that_cannot_own_the_audit_log_is_not_ready(tmp_path: Path) -> None:
    """A chained log admits one writer, so the second replica must fail readiness.

    Wave E2 moved the ``flock`` to first write on purpose — read-only CLI
    surfaces have to build a Broker while the server runs. That left the probe
    checking file permissions only, so the second replica passes readiness,
    Kubernetes puts it in the Service, and every request it is handed returns a
    bare 500 naming nothing.
    """
    overrides: dict[str, Any] = {
        "attestation": {"enabled": True, "private_key_path": _signing_key(tmp_path)},
        "audit": {"path": str(tmp_path / "audit.jsonl"), "chained": True},
        "api": {"keys": [_KEY]},
    }
    config = _write_config(tmp_path / "nautilus.yaml", **overrides)

    first = _Server(config, tmp_path)
    second: _Server | None = None
    try:
        assert first.wait_for_port(), f"replica A never listened:\n{first.output()[-3000:]}"
        served = _post(
            first.url("/v1/request"),
            headers={"X-API-Key": _KEY, "Content-Type": "application/json"},
            json={"agent_id": "a1", "intent": "orders", "context": {"purpose": "x"}},
        )
        assert served.status_code == 200, served.text

        second = _Server(config, tmp_path)
        if not second.wait_for_port():
            # Refusing to start at all is a correct answer too — better than
            # serving 500s. Nothing more to assert.
            assert second.proc.returncode not in (0, None), (
                f"replica B exited 0 without listening:\n{second.output()[-3000:]}"
            )
            return
        ready = _get(second.url("/readyz"))
        alive = _get(first.url("/readyz"))
    finally:
        if second is not None:
            second.close()
        first.close()

    assert alive.status_code == 200, (
        f"replica A, which owns the log, stopped being ready: {alive.text}. "
        f"The fix must take the second writer out of rotation, not the first."
    )
    assert ready.status_code == 503, (
        f"replica B answered /readyz {ready.status_code} {ready.text!r} while "
        f"another process holds the chained log's writer lock. It joins the "
        f"Service and 500s every request it is given."
    )


# ---------------------------------------------------------------------------
# 3. Readiness answers, whatever the store is doing.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e12_readyz_answers_when_the_session_store_is_frozen(tmp_path: Path) -> None:
    """A store that accepts the connection and never replies must not wedge the probe.

    The probe is what takes a pod out of rotation. A store that is *down*
    answers fast (E1 pinned that); a store that is reachable but frozen — a
    paused container, a saturated primary, a network black hole — leaves the
    sentinel ``aget`` on an already-open connection with no deadline, and the
    probe never returns at all.

    The stand-in below freezes the store, not the endpoint: the bound under
    test is the one ``/readyz`` is supposed to impose on any backend.
    """
    from httpx import ASGITransport, AsyncClient

    from nautilus.core.broker import Broker
    from nautilus.transport.fastapi_app import create_app

    config = _write_config(
        tmp_path / "nautilus.yaml",
        audit={"path": str(tmp_path / "audit.jsonl")},
        api={"keys": [_KEY]},
    )
    broker = await Broker.afrom_config(config)
    await broker.setup()

    class _FrozenStore:
        """Connects, accepts the query, and never answers."""

        async def aget(self, _key: str) -> dict[str, Any]:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    broker._session_store = _FrozenStore()  # type: ignore[assignment]
    app = create_app(None, existing_broker=broker)
    app.state.broker = broker
    app.state.ready = True
    app.state.api_keys = [_KEY]
    app.state.auth_mode = "api_key"

    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://t")
    try:
        response = await asyncio.wait_for(client.get("/readyz"), timeout=30.0)
    except TimeoutError:
        pytest.fail(
            "/readyz did not answer within 30s against a store that accepts the "
            "query and never replies. The kubelet gives up, the pod is never "
            "drained, and every probe leaves another wedged handler behind."
        )
    finally:
        await client.aclose()
        await broker.aclose()

    assert response.status_code == 503, (
        f"/readyz answered {response.status_code} {response.text!r} while the "
        f"session store was not answering at all"
    )


@pytest.mark.asyncio
async def test_e12_readyz_is_still_green_on_a_healthy_store(tmp_path: Path) -> None:
    """Control: bounding the probe must not make a working store read as broken."""
    from httpx import ASGITransport, AsyncClient

    from nautilus.core.broker import Broker
    from nautilus.transport.fastapi_app import create_app

    config = _write_config(
        tmp_path / "nautilus.yaml",
        audit={"path": str(tmp_path / "audit.jsonl")},
        api={"keys": [_KEY]},
    )
    broker = await Broker.afrom_config(config)
    await broker.setup()
    app = create_app(None, existing_broker=broker)
    app.state.broker = broker
    app.state.ready = True
    app.state.api_keys = [_KEY]
    app.state.auth_mode = "api_key"

    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://t")
    try:
        response = await client.get("/readyz")
    finally:
        await client.aclose()
        await broker.aclose()
    assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# 4. A token never claims a purpose the policy refused.
# ---------------------------------------------------------------------------


def _purpose_config(tmp_path: Path) -> str:
    return _write_config(
        tmp_path / "nautilus.yaml",
        agents={
            "bounded": {
                "id": "bounded",
                "clearance": "unclassified",
                "allowed_purposes": ["analytics"],
            }
        },
        session_tokens={"enabled": True, "key_ring_path": str(tmp_path / "ring.json")},
        audit={"path": str(tmp_path / "audit.jsonl")},
        api={"keys": [_KEY]},
    )


@pytest.mark.asyncio
async def test_e12_no_token_claims_a_purpose_the_agent_may_not(tmp_path: Path) -> None:
    """The signature must not attest to an authorization the broker refused.

    ``fathom_router`` denies every source when the requested purpose is outside
    the agent's ``allowed_purposes``. The broker mints the session token from
    the purpose the caller *typed*, so the same 200 response carries a validly
    signed artefact asserting exactly the purpose the policy just refused —
    and adapters forward it downstream, where the only thing a reader has is
    the signature and the claims.
    """
    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(_purpose_config(tmp_path))
    await broker.setup()
    try:
        answer = await broker.arequest(
            "bounded", "list recent orders", {"purpose": "export", "session_id": "s1"}
        )
        assert answer.outcome == "denied", (
            f"the purpose rule stopped firing: outcome={answer.outcome}"
        )
        if answer.session_token:
            claims = broker._session_tokens.verify(answer.session_token)  # type: ignore[union-attr]
            assert claims.purpose != "export", (
                f"a request refused for claiming purpose 'export' was handed a "
                f"signed token whose purpose claim is {claims.purpose!r}"
            )
    finally:
        await broker.aclose()


@pytest.mark.asyncio
async def test_e12_a_permitted_purpose_still_mints_a_token(tmp_path: Path) -> None:
    """Control: refusing the wrong purpose must not stop the right one working."""
    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(_purpose_config(tmp_path))
    await broker.setup()
    try:
        answer = await broker.arequest(
            "bounded", "list recent orders", {"purpose": "analytics", "session_id": "s1"}
        )
        assert answer.session_token, "a permitted purpose minted no token"
        claims = broker._session_tokens.verify(answer.session_token)  # type: ignore[union-attr]
        assert claims.purpose == "analytics"
    finally:
        await broker.aclose()


@pytest.mark.asyncio
async def test_e12_the_sessions_route_refuses_an_unclaimable_purpose(tmp_path: Path) -> None:
    """``POST /v1/sessions`` mints on demand, so it needs the same rule.

    Without it the denial path is closed and the direct mint is wide open: a
    caller asks for a token claiming any string it likes and gets one.
    """
    from httpx import ASGITransport, AsyncClient

    from nautilus.core.broker import Broker
    from nautilus.transport.fastapi_app import create_app

    broker = await Broker.afrom_config(_purpose_config(tmp_path))
    await broker.setup()
    app = create_app(None, existing_broker=broker)
    app.state.broker = broker
    app.state.ready = True
    app.state.api_keys = [_KEY]
    app.state.auth_mode = "api_key"
    # ASGITransport does not run the lifespan, which is what normally wires the
    # broker's ring to app.state.
    app.state.key_ring = broker.key_ring
    app.state.broker_instance_id = broker.instance_id

    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://t")
    try:
        refused = await client.post(
            "/v1/sessions",
            headers={"X-API-Key": _KEY},
            json={"agent_id": "bounded", "purpose": "exfiltrate-everything"},
        )
        allowed = await client.post(
            "/v1/sessions",
            headers={"X-API-Key": _KEY},
            json={"agent_id": "bounded", "purpose": "analytics"},
        )
    finally:
        await client.aclose()
        await broker.aclose()

    assert refused.status_code == 403, (
        f"POST /v1/sessions answered {refused.status_code} to a purpose the "
        f"agent may not claim, and the body carries a signed token: "
        f"{refused.text[:300]}"
    )
    assert allowed.status_code in (200, 201), (
        f"the control mint stopped working: {allowed.status_code} {allowed.text[:300]}"
    )


# ---------------------------------------------------------------------------
# 5. The console enforces the capabilities the API enforces.
# ---------------------------------------------------------------------------


def _console_client(tmp_path: Path, *capabilities: str) -> Any:
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    config = _write_config(
        tmp_path / f"nautilus-{'-'.join(capabilities)}.yaml",
        audit={"path": str(tmp_path / "audit.jsonl")},
        api={"keys": [{"key": _KEY, "capabilities": list(capabilities)}]},
        ui={"enabled": True},
    )
    return TestClient(create_app(config))


@pytest.mark.parametrize(
    ("held", "path", "denied_twin"),
    [
        ("query", "/admin/audit", "/v1/audit"),
        ("query", "/admin/decisions", "/v1/audit"),
        ("audit_read", "/admin/sources", "/v1/sources"),
    ],
)
def test_e12_admin_pages_enforce_capabilities(
    tmp_path: Path, held: str, path: str, denied_twin: str
) -> None:
    """A capability the API enforces must not be optional on the console.

    Wave E3 closed ``/admin/api/query`` and nothing else. The read pages reach
    the same audit trail and the same source catalogue, so a key scoped to
    ``query`` reads every decision every other agent ever made, and the route
    that exists to refuse it does so one URL away.
    """
    with _console_client(tmp_path, held) as client:
        api = client.get(denied_twin, headers={"X-API-Key": _KEY})
        assert api.status_code == 403, (
            f"the control route {denied_twin} stopped refusing a {held!r}-only key"
        )
        console = client.get(path, cookies={"nautilus_key": _KEY}, follow_redirects=False)

    assert console.status_code == 403, (
        f"{path} answered {console.status_code} to a key holding only {held!r}, "
        f"while {denied_twin} answers 403 to the same key for the same data"
    )


@pytest.mark.parametrize(
    ("held", "path"),
    [
        ("audit_read", "/admin/audit"),
        ("audit_read", "/admin/decisions"),
        ("query", "/admin/sources"),
        ("query", "/admin/playground"),
    ],
)
def test_e12_admin_pages_still_serve_a_scoped_key(tmp_path: Path, held: str, path: str) -> None:
    """Control: the gate must admit the key that does hold the capability.

    Without this, refusing every console page would also pass.
    """
    with _console_client(tmp_path, held) as client:
        page = client.get(path, cookies={"nautilus_key": _KEY}, follow_redirects=False)
    assert page.status_code == 200, (
        f"{path} answered {page.status_code} to a key holding {held!r}; the gate "
        f"refuses the credential it is supposed to admit"
    )
