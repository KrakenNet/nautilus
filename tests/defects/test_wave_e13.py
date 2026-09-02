# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false, reportPrivateUsage=false
"""WAVE E13 — the majors the same live-fire re-run found, all reproduced first.

1. **Any credential can poison another caller's session ledger.** A session id
   is an unowned string. Pour PII exposure into ``session_id: "shared"`` with
   one credential and a different, clean credential naming that id is denied
   every source by cumulative escalation — while the identical request in its
   own session succeeds. §4.15 closed the *reset* (a caller cannot wipe its own
   history); the per-session record is still cross-principal write-shared.

   A session legitimately spans agents: a handoff is keyed on
   ``(session_id, source_agent, receiving_agent)``. So the rule is ownership
   with a declared-partner exception, not exclusion — the first principal to
   touch a session owns it, and another principal joins only where a handoff to
   its agent was declared and allowed in that session.

2. **A rejected session token is a 500.** Every body-context rejection — agent
   mismatch, tamper, stripped signature, ``alg=none``, unknown kid, a token from
   a foreign key ring — fails closed and answers a bare
   ``500 Internal Server Error`` with an uncaught ``SessionTokenError``. The
   header path answers 401 correctly, so the status depends on which field
   carried the token.

3. **An audit write that fails mid-request is a 500.** ``chmod 000`` the audit
   log and the next request answers plain-text ``Internal Server Error`` after
   the source was queried and the ledger charged. ``FileSink.write`` reopens the
   file per write, so the ``PermissionError`` escapes ``_emit_attestation`` with
   nothing catching it. Failing closed is right; a 500 with no structured body
   is not — the caller cannot tell "your request was bad" from "our recorder is
   down, retry".

4. **The 503 for a busy exposure ledger names a cause it never checked.** One
   request, zero concurrency, a frozen store: ``Broker busy: waited 30.0s ...
   and another request from the same caller still holds it``. No such request
   existed. The wait covers the store round trip as well as the in-process
   lock, and the message asserts only one of the two.

5. **The schema-version gate is boot-only.** Wave E11 checks the version in
   ``setup()``. Hold a v1 replica up, move the store to v2, and it keeps reading
   and read-modify-writing the shared rows with no error — which is precisely
   the rolling-upgrade window the gate's own comment says it covers.

6/7. **The deploy quickstart still does not run.** ``examples/quickstart``
   promises ``/v1/sources`` needs no auth while its own config sets
   ``api.keys``, and pipes a JSONL audit log through ``python3 -m json.tool``,
   which dies on the second record.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_KEY_A = "e13-key-a"
_KEY_B = "e13-key-b"
_PII_SOURCE: dict[str, Any] = {
    "id": "people",
    "type": "static",
    "classification": "unclassified",
    "data_types": ["people"],
    "rows": [{"id": 1, "name": "ada"}],
}
_PLAIN_SOURCE: dict[str, Any] = {
    "id": "orders",
    "type": "static",
    "classification": "unclassified",
    "data_types": ["orders"],
    "rows": [{"id": 1, "region": "us-east"}],
}


def _write_config(path: Path, **overrides: Any) -> str:
    document: dict[str, Any] = {
        "sources": [_PLAIN_SOURCE, _PII_SOURCE],
        "agents": {
            "a1": {"id": "a1", "clearance": "unclassified"},
            "a2": {"id": "a2", "clearance": "unclassified"},
        },
    }
    document.update(overrides)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# 1. A session belongs to somebody.
# ---------------------------------------------------------------------------


def _ledger_config(tmp_path: Path) -> str:
    return _write_config(
        tmp_path / "nautilus.yaml",
        audit={"path": str(tmp_path / "audit.jsonl")},
        api={
            "keys": [
                {"key": _KEY_A, "agent_id": "a1", "capabilities": ["query"]},
                {"key": _KEY_B, "agent_id": "a2", "capabilities": ["query"]},
            ]
        },
    )


async def _ask(broker: Any, agent: str, key: str, session: str, intent: str) -> Any:
    """One request as the credential ``key``, exactly as the transport calls it."""
    return await broker.arequest(
        agent,
        intent,
        {"purpose": "analytics", "session_id": session},
        caller={"auth": f"api_key:{key}", "peer": None},
    )


@pytest.mark.asyncio
async def test_e13_a_stranger_cannot_write_another_callers_session(tmp_path: Path) -> None:
    """A session id is a name, not a capability.

    Cumulative exposure is a policy input: what the ledger says decides what the
    rules do. If any credential can add to any session's ledger by naming it,
    then any credential can drive any other caller's escalation — a denial of
    service against a competitor on the same broker, and a side channel that
    reports back through which rules fire.
    """
    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(_ledger_config(tmp_path))
    await broker.setup()
    try:
        mine = await _ask(broker, "a1", _KEY_A, "shared-session", "list people")
        assert mine.outcome in {"allowed", "denied", "skipped"}, mine.outcome

        with pytest.raises(Exception, match="(?i)session|principal|owner"):
            await _ask(broker, "a2", _KEY_B, "shared-session", "list recent orders")
    finally:
        await broker.aclose()


@pytest.mark.asyncio
async def test_e13_the_owner_keeps_using_its_own_session(tmp_path: Path) -> None:
    """Control: ownership must not lock the owner out of its own session."""
    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(_ledger_config(tmp_path))
    await broker.setup()
    try:
        first = await _ask(broker, "a1", _KEY_A, "mine", "list people")
        second = await _ask(broker, "a1", _KEY_A, "mine", "list recent orders")
    finally:
        await broker.aclose()
    assert first.outcome != "errored" and second.outcome != "errored"


@pytest.mark.asyncio
async def test_e13_a_declared_handoff_partner_may_join(tmp_path: Path) -> None:
    """Control: the feature ownership must not break.

    A handoff is keyed on ``(session_id, source_agent, receiving_agent)``, so a
    session spanning two agents — and therefore two credentials — is the
    supported shape. The receiving side has to be able to continue it, and to
    inherit what the session has already been exposed to; that inheritance is
    the whole point of tracking exposure per session.
    """
    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(_ledger_config(tmp_path))
    await broker.setup()
    try:
        await _ask(broker, "a1", _KEY_A, "handoff-session", "list people")
        decision = await broker.declare_handoff(
            source_agent_id="a1",
            receiving_agent_id="a2",
            session_id="handoff-session",
            data_classifications=["unclassified"],
        )
        assert decision.action == "allow", f"the handoff itself was refused: {decision}"

        joined = await _ask(broker, "a2", _KEY_B, "handoff-session", "list recent orders")
    finally:
        await broker.aclose()

    assert joined.outcome != "errored", (
        f"the declared handoff recipient was refused its own session: "
        f"{[ (e.error_type, e.message) for e in joined.errored ]}"
    )


@pytest.mark.asyncio
async def test_e13_an_in_library_caller_is_not_gated(tmp_path: Path) -> None:
    """Control: the boundary is between callers, and in-library there is one.

    ``Broker.arequest`` called directly presents no credential and no peer, so
    every agent would look like a separate principal and one process running
    two of its own agents through one session would refuse itself. Ownership is
    enforced where a second caller can exist — the transports, which always
    pass a caller identity.
    """
    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(_ledger_config(tmp_path))
    await broker.setup()
    try:
        first = await broker.arequest("a1", "list people", {"session_id": "lib"})
        second = await broker.arequest("a2", "list recent orders", {"session_id": "lib"})
    finally:
        await broker.aclose()
    assert first.outcome != "errored" and second.outcome != "errored"


# ---------------------------------------------------------------------------
# 2. A rejected token is a 401, whichever field carried it.
# ---------------------------------------------------------------------------


def _token_config(tmp_path: Path) -> str:
    return _write_config(
        tmp_path / "nautilus.yaml",
        audit={"path": str(tmp_path / "audit.jsonl")},
        session_tokens={"enabled": True, "key_ring_path": str(tmp_path / "ring.json")},
        api={"keys": [_KEY_A]},
    )


async def _client(config: str) -> Any:
    from httpx import ASGITransport, AsyncClient

    from nautilus.core.broker import Broker
    from nautilus.transport.fastapi_app import create_app

    broker = await Broker.afrom_config(config)
    await broker.setup()
    app = create_app(None, existing_broker=broker)
    app.state.broker = broker
    app.state.ready = True
    app.state.api_keys = [_KEY_A]
    app.state.auth_mode = "api_key"
    app.state.key_ring = broker.key_ring
    app.state.broker_instance_id = broker.instance_id
    return broker, AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


@pytest.mark.parametrize(
    ("label", "token"),
    [
        ("garbage", "not-a-token"),
        ("alg-none", "eyJhbGciOiAibm9uZSIsICJraWQiOiAieCJ9.e30."),
        ("stripped-signature", "eyJhbGciOiAiRWREU0EiLCAia2lkIjogIngifQ.e30."),
    ],
)
@pytest.mark.asyncio
async def test_e13_a_bad_body_token_is_401_not_500(
    tmp_path: Path, label: str, token: str
) -> None:
    """Fail-closed is right; calling it a server error is not.

    The header path already answers 401. A caller that puts the same token in
    ``context`` gets a 500, so the status code reports where the field was
    rather than what was wrong, and every rejected credential looks to a
    monitoring stack like a Nautilus fault.
    """
    broker, client = await _client(_token_config(tmp_path))
    try:
        via_body = await client.post(
            "/v1/request",
            headers={"X-API-Key": _KEY_A},
            json={
                "agent_id": "a1",
                "intent": "list recent orders",
                "context": {"purpose": "analytics", "session_token": token},
            },
        )
        via_header = await client.post(
            "/v1/request",
            headers={"X-API-Key": _KEY_A, "X-Nautilus-Session-Token": token},
            json={
                "agent_id": "a1",
                "intent": "list recent orders",
                "context": {"purpose": "analytics"},
            },
        )
    finally:
        await client.aclose()
        await broker.aclose()

    assert via_header.status_code == 401, (
        f"the control path stopped answering 401 to a {label} token: "
        f"{via_header.status_code}"
    )
    assert via_body.status_code == 401, (
        f"a {label} session token in the request body answered "
        f"{via_body.status_code}, where the same token in the header answers "
        f"401. Body: {via_body.text[:200]}"
    )


@pytest.mark.asyncio
async def test_e13_a_good_token_still_serves(tmp_path: Path) -> None:
    """Control: refusing bad tokens must not refuse good ones."""
    broker, client = await _client(_token_config(tmp_path))
    try:
        minted = await client.post(
            "/v1/request",
            headers={"X-API-Key": _KEY_A},
            json={
                "agent_id": "a1",
                "intent": "list recent orders",
                "context": {"purpose": "analytics", "session_id": "s1"},
            },
        )
        assert minted.status_code == 200, minted.text
        token = minted.json()["session_token"]
        assert token, "no token to re-present"

        again = await client.post(
            "/v1/request",
            headers={"X-API-Key": _KEY_A},
            json={
                "agent_id": "a1",
                "intent": "list recent orders",
                "context": {
                    "purpose": "analytics",
                    "session_id": "s1",
                    "session_token": token,
                },
            },
        )
    finally:
        await client.aclose()
        await broker.aclose()
    assert again.status_code == 200, again.text


# ---------------------------------------------------------------------------
# 3. A recorder that has stopped recording is a 503.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e13_an_unwritable_audit_log_is_503_not_500(tmp_path: Path) -> None:
    """"Our recorder is down, retry" and "your request was bad" are different answers.

    ``FileSink.write`` reopens the file on every write, so a log that becomes
    unwritable mid-request raises ``PermissionError`` out of
    ``_emit_attestation`` with nothing catching it: the caller gets plain-text
    ``Internal Server Error`` — not even the structured error body every other
    failure uses — for a request whose source was already queried and whose
    exposure was already charged. ``/readyz`` sees it correctly in under 2ms;
    the request path does not see it at all.
    """
    audit_path = tmp_path / "audit.jsonl"
    config = _write_config(
        tmp_path / "nautilus.yaml",
        audit={"path": str(audit_path)},
        api={"keys": [_KEY_A]},
    )
    broker, client = await _client(config)
    body: dict[str, Any] = {
        "agent_id": "a1",
        "intent": "list recent orders",
        "context": {"purpose": "analytics", "session_id": "u1"},
    }
    try:
        healthy = await client.post("/v1/request", headers={"X-API-Key": _KEY_A}, json=body)
        assert healthy.status_code == 200, healthy.text

        audit_path.chmod(0o000)
        try:
            broken = await client.post(
                "/v1/request", headers={"X-API-Key": _KEY_A}, json=body
            )
        finally:
            audit_path.chmod(0o644)
    finally:
        await client.aclose()
        await broker.aclose()

    assert broken.status_code == 503, (
        f"an unwritable audit log answered {broken.status_code} "
        f"{broken.text[:200]!r}. A request that cannot be recorded must fail "
        f"closed as a service problem the caller can retry, not as a 500."
    )
    assert "retry-after" in {k.lower() for k in broken.headers}, (
        "the 503 carries no Retry-After, so a client has nothing to act on"
    )


# ---------------------------------------------------------------------------
# 4. The busy message says what was actually observed.
# ---------------------------------------------------------------------------


def test_e13_the_busy_message_does_not_invent_a_second_caller() -> None:
    """A timeout is evidence of a wait, not evidence of who was holding it.

    The budget covers the in-process lock *and* the store round trip that takes
    the shared advisory lock. A single request against a frozen store times out
    with the message blaming a concurrent request from the same caller, which
    sends an operator to look for load that is not there.
    """
    from nautilus.core.broker import _busy_message

    message = _busy_message("session-1, principal:abc", 30.0, None)
    assert "another request from the same caller still holds it" not in message, (
        f"the busy message asserts a cause it never checked:\n{message}"
    )
    for expected in ("30.0", "session-1"):
        assert expected in message, f"the message dropped {expected!r}:\n{message}"
    assert "store" in message.lower() or "unreachable" in message.lower(), (
        f"the message names only contention, and the other cause — a store that "
        f"is slow or not answering — is the one a single uncontended request "
        f"hits:\n{message}"
    )


# ---------------------------------------------------------------------------
# 5. The version gate is checked while running, not only at boot.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e13_a_running_replica_rechecks_the_schema_version(tmp_path: Path) -> None:
    """The gate exists for the rollout window, so it has to run during one.

    Replicas roll one at a time. Checking only in ``setup()`` catches the new
    build starting and misses the old build still serving: it kept reading and
    read-modify-writing the shared rows after the store was stamped for a schema
    it does not understand.
    """
    from nautilus.core import session_sqlite
    from nautilus.core.session_sqlite import SqliteSessionStore

    path = tmp_path / "sessions.db"
    store = SqliteSessionStore(str(path))
    await store.setup()
    try:
        await store.aupdate("s1", {"sources_visited": ["orders"]})
        assert (await store.aget("s1"))["sources_visited"] == ["orders"]

        # The store moves under a replica that is already up — what a rolling
        # upgrade does to every pod that has not been replaced yet.
        import sqlite3

        conn = sqlite3.connect(path)
        conn.execute(f"PRAGMA user_version = {session_sqlite._SCHEMA_VERSION + 1}")
        conn.commit()
        conn.close()

        verify: Any = getattr(store, "averify_schema", None)
        assert callable(verify), (
            "the session store has no averify_schema(): the version stamp is "
            "read once in setup() and never again, so a replica that is already "
            "up never notices the store move under it"
        )
        with pytest.raises(Exception, match="(?i)schema|version"):
            checked: Any = verify()
            await checked
    finally:
        await store.aclose()


@pytest.mark.asyncio
async def test_e13_the_recheck_passes_on_a_matching_store(tmp_path: Path) -> None:
    """Control: the recheck must not fail a store that is exactly right."""
    from nautilus.core.session_sqlite import SqliteSessionStore

    store = SqliteSessionStore(str(tmp_path / "sessions.db"))
    await store.setup()
    try:
        await store.averify_schema()
    finally:
        await store.aclose()


# ---------------------------------------------------------------------------
# 6/7. The quickstart is a thing you can paste.
# ---------------------------------------------------------------------------


def _quickstart_readme() -> str:
    return (_REPO_ROOT / "examples" / "quickstart" / "README.md").read_text(encoding="utf-8")


def test_e13_the_quickstart_does_not_promise_auth_it_requires() -> None:
    """The shipped config sets ``api.keys``, so nothing there is auth-free.

    Reproduced against a running broker with the rest of the quickstart
    working: the sources curl returns 401 while the POST two blocks later
    returns 200 with real rows.
    """
    readme = _quickstart_readme()
    config: dict[str, Any] = yaml.safe_load(
        (_REPO_ROOT / "examples" / "quickstart" / "nautilus.yaml").read_text(encoding="utf-8")
    )
    keys = ((config.get("api") or {}).get("keys")) or []
    assert keys, "the quickstart config no longer sets api.keys; re-read this pin"
    assert "no auth required" not in readme.lower(), (
        "examples/quickstart/README.md says a route needs no auth while its own "
        "config sets api.keys, so that command answers 401"
    )
    block = readme.split("/v1/sources")[0].rsplit("```bash", 1)[-1]
    assert "X-API-Key" in block or "X-API-Key" in readme.split("/v1/sources")[1][:200], (
        "the /v1/sources example sends no key, so it cannot work"
    )


def test_e13_the_quickstart_reads_the_audit_log_as_jsonl() -> None:
    """``json.tool`` reads one document; the audit log is one per line.

    It works on a log with a single entry and breaks permanently from the
    second brokered request on: ``Extra data: line 2 column 1``.
    """
    readme = _quickstart_readme()
    for line in readme.splitlines():
        if "json.tool" not in line:
            continue
        assert "--json-lines" in line, (
            f"{line.strip()!r} pipes a JSONL audit log through json.tool, which "
            f"reads a single JSON document and fails on the second record"
        )


def test_e13_the_quickstart_audit_command_matches_the_log_it_reads() -> None:
    """Control: the flag has to be one the stdlib actually has, on real JSONL."""
    import subprocess
    import sys

    sample = "\n".join(json.dumps({"seq": i}) for i in range(3))
    result = subprocess.run(  # noqa: S603 — this interpreter, a literal argv
        [sys.executable, "-m", "json.tool", "--json-lines"],
        input=sample.encode("utf-8"),
        check=False,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
