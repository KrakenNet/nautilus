# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false, reportPrivateImportUsage=false
"""WAVE E11 — the eight minors the structural re-audit left open.

Each one was reproduced first-hand at HEAD before a line of fix was written.
Three of the eight turned out to be already closed by earlier waves; they are
pinned here as regressions rather than dropped, because "already fixed" is a
claim that decays.

1. **The session token claims a purpose nobody enforced.**
   ``Broker._process_session_token`` consumes ``claims.session_id`` and compares
   ``claims.agent_id``. ``claims.purpose`` and ``claims.clearance`` are read by
   nothing. Present a token minted under ``purpose: analytics`` and ask again
   under ``purpose: export``: the request runs as ``export`` and the signed
   artefact handed back — and forwarded downstream in
   ``X-Nautilus-Session-Token`` — still says ``analytics``.

2. **A curated keyword overlay shadows the data type it curates.**
   ``build_keyword_map`` returns ``{**generated, **explicit}``: an explicit
   entry replaces the generated base wholesale. An operator who adds a synonym
   for ``orders`` silently removes the word *orders* from the vocabulary, so an
   intent naming the advertised data type verbatim matches nothing.

3. **Neither session store carries a schema version.** ``CREATE TABLE IF NOT
   EXISTS`` means a future column addition is a silent no-op against an old
   database, and an old binary against a new database reads columns that moved.

4. **``fathom.compiler.Compiler`` is outside fathom's public surface.**
   ``fathom.__all__`` re-exports everything else Nautilus imports;
   ``Compiler``, ``RuleDefinition`` and ``TemplateDefinition`` it does not. The
   dependency is deliberately uncapped, so the guard has to be a test that
   fails on the upgrade rather than a pin that prevents one.

5–7. **Already closed, pinned so they stay closed:** the image CMD binds
   ``0.0.0.0:8000`` (E-earlier), and the published image genuinely carries no
   driver extras (E4 regenerated the lock).

8. **``nautilus serve`` exits 0 when the app fails to start.** uvicorn does not
   raise when the lifespan raises — it logs "Application startup failed" and
   returns — and ``_cmd_serve`` ends in an unconditional ``return 0``. A
   Deployment with a fail-closed session store it cannot reach exits cleanly,
   so the container is Completed, not CrashLoopBackOff, and nothing restarts.

9. **The audit emptyDir is uncapped.** No ``sizeLimit`` and no
   ``ephemeral-storage`` request or limit: the audit log is append-only and
   grows with traffic until it fills the node's disk, which evicts every pod on
   it, not just this one.

10. **The deploy quickstart does not run.** The curl posts a JSON body with no
    ``Content-Type``, and the README tells the operator to run
    ``nautilus key generate``, which is not a command.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SOURCE: dict[str, Any] = {
    "id": "orders",
    "type": "static",
    "classification": "unclassified",
    "data_types": ["orders"],
    "rows": [{"id": 1, "region": "us-east"}],
}
_AGENTS: dict[str, Any] = {"a1": {"id": "a1", "clearance": "unclassified"}}


def _write_config(path: Path, **overrides: Any) -> str:
    document: dict[str, Any] = {"sources": [_SOURCE], "agents": _AGENTS}
    document.update(overrides)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# 1. The token describes the request that actually ran.
# ---------------------------------------------------------------------------


def _token_config(tmp_path: Path) -> str:
    return _write_config(
        tmp_path / "nautilus.yaml",
        session_tokens={"enabled": True, "key_ring_path": str(tmp_path / "ring.json")},
        audit={"path": str(tmp_path / "audit.jsonl")},
    )


@pytest.mark.asyncio
async def test_e11_the_session_token_claims_the_purpose_that_was_enforced(
    tmp_path: Path,
) -> None:
    """A token carried into a new purpose must not keep claiming the old one.

    The token is a bearer credential: adapters forward it downstream in
    ``X-Nautilus-Session-Token``, and a downstream reader has nothing but the
    signature and the claims. If the broker enforces ``export`` while the
    signed artefact says ``analytics``, the signature attests to a request that
    never happened.
    """
    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(_token_config(tmp_path))
    await broker.setup()
    try:
        first = await broker.arequest(
            "a1", "list recent orders", {"purpose": "analytics", "session_id": "s1"}
        )
        assert first.session_token, "no token was minted to test with"

        second = await broker.arequest(
            "a1",
            "list recent orders",
            {"purpose": "export", "session_id": "s1", "session_token": first.session_token},
        )
        assert second.session_token, "the second request handed back no token"

        assert broker._session_tokens is not None  # pyright: ignore[reportPrivateUsage]
        claims = broker._session_tokens.verify(  # pyright: ignore[reportPrivateUsage]
            second.session_token
        )
    finally:
        await broker.aclose()

    assert claims.purpose == "export", (
        f"the request ran under purpose 'export' and the token handed back "
        f"claims purpose {claims.purpose!r}. The purpose claim is written at "
        f"mint time and read by nothing afterwards, so a signed artefact "
        f"describes a request that was never made."
    )


@pytest.mark.asyncio
async def test_e11_an_unchanged_purpose_does_not_remint(tmp_path: Path) -> None:
    """Control: re-minting happens on drift, not on every request.

    Without this, handing back a fresh token unconditionally would also pass —
    and that quietly resets the expiry the original mint set, which is the
    lifetime bound a session token exists to carry.
    """
    from nautilus.core.broker import Broker

    broker = await Broker.afrom_config(_token_config(tmp_path))
    await broker.setup()
    try:
        first = await broker.arequest(
            "a1", "list recent orders", {"purpose": "analytics", "session_id": "s1"}
        )
        second = await broker.arequest(
            "a1",
            "list recent orders",
            {"purpose": "analytics", "session_id": "s1", "session_token": first.session_token},
        )
    finally:
        await broker.aclose()

    assert second.session_token == first.session_token, (
        "a request whose purpose matched the token's claim was handed a "
        "different token; re-minting on every request resets the session's "
        "expiry bound"
    )


# ---------------------------------------------------------------------------
# 2. A curated overlay adds vocabulary; it does not remove any.
# ---------------------------------------------------------------------------


def test_e11_an_advertised_data_type_matches_its_own_name() -> None:
    """Adding a synonym for ``orders`` must not delete the word *orders*.

    Every source advertises its ``data_types``, ``/v1/sources`` publishes them,
    and the docs tell an agent to name what it needs. An operator curating a
    synonym list has no reason to expect that doing so makes the advertised
    name itself unmatchable.
    """
    from nautilus.analysis.pattern_matching import PatternMatchingIntentAnalyzer, build_keyword_map
    from nautilus.config.models import SourceConfig

    source = SourceConfig.model_validate(_SOURCE)
    keyword_map = build_keyword_map([source], {"orders": ["purchase order"]})
    analysis = PatternMatchingIntentAnalyzer(keyword_map).analyze("list recent orders", {})

    assert "orders" in analysis.data_types_needed, (
        f"an intent naming the advertised data type 'orders' verbatim resolved "
        f"to {analysis.data_types_needed!r}. The explicit keyword_map entry "
        f"replaced the generated base rather than adding to it, so curating a "
        f"synonym removed the data type's own name from the vocabulary."
    )


def test_e11_a_curated_keyword_still_matches() -> None:
    """Control: the operator's own synonym must keep working.

    Unioning must not become 'ignore the explicit map'.
    """
    from nautilus.analysis.pattern_matching import PatternMatchingIntentAnalyzer, build_keyword_map
    from nautilus.config.models import SourceConfig

    source = SourceConfig.model_validate(_SOURCE)
    keyword_map = build_keyword_map([source], {"orders": ["purchase order"]})
    analysis = PatternMatchingIntentAnalyzer(keyword_map).analyze("show the purchase order", {})

    assert "orders" in analysis.data_types_needed, (
        "the curated keyword 'purchase order' stopped matching; the explicit "
        "keyword_map is no longer applied"
    )


# ---------------------------------------------------------------------------
# 3. A store knows which schema it is looking at.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e11_sqlite_refuses_a_schema_it_does_not_understand(tmp_path: Path) -> None:
    """A database written by a newer Nautilus must not be read blindly.

    ``CREATE TABLE IF NOT EXISTS`` succeeds against any table of that name.
    Started against a schema it does not know, the store reads columns that may
    have moved and writes rows the newer binary will not understand — silently,
    because nothing on either side ever compares versions.
    """
    from nautilus.core.session_sqlite import SqliteSessionStore

    path = tmp_path / "sessions.db"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 99")
    conn.commit()
    conn.close()

    store = SqliteSessionStore(str(path))
    with pytest.raises(Exception, match="(?i)schema|version"):
        await store.setup()
    await store.aclose()


@pytest.mark.asyncio
async def test_e11_sqlite_stamps_a_fresh_database_and_reopens_it(tmp_path: Path) -> None:
    """Control: the version must be written, and a store must reopen its own.

    A refusal that also refuses the schema the store itself just created is a
    store that cannot start twice.
    """
    from nautilus.core.session_sqlite import SqliteSessionStore

    path = tmp_path / "sessions.db"
    first = SqliteSessionStore(str(path))
    await first.setup()
    await first.aupdate("s1", {"sources_visited": ["orders"]})
    await first.aclose()

    stamped = sqlite3.connect(path).execute("PRAGMA user_version").fetchone()[0]
    assert stamped > 0, "setup() left the schema version at 0; nothing was stamped"

    second = SqliteSessionStore(str(path))
    await second.setup()
    try:
        assert (await second.aget("s1"))["sources_visited"] == ["orders"]
    finally:
        await second.aclose()


@pytest.mark.docker
@pytest.mark.asyncio
async def test_e11_postgres_refuses_a_schema_it_does_not_understand(pg_container: str) -> None:
    """The shared store is where a version mismatch actually bites.

    Replicas roll one at a time. Old and new binaries share one database for
    the length of a rollout, which is exactly when an unversioned schema lets
    two different readers disagree about what a row means.
    """
    import asyncpg  # pyright: ignore[reportMissingTypeStubs]

    from nautilus.core.session_pg import PostgresSessionStore

    seed = PostgresSessionStore(pg_container)
    await seed.setup()
    await seed.aclose()

    conn: Any = await asyncpg.connect(dsn=pg_container)  # pyright: ignore[reportUnknownMemberType]
    try:
        await conn.execute("UPDATE nautilus_schema_version SET version = 99")
        store = PostgresSessionStore(pg_container)
        with pytest.raises(Exception, match="(?i)schema|version"):
            await store.setup()
        await store.aclose()
    finally:
        # The container is shared with every other docker-lane test; leaving a
        # version this build refuses would fail all of them, not just this one.
        await conn.execute("UPDATE nautilus_schema_version SET version = 1")
        await conn.close()


# ---------------------------------------------------------------------------
# 4. The private fathom surface Nautilus depends on.
# ---------------------------------------------------------------------------


def test_e11_the_private_fathom_surface_is_still_there() -> None:
    """``fathom-rules`` is uncapped on purpose, so the guard is a test.

    ``fathom.__all__`` re-exports every other name Nautilus imports. The rule
    validator reaches past it into ``fathom.compiler``, which carries no
    compatibility promise: a minor release may move or rename any of this and
    the only symptom would be ``nautilus rule validate`` failing in the field.
    """
    import inspect

    from fathom.compiler import CompilationError, Compiler
    from fathom.models import RuleDefinition, TemplateDefinition

    assert issubclass(CompilationError, Exception)
    for model in (RuleDefinition, TemplateDefinition):
        assert hasattr(model, "model_validate"), f"{model.__name__} is no longer a pydantic model"

    # The three entry points nautilus/rkm/validator/static.py calls, and the
    # parameter names it passes them by position.
    expected = {
        "parse_template_file": ["path"],
        "parse_rule_file": ["path"],
        "compile_rule": ["rule", "module", "templates"],
    }
    for name, params in expected.items():
        method = getattr(Compiler, name, None)
        assert callable(method), (
            f"fathom.compiler.Compiler.{name}() is gone. It is outside fathom's "
            f"public surface and nautilus/rkm/validator/static.py calls it."
        )
        signature = list(inspect.signature(method).parameters)[1:]
        assert len(signature) >= len(params), (
            f"Compiler.{name}{tuple(signature)} no longer takes the "
            f"{len(params)} arguments static.py passes it"
        )


# ---------------------------------------------------------------------------
# 5–7. Closed by earlier waves; pinned so they stay closed.
# ---------------------------------------------------------------------------


def test_e11_every_shipped_command_binds_a_parseable_address() -> None:
    """``--bind 0.0.0.0`` is rejected by the parser, so a CMD must carry a port."""
    from nautilus.cli.serve import _split_bind  # pyright: ignore[reportPrivateUsage]

    text = (_REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    binds = [
        line.split('"--bind", "')[1].split('"')[0]
        for line in text.splitlines()
        if '"--bind", "' in line
    ]
    assert binds, "no Dockerfile CMD passes --bind; the image serves on loopback"
    for bind in binds:
        host, port = _split_bind(bind)
        assert host == "0.0.0.0" and port > 0, f"{bind!r} does not listen outside the container"  # noqa: S104


def test_e11_the_image_carries_no_driver_extras() -> None:
    """deployment.yaml tells operators to add the extras their sources need.

    That comment is only true while the image build installs none of them.
    """
    text = (_REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    installed: set[str] = set()
    for line in text.splitlines():
        if not line.startswith("RUN uv sync"):
            continue
        words = line.split()
        installed |= {
            words[index + 1] for index, word in enumerate(words[:-1]) if word == "--extra"
        }
    drivers = {"postgres", "pgvector", "elasticsearch", "neo4j", "influxdb", "s3"}
    assert not (installed & drivers), (
        f"the image installs driver extras {sorted(installed & drivers)}, while "
        f"deploy/deployment.yaml tells operators the image carries none"
    )


# ---------------------------------------------------------------------------
# 8. A pod that cannot start must not exit cleanly.
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _serve(config: str, port: int) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 — this interpreter, a literal argv
        [
            sys.executable,
            "-m",
            "nautilus",
            "serve",
            "--config",
            config,
            "--bind",
            f"127.0.0.1:{port}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=str(_REPO_ROOT),
        # ``OTEL_SDK_DISABLED`` is the switch the SDK reads. This said
        # ``NAUTILUS_DISABLE_OTEL``, which nothing anywhere reads, so the
        # subprocess exported exporters it could not reach and the quieting
        # this line exists for never happened.
        env={**os.environ, "OTEL_SDK_DISABLED": "true"},
    )


def test_e11_serve_exits_nonzero_when_the_app_cannot_start(tmp_path: Path) -> None:
    """A fail-closed session store it cannot reach must be a failed start.

    uvicorn does not raise when the lifespan raises: it logs "Application
    startup failed. Exiting." and ``serve()`` returns normally.
    ``_cmd_serve`` then falls through to ``return 0``, so Kubernetes sees
    Completed rather than a crash, and a Deployment whose store is unreachable
    reports healthy while serving nothing.
    """
    config = _write_config(
        tmp_path / "nautilus.yaml",
        audit={"path": str(tmp_path / "audit.jsonl")},
        session_store={
            "backend": "postgres",
            # Port 1 refuses immediately — this is a wiring pin, not a timeout.
            "dsn": "postgresql://nautilus@127.0.0.1:1/nautilus",
            "on_failure": "fail_closed",
        },
    )
    proc = _serve(config, _free_port())
    try:
        output = (proc.communicate(timeout=120)[0] or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        pytest.fail("nautilus serve neither started nor exited within 120s")

    assert proc.returncode != 0, (
        f"nautilus serve exited 0 after failing to start. Output:\n{output[-3000:]}"
    )


def test_e11_serve_exits_zero_on_a_clean_shutdown(tmp_path: Path) -> None:
    """Control: a working config must still exit 0 when it is asked to stop.

    Without this, ``return 2`` unconditionally would also pass, and every
    rolling update would look like a crash.
    """
    config = _write_config(
        tmp_path / "nautilus.yaml",
        audit={"path": str(tmp_path / "audit.jsonl")},
        api={"keys": ["k"]},
    )
    port = _free_port()
    proc = _serve(config, port)
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                output = (proc.stdout.read() if proc.stdout else b"").decode("utf-8", "replace")
                pytest.fail(f"nautilus serve exited before it listened:\n{output[-3000:]}")
            with socket.socket() as probe:
                probe.settimeout(0.5)
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.25)
        else:
            pytest.fail("nautilus serve never listened")

        proc.terminate()
        output = (proc.communicate(timeout=60)[0] or b"").decode("utf-8", "replace")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()

    # uvicorn re-raises the signal it captured once it has shut down cleanly,
    # so a graceful SIGTERM stop surfaces as -SIGTERM, which is the 128+15
    # Kubernetes reads as a normal termination.
    assert proc.returncode in (0, -signal.SIGTERM), (
        f"a healthy broker asked to stop exited {proc.returncode}. Output:\n{output[-3000:]}"
    )


# ---------------------------------------------------------------------------
# 9. The audit volume has a ceiling.
# ---------------------------------------------------------------------------


def _deployment() -> dict[str, Any]:
    text = (_REPO_ROOT / "deploy" / "deployment.yaml").read_text(encoding="utf-8")
    for document in yaml.safe_load_all(text):
        if isinstance(document, dict) and document.get("kind") == "Deployment":
            return dict(document)
    pytest.fail("deploy/deployment.yaml declares no Deployment")


def test_e11_the_audit_volume_cannot_fill_the_node(tmp_path: Path) -> None:
    """An uncapped emptyDir evicts every pod on the node, not just this one.

    The audit log is append-only by design and grows with traffic. Without a
    ``sizeLimit`` and an ``ephemeral-storage`` request the kubelet has no
    signal until the disk-pressure threshold trips, and disk pressure is a node
    condition: the eviction manager takes down neighbours too.
    """
    spec = _deployment()["spec"]["template"]["spec"]
    volumes = {v["name"]: v for v in spec["volumes"]}
    audit = volumes.get("audit")
    assert audit is not None, "the audit volume is gone"
    assert (audit.get("emptyDir") or {}).get("sizeLimit"), (
        "the audit emptyDir has no sizeLimit; an append-only log grows until it "
        "fills the node and the kubelet evicts every pod on it"
    )

    resources = spec["containers"][0]["resources"]
    assert "ephemeral-storage" in resources.get("requests", {}), (
        "no ephemeral-storage request; the scheduler places this pod on a node "
        "with no regard for the disk its audit log will use"
    )
    assert "ephemeral-storage" in resources.get("limits", {}), (
        "no ephemeral-storage limit; the pod is not evicted before the node is"
    )


def test_e11_the_pod_still_declares_cpu_and_memory(tmp_path: Path) -> None:
    """Control: adding ephemeral-storage must not displace what was there."""
    resources = _deployment()["spec"]["template"]["spec"]["containers"][0]["resources"]
    assert resources["requests"]["cpu"], "the cpu request is gone"
    assert resources["requests"]["memory"] and resources["limits"]["memory"]


# ---------------------------------------------------------------------------
# 10. The quickstart is a thing you can paste.
# ---------------------------------------------------------------------------


def _deploy_readme() -> str:
    return (_REPO_ROOT / "docs" / "how-to" / "deploying.md").read_text(encoding="utf-8")


def _quickstart_curl() -> str:
    """The whole ``curl`` command the README opens with, continuations joined.

    Headers may sit either side of the URL, so the window has to be the
    command, not the text after the path.
    """
    fence = next(
        block
        for block in _deploy_readme().split("```")
        if "/v1/request" in block and "curl" in block
    )
    command = fence.replace("\\\n", " ")
    return next(line for line in command.splitlines() if "curl" in line)


def test_e11_the_quickstart_curl_declares_its_content_type() -> None:
    """``curl -d '{...}'`` sends form-encoded, which FastAPI answers 422 to.

    This is the first command in the deployment guide and the first thing an
    operator runs against a fresh install. It fails.
    """
    assert "content-type" in _quickstart_curl().lower(), (
        "the quickstart curl posts a JSON body with no Content-Type header. "
        "curl defaults to application/x-www-form-urlencoded and /v1/request "
        "answers 422."
    )


def test_e11_the_readme_only_names_commands_that_exist() -> None:
    """``nautilus key generate`` is not a command; the README says to run it."""
    readme = _deploy_readme()
    for token in ("nautilus key generate", "nautilus key create"):
        assert token not in readme, (
            f"the deployment guide tells the operator to run '{token}', which "
            f"nautilus key does not implement"
        )

    # Whatever it does name instead has to work.
    assert "openssl genpkey" in readme or "key generate" in readme, (
        "the README no longer says how to produce the attestation key at all"
    )


def test_e11_the_quickstart_still_authenticates() -> None:
    """Control: adding a header must not drop the one that was already there."""
    assert "X-API-Key" in _quickstart_curl(), "the quickstart curl no longer sends X-API-Key"


def test_e11_the_quickstart_body_is_valid_json() -> None:
    """Control: the body the header now describes has to actually be JSON."""
    payload = _quickstart_curl().split("-d '")[1].split("'")[0]
    parsed: Any = json.loads(payload)
    assert parsed["agent_id"] and parsed["intent"] and parsed["context"]["purpose"]
