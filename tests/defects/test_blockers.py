"""The eight ship blockers from the 1.0 audit, each as one failing assertion.

Every test here reproduces a defect that the 1533-test suite reports as
healthy. They fail today by design. A fix is done when its test is green and
nothing else in the suite went red.

Finding ids match the audit report at ``nautilus-1.0-audit/REPORT.md``.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.defect


# ---------------------------------------------------------------------------
# B1 -- an unknown classification label fails OPEN
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "classification",
    [
        "Confidential",  # capitalisation
        "secret ",  # trailing space
        "top_secret",  # underscore; the hierarchy spells it "top-secret"
        "restricted",  # an org-local label
        "",  # empty
    ],
)
def test_b1_unknown_classification_denies_instead_of_routing(
    classification: str, pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A source whose classification is not on the ladder must not load.

    ``fathom.engine.dominates`` ranks an unknown *object* level -1, i.e. below
    ``unclassified``, so every clearance dominates it and
    ``default-classification-deny`` never fires. Nothing validates the string
    at load, so a typo in the primary access-control field publishes the source
    to every agent.

    Startup is the only place an operator can still see the typo -- denying at
    request time instead would look identical to the policy working -- so the
    contract is a refused config, not a denied request.
    """
    import asyncio

    from nautilus import Broker
    from nautilus.config.loader import ConfigError

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [
                {
                    "id": "patients",
                    "type": "postgres",
                    "description": "patient records",
                    "classification": classification,
                    "data_types": ["patients"],
                    "allowed_purposes": [],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.patients",
                }
            ],
            # the bottom of the ladder
            "agents": {"intern": {"id": "intern", "clearance": "unclassified"}},
        }
    )

    async def _run() -> Any:
        broker = Broker.from_config(config)
        try:
            return await broker.arequest(
                "intern", "patients", {"purpose": "any", "session_id": "s1"}
            )
        finally:
            await broker.aclose()

    with pytest.raises(ConfigError) as caught:
        asyncio.run(_run())
    assert classification.strip() != "" or "classification" in str(caught.value)
    assert "patients" in str(caught.value), (
        f"the config was refused, but the message does not name the offending "
        f"source, so an operator cannot find the typo: {caught.value}"
    )


@pytest.mark.parametrize("label", ["Secret", "ultra-mega-secret", ""])
def test_b1_unknown_handoff_classification_is_denied(label: str, write_config: Any) -> None:
    """``declare_handoff`` must deny a classification the hierarchy rejects.

    Same root cause as the routing half: ``handoff.yaml`` needs
    ``fathom-dominates`` to be TRUE before it can deny, so an unrecognised
    label allows the handoff. The identical call with ``secret`` is denied.
    """
    import asyncio

    from nautilus import Broker

    config = write_config(
        {
            "sources": [],
            "agents": {
                "spy": {"id": "spy", "clearance": "secret"},
                "analyst": {"id": "analyst", "clearance": "unclassified"},
            },
        }
    )

    async def _run(classification: str) -> Any:
        broker = Broker.from_config(config)
        try:
            return await broker.declare_handoff(
                source_agent_id="spy",
                receiving_agent_id="analyst",
                session_id="s1",
                data_classifications=[classification],
            )
        finally:
            await broker.aclose()

    control = asyncio.run(_run("secret"))
    assert control.action == "deny", (
        f"fixture is wrong: a 'secret' handoff to an unclassified agent was "
        f"not denied ({control!r})"
    )

    decision = asyncio.run(_run(label))
    assert decision.action == "deny", (
        f"a handoff carrying the unrecognised classification {label!r} was "
        f"allowed ({decision.action!r}); the same call with 'secret' denies."
    )


# ---------------------------------------------------------------------------
# B2 -- either shipped rule pack kills ordinary requests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pack", "sensitive_type"),
    [("data-routing-nist", "pii"), ("data-routing-hipaa", "phi")],
)
def test_b2_shipped_pack_does_not_break_ordinary_requests(pack: str, sensitive_type: str) -> None:
    """Enabling a shipped compliance pack must not turn a request into an error.

    ``ac-6-least-privilege`` and ``minimum-necessary-phi-scope`` assert a
    ``scope_constraint`` for every confidential-or-above source without
    requiring that the source was routed, so the default-on consistency check
    raises ``scope_without_routing`` for any intent that does not happen to
    overlap every such source.
    """
    from nautilus.config.models import SourceConfig
    from nautilus.core.fathom_router import FathomRouter
    from nautilus.core.models import IntentAnalysis

    sources = [
        SourceConfig(
            id="sensitive",
            type="postgres",
            description="sensitive",
            classification="confidential",
            data_types=[sensitive_type],
            connection="postgresql://unused/db",
            table="t",
        ),
        SourceConfig(
            id="tickets",
            type="postgres",
            description="tickets",
            classification="unclassified",
            data_types=["tickets"],
            connection="postgresql://unused/db",
            table="t",
        ),
    ]
    from nautilus.rules import BUILT_IN_RULES_DIR

    router = FathomRouter(
        built_in_rules_dir=BUILT_IN_RULES_DIR,
        user_rules_dirs=[],
        rule_packs=[pack],
    )
    try:
        intent = IntentAnalysis(
            raw_intent="find tickets",
            data_types_needed=["tickets"],
            entities=[],
            temporal_scope=None,
            estimated_sensitivity="low",
        )
        # An intent naming only the unclassified source must route cleanly.
        result = router.route(
            "analyst",
            {"clearance": "unclassified", "purpose": "support"},
            intent,
            sources,
            {},
        )
    finally:
        router.close()

    routed = {d.source_id for d in result.routing_decisions}
    assert "tickets" in routed, f"pack {pack!r} broke an ordinary request; routed={sorted(routed)}"


# ---------------------------------------------------------------------------
# B3 -- concurrent requests on one session lose cumulative exposure
# ---------------------------------------------------------------------------


def test_b3_concurrent_requests_do_not_lose_session_exposure(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Parallel requests on one session must all be recorded in the ledger.

    ``_route`` snapshots the session before adapter fan-out and
    ``_update_session`` writes the merged list afterwards, with no per-session
    lock across the await. Concurrent requests all merge onto the same stale
    snapshot and the last writer wins, so the cumulative-exposure control --
    the README's headline feature -- is defeated by issuing requests in
    parallel instead of in sequence.
    """
    import asyncio

    from nautilus import Broker

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    sources = [
        {
            "id": f"pii_{kind}",
            "type": "postgres",
            "description": kind,
            "classification": "unclassified",
            "data_types": ["pii", kind],
            "allowed_purposes": [],
            "connection": "${JOURNEY_PG_DSN}",
            "table": "journey.patients",
        }
        for kind in ("ssn", "dob", "phone", "email")
    ]
    config = write_config(
        {
            "sources": sources,
            "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
            "session_store": {"backend": "memory"},
        }
    )

    async def _run() -> set[str]:
        broker = Broker.from_config(config)
        await broker.setup()
        try:
            await asyncio.gather(
                *(
                    broker.arequest("analyst", kind, {"purpose": "p", "session_id": "shared"})
                    for kind in ("ssn", "dob", "phone", "email")
                )
            )
            store: Any = broker.session_store
            state = await store.aget("shared") if hasattr(store, "aget") else store.get("shared")
            return set(state.get("sources_visited", []))
        finally:
            await broker.aclose()

    visited = asyncio.run(_run())
    assert visited == {"pii_ssn", "pii_dob", "pii_phone", "pii_email"}, (
        "four concurrent requests each read a different PII source, but the "
        f"session ledger recorded only {sorted(visited)}. Cumulative exposure "
        "is lost to a read-modify-write race in the broker."
    )


# ---------------------------------------------------------------------------
# B5 -- the Adapter SDK's types are not the broker's types
# ---------------------------------------------------------------------------


def test_b5_sdk_adapter_result_matches_what_the_broker_reads() -> None:
    """An adapter built against the SDK must be able to serve a request.

    ``broker._gather_adapter_results`` reads ``res.error`` and ``res.rows``.
    The SDK's ``AdapterResult`` has neither, so every adapter written the
    documented way raises ``AttributeError`` on its first request -- after
    passing the SDK's own compliance suite.
    """
    from nautilus_adapter_sdk.types import AdapterResult as SdkResult

    from nautilus.core.models import AdapterResult as CoreResult

    core_fields = set(CoreResult.model_fields)
    sdk_fields = set(SdkResult.model_fields)
    missing = {"rows", "error"} - sdk_fields
    assert not missing, (
        f"the SDK's AdapterResult is missing {sorted(missing)}, which "
        f"broker.py reads off every adapter return. SDK has {sorted(sdk_fields)}, "
        f"broker expects {sorted(core_fields)}."
    )


def test_b5_wrong_adapter_return_type_does_not_sink_the_request(
    tmp_path: Path, write_config: Any
) -> None:
    """One adapter returning the wrong type must not take down the response.

    ``docs/concepts/architecture.md`` promises "One adapter failure never sinks
    the response". ``_gather_adapter_results`` guards only for a raised
    exception, so a wrong-typed *return* dereferences ``res.error`` outside any
    try block and kills the whole request, healthy sources included.
    """
    import asyncio

    from nautilus import Broker

    module = tmp_path / "adapters.py"
    module.write_text(_BAD_AND_GOOD_ADAPTERS, encoding="utf-8")
    config = write_config(
        {
            "adapters": [
                {"module_path": str(module), "class": "GoodAdapter", "source_type": "good"},
                {"module_path": str(module), "class": "BadAdapter", "source_type": "bad"},
            ],
            "sources": [
                {
                    "id": "healthy",
                    "type": "good",
                    "description": "healthy source",
                    "classification": "unclassified",
                    "data_types": ["docs"],
                    "allowed_purposes": [],
                    "connection": "memory://",
                },
                {
                    "id": "broken",
                    "type": "bad",
                    "description": "returns a plain dict",
                    "classification": "unclassified",
                    "data_types": ["docs"],
                    "allowed_purposes": [],
                    "connection": "memory://",
                },
            ],
            "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        }
    )

    async def _run() -> Any:
        broker = Broker.from_config(config)
        try:
            return await broker.arequest("analyst", "docs", {"purpose": "p", "session_id": "s1"})
        finally:
            await broker.aclose()

    response = asyncio.run(_run())
    assert response.data.get("healthy"), (
        "one adapter returned a plain dict instead of an AdapterResult and took "
        "the whole request down with it; the healthy co-queried source returned "
        f"nothing. docs/concepts/architecture.md promises the opposite. "
        f"queried={response.sources_queried} errored={response.sources_errored}"
    )


# ---------------------------------------------------------------------------
# B6 -- the documented rule syntax does not compile, and validate says OK
# ---------------------------------------------------------------------------


DOC_RULE = {
    # module/ruleset are required by the loader; the defect under test is the
    # condition shape below, so these must be present or the test fails for
    # the wrong reason.
    "module": "nautilus-routing",
    "ruleset": "doc-example",
    "version": "1.0",
    "rules": [
        {
            "name": "severity-scope",
            "salience": 100,
            "when": [
                {
                    "template": "agent",
                    "conditions": [
                        # exactly as published in docs/how-to/write-a-routing-rule.md
                        {"slot": "clearance", "operator": "eq", "value": "unclassified"}
                    ],
                }
            ],
            "then": {"action": "route", "reason": "unclassified agents get low severity"},
        }
    ],
}


def test_b6_documented_rule_syntax_compiles(tmp_path: Path) -> None:
    """Every rule file published in the how-tos must load into an engine.

    ``fathom.models.ConditionEntry`` forbids extra keys and has exactly
    ``slot``/``expression``/``bind``/``test``. The ``operator:``/``value:``
    form both how-tos published has never compiled on any fathom version, and
    the broker has no try/except around router construction, so following the
    documentation took the broker down at startup.

    The snippets are read out of the docs rather than copied here, so the test
    cannot drift away from what a reader is told to write.
    """
    import re

    import yaml

    from nautilus.core.fathom_router import FathomRouter
    from nautilus.rules import BUILT_IN_RULES_DIR

    docs = sorted(Path("docs/how-to").glob("*.md"))
    assert docs, "no how-to docs found; the test is looking in the wrong place"

    snippets: list[tuple[str, str]] = []
    for doc in docs:
        for block in re.findall(r"```yaml\n(.*?)```", doc.read_text(encoding="utf-8"), re.S):
            parsed = yaml.safe_load(block)
            # A rule *file* is the shape the loader takes: a top-level module
            # plus rules. Config fragments also use a ``rules:`` key and are
            # not rule files.
            if isinstance(parsed, dict) and "module" in parsed and "rules" in parsed:
                snippets.append((f"{doc.name}", block))
    assert snippets, "no rule-file snippets found in docs/how-to; the regex missed them"

    for i, (name, block) in enumerate(snippets):
        rules_dir = tmp_path / f"snippet-{i}"
        rules_dir.mkdir()
        (rules_dir / "rule.yaml").write_text(block, encoding="utf-8")
        try:
            router = FathomRouter(
                built_in_rules_dir=BUILT_IN_RULES_DIR, user_rules_dirs=[rules_dir]
            )
        except Exception as exc:  # noqa: BLE001 -- the failure is the finding
            pytest.fail(f"the rule published in {name} does not compile: {exc}")
        router.close()


def test_b6_validate_rejects_a_rule_the_engine_cannot_load(tmp_path: Path) -> None:
    """``nautilus rules validate`` must not green-light an uncompilable rule.

    ``validate_static`` checks YAML shape, template names and duplicates, and
    never invokes the compiler -- despite a docstring claiming it wraps
    ``Fathom.validate`` and a doc promising it catches "malformed conditions".
    """
    import yaml

    from nautilus.rkm.validator.static import validate_static

    path = tmp_path / "severity-scope.yaml"
    path.write_text(yaml.safe_dump(DOC_RULE), encoding="utf-8")

    report = validate_static(path)
    assert not report.ok, (
        "validate_static reported OK for a rule whose condition keys fathom "
        "rejects; the broker then refuses to start on the same file."
    )


# ---------------------------------------------------------------------------
# B7 -- the forensic worker cannot read the audit log Nautilus writes
# ---------------------------------------------------------------------------


def test_b7_forensic_worker_parses_a_real_broker_audit_log(
    pg_dsn: str,
    write_config: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The worker must process the lines the broker actually emits.

    ``AuditLogger.emit`` writes a fathom ``AuditRecord`` with the Nautilus
    entry nested as a JSON string under ``metadata.nautilus_audit_entry``; the
    worker validates the *outer* line as an ``AuditEntry``, so every line is
    skipped as malformed and the detector reports success having read nothing.
    The repo's other two readers already unwrap correctly.
    """
    import asyncio

    from nautilus import Broker
    from nautilus.forensics.handoff_worker import run_worker
    from nautilus.forensics.sinks import JSONLForensicSink

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    audit_path = tmp_path / "audit.jsonl"
    config = write_config(
        {
            "sources": [
                {
                    "id": "vulns",
                    "type": "postgres",
                    "description": "vulns",
                    "classification": "unclassified",
                    "data_types": ["cve"],
                    "allowed_purposes": [],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.vulns",
                }
            ],
            "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
            "audit": {"path": str(audit_path)},
        }
    )

    async def _run() -> None:
        broker = Broker.from_config(config)
        try:
            for i in range(3):
                await broker.arequest("analyst", "cve", {"purpose": "p", "session_id": f"s{i}"})
        finally:
            await broker.aclose()

    asyncio.run(_run())
    lines = [ln for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert lines, "the broker wrote no audit lines; the fixture is wrong, not the worker"

    async def _worker() -> Any:
        sink = JSONLForensicSink(tmp_path / "inferred.jsonl")
        try:
            return await run_worker(audit_path, tmp_path / "offsets.json", sink)
        finally:
            await sink.close()

    with caplog.at_level(logging.WARNING, logger="nautilus.forensics.handoff_worker"):
        report = asyncio.run(_worker())

    # ``lines_processed`` is incremented *before* the parse attempt, so it is
    # not evidence that anything was understood. The warning is.
    skipped = [r for r in caplog.records if "skipping malformed audit line" in r.message]
    assert not skipped, (
        f"the worker skipped {len(skipped)} of {report.lines_processed} real "
        f"broker audit lines as malformed, then returned success. Top-level "
        f"keys on a real line: {sorted(json.loads(lines[0]))}"
    )


_BAD_AND_GOOD_ADAPTERS = '''
"""Two local adapters: one well-behaved, one returning the wrong type."""

from __future__ import annotations

from typing import Any, ClassVar

from nautilus.core.models import AdapterResult


class GoodAdapter:
    source_type: ClassVar[str] = "good"

    async def connect(self, config: Any) -> None:
        self._config = config

    async def execute(self, *args: Any, **kwargs: Any) -> AdapterResult:
        return AdapterResult(
            source_id="healthy", rows=[{"ok": True}], duration_ms=1, error=None
        )

    async def get_schema(self, *args: Any, **kwargs: Any) -> Any:
        # Raising is the documented opt-out; the broker logs "skipping
        # fingerprint check". (Returning None instead makes the broker raise
        # AttributeError on .fingerprint() -- a separate defect, not this one.)
        raise NotImplementedError("no schema for the fixture adapter")

    async def close(self) -> None:
        return None


class BadAdapter(GoodAdapter):
    """Returns a plain dict, exactly like an adapter built on the SDK's type."""

    source_type: ClassVar[str] = "bad"

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        return {"source_id": "broken", "data": [{"oops": True}], "metadata": {}}
'''


# ---------------------------------------------------------------------------
# B4 -- the MCP HTTP transport has no authentication
# ---------------------------------------------------------------------------


def test_b4_mcp_http_transport_requires_an_api_key(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``nautilus serve --transport mcp --mcp-mode http`` must not serve anonymously.

    ``_run_mcp`` calls ``mcp.run_streamable_http_async()`` on a raw server, so
    the configured ``api.keys`` are read, bound, and discarded. The gate that
    would apply them (``mcp_server.http_app``) is dead code whose only callers
    are tests. ``nautilus_request`` takes ``agent_id`` verbatim by design, so
    the transport is the only identity boundary there is: any caller who can
    reach the port asserts the highest-clearance agent in the config.

    The same config's REST leg 401s the same anonymous caller.
    """
    import socket
    import subprocess
    import time

    import httpx

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [
                {
                    "id": "patients",
                    "type": "postgres",
                    "description": "patient records",
                    "classification": "secret",
                    "data_types": ["patients"],
                    "allowed_purposes": [],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.patients",
                }
            ],
            "agents": {"chief": {"id": "chief", "clearance": "secret"}},
            "api": {"keys": ["the-only-valid-key"]},
        }
    )

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    log = tmp_path / "serve.log"
    with log.open("wb") as sink:
        proc = subprocess.Popen(
            [
                ".venv/bin/nautilus",
                "serve",
                "--config",
                config,
                "--transport",
                "mcp",
                "--mcp-mode",
                "http",
                "--bind",
                f"127.0.0.1:{port}",
            ],
            stdout=sink,
            stderr=subprocess.STDOUT,
            env={**os.environ, "JOURNEY_PG_DSN": pg_dsn},
        )
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                pytest.fail(f"serve exited {proc.returncode}:\n{log.read_text()}")
            with socket.socket() as s:
                s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.5)
        else:
            pytest.fail(f"serve never listened on {port}:\n{log.read_text()}")

        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "anonymous-caller", "version": "0"},
            },
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        anonymous = httpx.post(
            f"http://127.0.0.1:{port}/mcp", json=initialize, headers=headers, timeout=30
        )
        wrong_key = httpx.post(
            f"http://127.0.0.1:{port}/mcp",
            json=initialize,
            headers={**headers, "X-API-Key": "definitely-not-the-key"},
            timeout=30,
        )
        # Control: a gate that 401s every caller would satisfy the two
        # assertions below without being a gate at all.
        valid_key = httpx.post(
            f"http://127.0.0.1:{port}/mcp",
            json=initialize,
            headers={**headers, "X-API-Key": "the-only-valid-key"},
            timeout=30,
        )
    finally:
        proc.terminate()
        proc.wait(timeout=30)

    assert anonymous.status_code == 401, (
        f"an anonymous caller initialised an MCP session over HTTP "
        f"(HTTP {anonymous.status_code}) against a config that declares "
        f"api.keys. The REST transport 401s the identical caller."
    )
    assert wrong_key.status_code == 401, (
        f"a deliberately wrong X-API-Key initialised an MCP session (HTTP {wrong_key.status_code})."
    )
    assert valid_key.status_code != 401, (
        f"the configured key was rejected too (HTTP {valid_key.status_code}); the "
        f"transport is closed to everyone, which is not the same as authenticated."
    )


def test_b5_sdk_built_adapter_serves_a_request(tmp_path: Path, write_config: Any) -> None:
    """An adapter written entirely against the SDK must serve a real request.

    This is the claim the SDK exists to make, and the one its own compliance
    suite cannot check: the suite validates against the SDK's own types, so a
    mirror that has drifted from ``nautilus.core.models`` passes it and then
    fails on the first real request.
    """
    import asyncio

    from nautilus import Broker

    module = tmp_path / "sdk_adapter.py"
    module.write_text(_SDK_ADAPTER, encoding="utf-8")
    config = write_config(
        {
            "adapters": [{"module_path": str(module), "class": "SdkAdapter", "source_type": "sdk"}],
            "sources": [
                {
                    "id": "sdk_source",
                    "type": "sdk",
                    "description": "built against the SDK only",
                    "classification": "unclassified",
                    "data_types": ["docs"],
                    "allowed_purposes": [],
                    "connection": "memory://",
                }
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    async def _run() -> Any:
        broker = Broker.from_config(config)
        try:
            return await broker.arequest("a", "docs", {"purpose": "p", "session_id": "s1"})
        finally:
            await broker.aclose()

    response = asyncio.run(_run())
    assert response.data.get("sdk_source") == [{"ok": True}], (
        f"an adapter built the documented way returned nothing. "
        f"errored={response.sources_errored} data={response.data}"
    )


_SDK_ADAPTER = '''
"""An adapter that imports only from nautilus_adapter_sdk, as documented."""

from __future__ import annotations

from typing import Any, ClassVar

from nautilus_adapter_sdk.types import AdapterResult


class SdkAdapter:
    source_type: ClassVar[str] = "sdk"

    async def connect(self, config: Any) -> None:
        self._config = config

    async def execute(self, intent: Any, scope: Any, context: Any) -> AdapterResult:
        return AdapterResult(
            source_id=self._config.id, rows=[{"ok": True}], duration_ms=1, error=None
        )

    async def get_schema(self) -> Any:
        raise NotImplementedError

    async def close(self) -> None:
        return None
'''
