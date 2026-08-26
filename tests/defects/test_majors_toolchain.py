"""Pins for the analysis, timeout, CLI and toolchain defects (REPORT.md 4.16-4.22).

The LLM tests run against a local stub that speaks the OpenAI chat-completions
shape and records the prompt it was sent. That is deliberate: the defects are
about *what Nautilus puts in the prompt*, so a real model would only add
nondeterminism to an assertion about our own outbound payload.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.defect


_SLOW_ADAPTER = '''
"""An adapter whose backend never answers."""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

from nautilus.core.models import AdapterResult


class SlowAdapter:
    source_type: ClassVar[str] = "slow"

    async def connect(self, config: Any) -> None:
        self._config = config

    async def execute(self, *args: Any, **kwargs: Any) -> AdapterResult:
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")

    async def get_schema(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("no schema for the fixture adapter")

    async def close(self) -> None:
        return None


class FastAdapter(SlowAdapter):
    source_type: ClassVar[str] = "fast"

    async def execute(self, *args: Any, **kwargs: Any) -> AdapterResult:
        # The configured source id, not the adapter's type: the broker keys
        # the response by it.
        return AdapterResult(
            source_id=self._config.id, rows=[{"ok": True}], duration_ms=1, error=None
        )
'''


# ---------------------------------------------------------------------------
# 4.16 / 4.17 -- what Nautilus sends to the analysis provider
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_llm() -> Any:
    """An OpenAI-compatible endpoint that records every prompt it receives."""
    seen: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"] or 0))
            seen.append(json.loads(body))
            analysis = json.dumps(
                {
                    "data_types_needed": ["patients"],
                    "entities": [],
                    "temporal_scope": None,
                    "sensitivity": "low",
                    "raw_intent": "patients",
                }
            )
            # The provider calls the Responses API, not chat completions.
            payload = json.dumps(
                {
                    "id": "resp_stub",
                    "object": "response",
                    "created_at": 0,
                    "status": "completed",
                    "model": "stub-model",
                    "output": [
                        {
                            "type": "message",
                            "id": "msg_stub",
                            "status": "completed",
                            "role": "assistant",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": analysis,
                                    "annotations": [],
                                }
                            ],
                        }
                    ],
                    "parallel_tool_calls": False,
                    "tool_choice": "auto",
                    "tools": [],
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: Any) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield (f"http://127.0.0.1:{server.server_port}/v1", seen)
    finally:
        server.shutdown()
        server.server_close()


def _llm_config(write_config: Any, base_url: str, pg_dsn: str) -> str:
    return write_config(
        {
            "sources": [
                {
                    "id": "patients",
                    "type": "postgres",
                    "description": "patient records",
                    "classification": "unclassified",
                    "data_types": ["patients", "billing"],
                    "allowed_purposes": [],
                    "connection": pg_dsn,
                    "table": "journey.patients",
                }
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
            "analysis": {
                "mode": "llm-first",
                # LocalInferenceProvider subclasses OpenAIProvider and
                # overrides only the client factory, so it is the same prompt
                # path the report names -- pointed at a stub we can inspect.
                "provider": {
                    "type": "local",
                    "base_url": base_url,
                    "model": "stub-model",
                    "api_key_env": "STUB_LLM_KEY",
                },
            },
            "session_tokens": {"enabled": True},
        }
    )


@pytest.mark.docker
def test_m416_the_session_token_is_not_sent_to_the_analysis_provider(
    stub_llm: Any, pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The signed session credential must not leave the process in a prompt.

    ``Broker.arequest`` mints the session token into ``context`` before
    ``_analyze_intent``, and the OpenAI/Anthropic providers do
    ``json.dumps(context)`` straight into the prompt, so the live credential
    is always present when ``session_tokens.enabled: true``. Clearance,
    purpose, session_id and embedding are the *declared* context contract
    (``analysis/llm/base.py:63-65``) and are not the issue; the token appears
    in no context contract, no doc, and has no opt-out.

    It is a real credential: ``_gate_handoff_token`` requires a valid matching
    token before any ``declare_handoff``, and ``verify_session_token``
    accepts it as an HTTP header.
    """
    from nautilus import Broker

    monkeypatch.setenv("STUB_LLM_KEY", "stub-key")
    base_url, seen = stub_llm
    config = _llm_config(write_config, base_url, pg_dsn)

    async def _run() -> None:
        broker = Broker.from_config(config)
        try:
            await broker.arequest(
                "a", "patient records", {"purpose": "care", "session_id": "s-leak"}
            )
        finally:
            await broker.aclose()

    # The claim is about the outbound prompt, so a provider-side error after
    # the request was sent must not hide it.
    with contextlib.suppress(Exception):
        asyncio.run(_run())
    assert seen, "the stub provider was never called; the fixture is wrong"
    prompts = json.dumps(seen)
    assert "session_token" not in prompts, (
        "the broker's signed session token was serialised into the analysis "
        "prompt and sent to the provider. Fix: pop it at the analysis boundary."
    )


@pytest.mark.docker
def test_m417_the_configured_data_types_reach_the_analysis_prompt(
    stub_llm: Any, pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The model must be told the vocabulary its answer is matched against.

    ``OpenAIProvider.analyze`` substitutes only ``$intent`` and
    ``$context_json``; the deployment's configured ``data_types`` never reach
    the prompt. ``fathom_router.py:249`` then encodes the model's tokens
    verbatim and ``overlaps()`` is a bare exact-token set intersection, so a
    plausible answer like ``case.files`` against a configured ``case`` yields
    ``sources_queried: []`` with no denial record -- a silent empty response,
    not a policy decision. ``analysis.keyword_map`` binds the two sides in
    pattern mode and is consumed only by the pattern matcher.
    """
    from nautilus import Broker

    monkeypatch.setenv("STUB_LLM_KEY", "stub-key")
    base_url, seen = stub_llm
    config = _llm_config(write_config, base_url, pg_dsn)

    async def _run() -> None:
        broker = Broker.from_config(config)
        try:
            await broker.arequest("a", "patient records", {"purpose": "care", "session_id": "s1"})
        finally:
            await broker.aclose()

    # The claim is about the outbound prompt, so a provider-side error after
    # the request was sent must not hide it.
    with contextlib.suppress(Exception):
        asyncio.run(_run())
    assert seen, "the stub provider was never called; the fixture is wrong"
    prompts = json.dumps(seen)
    missing = [dt for dt in ("patients", "billing") if dt not in prompts]
    assert not missing, (
        f"the configured data_types {missing} never reached the prompt, so the "
        f"model is guessing at a closed vocabulary it was never shown, and a "
        f"near-miss token produces an empty response with no denial record."
    )


# ---------------------------------------------------------------------------
# 4.18 -- no per-adapter deadline anywhere
# ---------------------------------------------------------------------------


def test_m418_a_hanging_adapter_does_not_pin_the_request(tmp_path: Path, write_config: Any) -> None:
    """One unresponsive source must not hold the request open indefinitely.

    ``grep "wait_for|asyncio.timeout|TimeoutError" nautilus/transport/
    nautilus/core/`` finds nothing; ``_gather_adapter_results`` is a bare
    ``asyncio.gather``. There is no ``SourceConfig`` timeout field,
    ``postgres.py`` passes no ``command_timeout`` and no ``timeout=``, and
    ``uvicorn.Config`` sets no request timeout. The request, its session
    write and its audit entry all wait, and the healthy co-queried source
    finishes and is held.
    """
    from nautilus import Broker
    from nautilus.config.models import SourceConfig

    assert SourceConfig.model_fields["timeout_s"].default is not None, (
        "the default source budget is unbounded, so an unconfigured source can still hang forever"
    )

    module = tmp_path / "slow_adapters.py"
    module.write_text(_SLOW_ADAPTER, encoding="utf-8")
    config = write_config(
        {
            "adapters": [
                {"module_path": str(module), "class": "SlowAdapter", "source_type": "slow"},
                {"module_path": str(module), "class": "FastAdapter", "source_type": "fast"},
            ],
            "sources": [
                {
                    "id": sid,
                    "type": stype,
                    "description": sid,
                    "classification": "unclassified",
                    "data_types": ["docs"],
                    "allowed_purposes": [],
                    "connection": "memory://",
                    # Explicit and short so the pin costs two seconds rather
                    # than a full default budget. That the default itself is
                    # finite is asserted below.
                    "timeout_s": 2,
                }
                for sid, stype in (("hangs", "slow"), ("answers", "fast"))
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    async def _run() -> Any:
        broker = Broker.from_config(config)
        try:
            # The adapter sleeps an hour. This bound is deliberately loose:
            # the pin is that *a* per-source deadline exists and that the
            # healthy source still answers, not that the default is any
            # particular number -- that belongs in config, not here.
            return await asyncio.wait_for(
                broker.arequest("a", "docs", {"purpose": "p", "session_id": "s1"}),
                timeout=30,
            )
        finally:
            await broker.aclose()

    try:
        response = asyncio.run(_run())
    except TimeoutError:
        pytest.fail(
            "a source whose execute() never returns held the whole request for "
            "30s with no per-adapter deadline. The healthy source finished and "
            "was held with it, and no audit entry was written."
        )
    assert response.data.get("answers"), (
        f"the healthy source returned nothing: errored={response.sources_errored}"
    )


# ---------------------------------------------------------------------------
# 4.19 / 4.20 -- the adapters CLI cannot see a deployment
# ---------------------------------------------------------------------------


def _nautilus(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(Path(".venv/bin/nautilus").resolve()), *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=120,
    )


def test_m419_adapters_list_can_list_a_configured_adapter(
    tmp_path: Path, write_config: Any
) -> None:
    """``nautilus adapters list`` must be able to see a real deployment.

    ``cli/adapters.py:236-246`` calls ``Broker.from_config(None)`` inside a
    bare ``except Exception: adapters = []``; ``load_config`` does
    ``Path(None)``, which raises ``TypeError`` before any I/O,
    unconditionally. ``list`` has no ``--config`` flag, so the output is
    always ``OK: no adapters registered``, exit 0.
    ``docs/how-to/monitor-with-grafana.md:61`` lists
    ``adapters list --status quarantined`` under **What to alert on**.
    """
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
                    "connection": "postgresql://localhost/x",
                    "table": "public.vulns",
                }
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )
    # There is no --config flag, so this is the only form a user can run,
    # from the directory holding their config.
    result = _nautilus("adapters", "list", cwd=Path(config).parent)
    assert "vulns" in result.stdout or "postgres" in result.stdout, (
        f"`adapters list` could not name the one configured adapter sitting "
        f"next to it, and takes no --config flag to be pointed at one.\n"
        f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_m420_adapters_schema_does_not_confirm_a_nonexistent_adapter(
    tmp_path: Path,
) -> None:
    """The CLI must not fabricate a schema for a name that does not exist.

    ``_get_adapter_schema`` unconditionally returns
    ``AdapterSchema.unknown(adapter_id=name, source_type="unknown")`` without
    consulting a config, a registry or an adapter, so a nonexistent adapter
    is confirmed as real with exit 0 -- and a *real* source prints a digest
    matching neither its live schema nor its stored baseline. The dead
    ``if schema is None: warn(...)`` branch in both callers shows the correct
    behaviour was written and stranded.
    """
    result = _nautilus("adapters", "schema", "no-such-adapter-anywhere", cwd=tmp_path)
    assert result.returncode != 0, (
        f"`adapters schema no-such-adapter-anywhere` exited 0 and printed a "
        f"schema for an adapter that does not exist:\n{result.stdout}"
    )


# ---------------------------------------------------------------------------
# 4.22 -- smaller API breakage with real consequences
# ---------------------------------------------------------------------------


def test_m422_version_command_works() -> None:
    """``nautilus version`` is the documented post-install check.

    ``cli/version.py:11`` looks up ``metadata.version("nautilus")``; the
    distribution is ``nautilus-rkm``, so it exits 1 on every install. Both
    existing tests monkeypatch ``cli.metadata.version`` with a name-ignoring
    lambda, which is why neither notices.
    """
    result = _nautilus("version")
    assert result.returncode == 0, (
        f"`nautilus version` exited {result.returncode}: "
        f"{(result.stderr or result.stdout).strip()!r}"
    )


def test_m422_afrom_config_exists() -> None:
    """``Broker.afrom_config`` is listed in README "What Ships Today".

    ``README.md:69`` and ``CHANGELOG.md:87`` are the only two occurrences in
    the repo.
    """
    from nautilus import Broker

    assert hasattr(Broker, "afrom_config"), (
        "README.md:69 lists afrom_config under 'What Ships Today'; it does not exist."
    )


@pytest.mark.docker
def test_m422_request_after_close_is_refused(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A closed broker must not serve real data with an unrecorded receipt.

    ``arequest`` never checks ``self._closed``, and ``PostgresAdapter.connect``
    doesn't check its own either, so a post-close request opens a *new* pool
    and returns real rows with a signed attestation token -- while zero lines
    reach the attestation sink (``I/O operation on closed file``, swallowed
    per AC-14.5). A second ``aclose()`` returns early on ``_closed`` and
    permanently refuses to release those connections.
    """
    from nautilus import Broker

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [
                {
                    "id": "patients",
                    "type": "postgres",
                    "description": "patient records",
                    "classification": "unclassified",
                    "data_types": ["patients"],
                    "allowed_purposes": [],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.patients",
                }
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    async def _run() -> Any:
        broker = Broker.from_config(config)
        await broker.aclose()
        return await broker.arequest("a", "patients", {"purpose": "p", "session_id": "s1"})

    try:
        response = asyncio.run(_run())
    except Exception:  # noqa: BLE001 -- refusing is the correct behaviour
        return

    assert not response.data.get("patients"), (
        "a request issued after close() returned real rows and a signed "
        "attestation token, and nothing reached the attestation sink. That is "
        "data egress with no receipt."
    )


@pytest.mark.docker
def test_m422_rest_forwards_fact_set_hash(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A field declared on the request model must not be silently dropped.

    ``BrokerRequest.fact_set_hash`` is declared -- and therefore appears in
    the OpenAPI schema -- but ``_handle_request`` never forwards it. The
    library echoes it; REST returns ``null``, 200, no warning.
    """
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    key = "journey-key"
    config = write_config(
        {
            "sources": [
                {
                    "id": "patients",
                    "type": "postgres",
                    "description": "patient records",
                    "classification": "unclassified",
                    "data_types": ["patients"],
                    "allowed_purposes": [],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.patients",
                }
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
            "api": {"keys": [key]},
        }
    )

    with TestClient(create_app(config), headers={"X-API-Key": key}) as client:
        body = client.post(
            "/v1/request",
            json={
                "agent_id": "a",
                "intent": "patients",
                "context": {"purpose": "p", "session_id": "s1"},
                "fact_set_hash": "deadbeef",
            },
        ).json()

    assert body.get("fact_set_hash") == "deadbeef", (
        f"REST returned fact_set_hash={body.get('fact_set_hash')!r} for a "
        f"request that declared 'deadbeef'. The library echoes it."
    )


@pytest.mark.parametrize(
    ("source_type", "missing_field", "extra"),
    [
        ("postgres", "table", {}),
        ("elasticsearch", "index", {}),
        ("neo4j", "label", {}),
        ("llm", "model", {}),
        ("rest", "endpoints", {}),
    ],
)
def test_m422_config_rejects_a_source_the_runtime_can_never_serve(
    write_config: Any, source_type: str, missing_field: str, extra: dict[str, Any]
) -> None:
    """A source missing its mandatory field must fail at load, not at runtime.

    ``SourceConfig`` is a flat union with everything optional, so the broker
    starts, ``/healthz`` and ``/readyz`` go green (neither touches adapters),
    and the source errors on every request forever. ``models.py:100-106``
    already narrowed ``embedder`` to a ``Literal`` for exactly this reason.
    """
    from nautilus import Broker

    config = write_config(
        {
            "sources": [
                {
                    "id": "broken",
                    "type": source_type,
                    "description": f"a {source_type} source with no {missing_field}",
                    "classification": "unclassified",
                    "data_types": ["docs"],
                    "allowed_purposes": [],
                    "connection": "memory://",
                    **extra,
                }
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    with pytest.raises(Exception, match=r".+"):
        broker = Broker.from_config(config)
        broker.close()
        pytest.fail(
            f"a {source_type} source with no '{missing_field}' loaded cleanly. "
            f"The broker starts, the health probes go green, and every request "
            f"to it fails forever."
        )


# ---------------------------------------------------------------------------
# 4.21 -- the rule-authoring toolchain is scoped wrong
# ---------------------------------------------------------------------------


_DISPATCH_RULES = {
    "module": "nautilus-routing",
    "ruleset": "dispatch",
    "version": "1.0.0",
    "rules": [
        {
            "name": f"route-{level}",
            "salience": 100 - i,
            "when": [
                {
                    "template": "source",
                    "conditions": [{"slot": "classification", "expression": f"equals({level})"}],
                }
            ],
            "then": [
                {
                    "assert": {
                        "template": "routing_decision",
                        "slots": {"source_id": f"src-{level}", "reason": f"{level} dispatch"},
                    }
                }
            ],
        }
        for i, level in enumerate(("public", "internal", "confidential", "secret"))
    ],
}


def test_m421_shadow_analysis_keeps_the_value_a_rule_constrains(tmp_path: Path) -> None:
    """Two rules matching *different values* of one slot do not shadow each other.

    ``rkm/validator/shadow.py:82`` records only the slot *name*, so
    ``equals(secret)``, ``operator: eq`` + ``value:``, and a bare ``bind:``
    all normalise to ``{'classification': ''}``. Any two rules constraining
    the same slot are then treated as having an equal LHS and the
    lower-salience one is flagged ``relation="shadows"`` -- which asserts a
    live deny rule can never fire. Verbatim ``test:`` expressions *are* kept
    as keys, so the asymmetry is an oversight rather than a design.

    A disjoint-value dispatch table is the clearest case: none of these four
    rules can shadow another, because no source has two classifications.
    """
    from nautilus.rkm.validator.shadow import shadow_check

    rules = _DISPATCH_RULES["rules"]
    proposed, existing = rules[-1], rules[:-1]

    flags = shadow_check(proposed, existing)
    shadowed = [f for f in flags if f.relation == "shadows"]
    assert not shadowed, (
        f"a rule matching classification=secret was reported as shadowing "
        f"{[f.existing_rule if hasattr(f, 'existing_rule') else f for f in shadowed]}, "
        f"which match public/internal/confidential. No source has two "
        f"classifications, so none of these can mask another; run_pipeline "
        f"auto-rejects the proposal on the resulting score."
    )


def test_m421_validate_static_inspects_the_then_clause(tmp_path: Path) -> None:
    """A rule that will raise on every matching request must not pass validation.

    ``validate_static`` walks only ``when``/``lhs`` and never inspects
    ``then.assert`` -- not the template name, not its slots.
    ``denial_record.rule_name`` is ``required: true`` in the template, so
    omitting it passes validate *and* test, loads into the engine, and then
    raises ``ConsistencyError: denial_missing_linkage`` on the first matching
    request. ``FathomRouter.replay()`` deliberately skips consistency checks,
    so the sandbox stage cannot catch it either, regardless of audit history.
    """
    import yaml

    from nautilus.rkm.validator.static import validate_static

    rule = {
        "module": "nautilus-routing",
        "ruleset": "incomplete-denial",
        "version": "1.0.0",
        "rules": [
            {
                "name": "deny-secret",
                "salience": 100,
                "when": [
                    {
                        "template": "source",
                        "conditions": [{"slot": "classification", "expression": "equals(secret)"}],
                    }
                ],
                "then": [
                    {
                        "assert": {
                            "template": "denial_record",
                            # rule_name is required: true in the template.
                            "slots": {"source_id": "src", "reason": "too sensitive"},
                        }
                    }
                ],
            }
        ],
    }
    path = tmp_path / "incomplete-denial.yaml"
    path.write_text(yaml.safe_dump(rule), encoding="utf-8")

    report = validate_static(path)
    assert not report.ok, (
        "validate_static passed a rule that omits the required "
        "denial_record.rule_name slot. It loads, then raises "
        "ConsistencyError: denial_missing_linkage on the first matching "
        "request -- after passing every gate the lifecycle documents."
    )


def test_m422_concurrent_approve_produces_one_decision(tmp_path: Path) -> None:
    """Two reviewers approving at once must produce one approval, not two.

    ``review.approve`` read ``proposal.status`` and then called
    ``queue.transition``, so both callers saw ``pending`` and both proceeded.
    ``fcntl.lockf`` did not stop them: its locks belong to the process, so a
    second thread asking for ``LOCK_EX`` on its own descriptor is granted it
    immediately. The proposal ends up with two recorded approvals by two
    different reviewers, and the governance record no longer says who decided.
    """
    from concurrent.futures import ThreadPoolExecutor
    from datetime import UTC, datetime

    from nautilus.rkm.queue import ProposalQueue
    from nautilus.rkm.review import AlreadyDecidedError, approve_proposal
    from nautilus.rkm.types import Proposal

    queue = ProposalQueue(tmp_path / "queue")
    queue.submit(
        Proposal(
            proposal_id="prop_race",
            schema_version=1,
            status="pending",
            proposer="curator",
            proposed_at=datetime.now(UTC),
            target_module="nautilus-routing",
            artifact_type="rule",
            artifact={},
            validation={},
            lineage={},
            decisions=[],
        )
    )

    def _approve(reviewer: str) -> str:
        try:
            approve_proposal(
                "prop_race",
                reviewer,
                queue=queue,
                lineage=None,  # type: ignore[arg-type]  -- unused: no router, so no promotion
            )
        except AlreadyDecidedError:
            return "refused"
        except Exception as exc:  # noqa: BLE001 -- anything else is a real failure
            return f"error:{type(exc).__name__}"
        return "approved"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(_approve, [f"reviewer-{i}" for i in range(8)]))

    decided = queue.get("prop_race")
    assert decided is not None
    approvals = [d for d in decided.decisions if d.get("to") == "approved"]
    assert len(approvals) == 1, (
        f"eight concurrent approves recorded {len(approvals)} approvals by "
        f"{[a.get('reviewer') for a in approvals]}. outcomes={outcomes}"
    )


def test_m419_scaffolded_adapter_passes_its_own_compliance_suite(tmp_path: Path) -> None:
    """``nautilus adapters new`` must produce a package that works.

    The scaffold built ``AdapterResult(data=..., metadata=...)`` -- a shape
    the broker cannot read -- and shipped no ``get_schema()``, so every
    generated adapter failed its own generated compliance tests and then
    failed again on its first real request. Both are exactly what an adapter
    author copies first.
    """
    import os
    import subprocess
    import sys

    nautilus_bin = str(Path(".venv/bin/nautilus").resolve())
    result = subprocess.run(
        [nautilus_bin, "adapters", "new", "my-csv-adapter", "--dir", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"scaffold failed: {result.stdout}\n{result.stderr}"

    generated = tmp_path / "my-csv-adapter"
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=generated,
        capture_output=True,
        text=True,
        timeout=300,
        env={
            **os.environ,
            "PYTHONPATH": str(generated / "src"),
            # The generated package's own pytest.ini/pyproject drives config;
            # the repo's coverage plugin must not follow us in.
            "COVERAGE_CORE": "",
        },
    )
    assert run.returncode == 0, (
        f"the generated adapter fails the compliance suite it ships with:\n"
        f"{run.stdout}\n{run.stderr}"
    )
    # Control: an empty suite also exits 0 on some configs, and would prove
    # nothing about the scaffold.
    assert " passed" in run.stdout, f"the generated suite ran no tests:\n{run.stdout}"


def test_m419_status_filter_refuses_to_answer_from_a_config(
    tmp_path: Path, write_config: Any
) -> None:
    """``--status quarantined`` without a server must fail, not report nothing.

    Quarantine lives in the serving process's memory. Answering from a config
    file can only ever print an empty list, which to an alert reads as
    "nothing is quarantined" -- the single most dangerous wrong answer this
    command can give, and the one the Grafana how-to tells operators to alert
    on.
    """
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
                    "connection": "postgresql://localhost/x",
                    "table": "public.vulns",
                }
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )
    result = _nautilus("adapters", "list", "--status", "quarantined", "--config", config)
    assert result.returncode != 0, (
        f"`adapters list --status quarantined` answered from a config file and "
        f"exited 0:\n{result.stdout}"
    )
