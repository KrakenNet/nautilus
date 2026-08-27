"""One pin per Wave A item — the findings that gate 1.0 (see the readiness review).

Wave A is the list of things that make Nautilus *lie* to whoever runs it: an
audit query that answers "no matches" to a filter that matches, a documented
security control the config cannot express, a certificate the adapter accepts
and discards, a promotion the docs call a deploy that is gone on restart.

Every pin here exercises the public surface a user reaches — the reader, the
loader, ``connect()``, the CLI, the shipped docs — because each defect survived
a suite that tested the seam underneath it.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.defect

REPO_ROOT = Path(__file__).resolve().parents[2]


# ===========================================================================
# A1 -- the default audit query stops scanning and reports completion
# ===========================================================================


def _audit_entry(agent_id: str, ts: datetime, request_id: str) -> dict[str, Any]:
    return {
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "request_id": request_id,
        "agent_id": agent_id,
        "session_id": None,
        "raw_intent": "q",
        "intent_analysis": {"raw_intent": "q", "data_types_needed": [], "entities": []},
        "facts_asserted_summary": {},
        "routing_decisions": [],
        "scope_constraints": [],
        "denial_records": [],
        "error_records": [],
        "rule_trace": [],
        "sources_queried": ["pg"],
        "sources_denied": [],
        "sources_skipped": [],
        "sources_errored": [],
        "attestation_token": None,
        "duration_ms": 1,
        "event_type": "request",
    }


def _audit_line(entry: dict[str, Any]) -> str:
    return json.dumps(
        {
            "timestamp": entry["timestamp"],
            "session_id": entry["request_id"],
            "modules_traversed": [],
            "rules_fired": [],
            "decision": "allow",
            "reason": "queried=1",
            "duration_us": 1000,
            "metadata": {"nautilus_audit_entry": json.dumps(entry, separators=(",", ":"))},
        }
    )


def test_wa1_a_filtered_audit_query_answers_in_the_default_sort_order(tmp_path: Path) -> None:
    """A filter that matches must not come back empty in the order the API defaults to.

    ``sort="desc"`` is the default on ``read_page``, on ``GET /v1/audit`` and on
    both admin pages, and it is the order a compliance team reads in. It reads a
    fixed window of ``page_size * 2`` lines backwards from the tail and stops,
    so a filter whose matches are older than that window returns zero entries
    *and* ``next_cursor=None`` — "no such access ever happened", which for an
    audit product is the worst available answer.

    The control is the ascending read of the same file with the same filter: if
    that does not find the five entries either, the fixture is wrong.
    """
    from nautilus.ui.audit_reader import AuditReader

    base = datetime(2026, 1, 1, tzinfo=UTC)
    lines: list[str] = []
    for i in range(5):
        lines.append(_audit_line(_audit_entry("needle", base + timedelta(seconds=i), f"r{i}")))
    for i in range(5, 300):
        lines.append(_audit_line(_audit_entry("haystack", base + timedelta(seconds=i), f"r{i}")))
    audit = tmp_path / "audit.jsonl"
    audit.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reader = AuditReader(audit)
    ascending = reader.read_page(agent_id="needle", sort="asc")
    assert len(ascending.entries) == 5, "fixture is wrong: ascending cannot see the matches either"

    descending = reader.read_page(agent_id="needle", sort="desc")
    assert len(descending.entries) == 5, (
        f"the default (desc) read found {len(descending.entries)} of 5 matching entries and "
        f"reported next_cursor={descending.next_cursor!r} — the caller is told the log holds "
        f"no such access"
    )


# ===========================================================================
# A2 -- the README's own config does not load
# ===========================================================================


def _readme_config_blocks() -> list[str]:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```yaml\n(.*?)```", text, flags=re.DOTALL)
    return [b for b in blocks if "sources:" in b]


def test_wa2_the_readme_config_loads_and_keeps_every_key_it_declares(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first config a user copies must load, and must not drop what it declares.

    Two failures in one block: keys the loader rejects (so minute two of the
    quick start is a traceback), and keys no model declares — ``rules.paths``
    and ``audit.sink`` — which are accepted and discarded, so a user who fixes
    only the reported errors ships a broker that loads none of their rules.
    """
    from nautilus.config.loader import load_config

    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost:5432/db")
    blocks = _readme_config_blocks()
    assert blocks, "no yaml config block found in README.md — this pin is testing nothing"

    for block in blocks:
        path = tmp_path / "readme.yaml"
        path.write_text(block, encoding="utf-8")
        config = load_config(str(path))  # must not raise
        assert config.sources, "the README config loaded with no sources"


# ===========================================================================
# A3 -- a mistyped key is accepted and silently changes what runs
# ===========================================================================


def test_wa3_a_mistyped_config_key_is_reported(tmp_path: Path) -> None:
    """A typo in the operator-facing document must not be swallowed.

    ``sesion_store:`` parses, validates, and runs the in-memory session store in
    production with no error and no warning — the deployment believes it has
    durable sessions. The project already forbids extras on the attestation sink
    specs; the document the operator actually types is the one surface that
    accepts anything.

    The control is the correctly spelled key below: it must still load, or this
    pin is only proving that the config is broken.
    """
    import yaml

    from nautilus.config.loader import ConfigError, load_config

    source = {
        "id": "src",
        "type": "postgres",
        "description": "a source",
        "classification": "unclassified",
        "data_types": ["x"],
        "connection": "postgresql://localhost:5432/db",
        "table": "public.t",
    }
    good = tmp_path / "good.yaml"
    good.write_text(
        yaml.safe_dump({"sources": [source], "session_store": {"backend": "memory"}}),
        encoding="utf-8",
    )
    load_config(str(good))

    typo = tmp_path / "typo.yaml"
    typo.write_text(
        yaml.safe_dump({"sources": [source], "sesion_store": {"backend": "postgres"}}),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="sesion_store"):
        load_config(str(typo))


# ===========================================================================
# A4 -- proxy_trust is documented and implemented, and the config cannot say it
# ===========================================================================


def test_wa4_proxy_trust_is_reachable_from_yaml(tmp_path: Path) -> None:
    """The operator guide documents ``api.auth.mode``; the config must carry it.

    Every transport already dispatches on ``config.api.auth.mode`` and the
    dependency it selects is implemented. ``ApiConfig`` is ``host``/``port``/
    ``keys``, so the mode can never be anything but the default and the
    documented deployment shape is unreachable.
    """
    import yaml

    from nautilus.config.loader import load_config

    path = tmp_path / "proxy.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "sources": [
                    {
                        "id": "src",
                        "type": "postgres",
                        "description": "a source",
                        "classification": "unclassified",
                        "data_types": ["x"],
                        "connection": "postgresql://localhost:5432/db",
                        "table": "public.t",
                    }
                ],
                "api": {
                    "auth": {"mode": "proxy_trust", "trusted_proxies": ["10.0.0.0/8"]},
                    "keys": [],
                },
            }
        ),
        encoding="utf-8",
    )
    config = load_config(str(path))
    assert getattr(config.api.auth, "mode", None) == "proxy_trust"
    assert list(getattr(config.api.auth, "trusted_proxies", [])) == ["10.0.0.0/8"]


def test_wa4_proxy_trust_refuses_an_untrusted_peer() -> None:
    """``X-Forwarded-User`` is only an identity if only the proxy can set it.

    Under ``proxy_trust`` the header *is* the credential. Without a check on who
    sent it, anyone who can reach the port authenticates as anyone — so the mode
    is not a security control until the peer is pinned to the proxy's address.

    The control is the trusted-peer request below: same header, same app, a CIDR
    that contains the client, which must be accepted.
    """
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from nautilus.transport.auth import proxy_trust_dependency

    app = FastAPI()

    @app.get("/who")
    async def _who(user: str = Depends(proxy_trust_dependency)) -> dict[str, str]:
        return {"user": user}

    assert _who is not None  # the route is registered by the decorator

    headers = {"X-Forwarded-User": "attacker"}
    app.state.trusted_proxies = ["10.0.0.0/8"]

    with TestClient(app, client=("203.0.113.9", 40000)) as client:
        denied = client.get("/who", headers=headers)
    assert denied.status_code == 401, (
        f"a caller outside the configured proxy range asserted an identity through "
        f"X-Forwarded-User and got {denied.status_code}"
    )

    with TestClient(app, client=("10.0.0.5", 40000)) as client:
        allowed = client.get("/who", headers=headers)
    assert allowed.status_code == 200, "the trusted-proxy control was rejected"


# ===========================================================================
# A5 -- adapters accept a client certificate and throw it away
# ===========================================================================


@pytest.mark.parametrize("source_type", ["elasticsearch", "neo4j"])
def test_wa5_an_unusable_client_certificate_is_reported(tmp_path: Path, source_type: str) -> None:
    """``auth: {type: mtls}`` must reach the client, or be refused.

    Elasticsearch passes ``ca_path`` as ``ca_certs`` and drops the cert/key pair
    entirely; omit ``ca_path`` and the branch does not run at all, so the client
    connects unauthenticated. Neo4j discards the whole block. Either way the
    operator configured mutual TLS, saw no error, and got a connection that does
    not present a certificate.

    A path that does not exist is the cheapest proof that the file is being
    read: ``connect()`` must fail rather than succeed without it. The control is
    the no-auth connect below, which must still build a client offline.
    """
    from nautilus.adapters.base import AdapterError
    from nautilus.config.models import SourceConfig

    adapters = {
        "elasticsearch": ("nautilus.adapters.elasticsearch", "ElasticsearchAdapter"),
        "neo4j": ("nautilus.adapters.neo4j", "Neo4jAdapter"),
    }
    module_name, class_name = adapters[source_type]
    module = __import__(module_name, fromlist=[class_name])
    adapter_cls = getattr(module, class_name)

    extra: dict[str, Any] = (
        {"index": "idx"} if source_type == "elasticsearch" else {"label": "Node"}
    )
    connection = "https://localhost:9200" if source_type == "elasticsearch" else "neo4j+s://l:7687"

    def _config(auth: dict[str, Any] | None) -> SourceConfig:
        return SourceConfig.model_validate(
            {
                "id": "src",
                "type": source_type,
                "description": "a source",
                "classification": "unclassified",
                "data_types": ["x"],
                "connection": connection,
                "auth": auth,
                **extra,
            }
        )

    import asyncio

    async def _connect(auth: dict[str, Any] | None) -> None:
        adapter = adapter_cls()
        try:
            await adapter.connect(_config(auth))
        finally:
            await adapter.close()

    asyncio.run(_connect(None))  # control: an offline client still builds

    missing = str(tmp_path / "nope.pem")
    with pytest.raises(AdapterError):
        asyncio.run(_connect({"type": "mtls", "cert_path": missing, "key_path": missing}))


def test_wa5_influx_reports_an_auth_type_it_cannot_use(tmp_path: Path) -> None:
    """An ``auth:`` block the adapter cannot honour must be refused, not ignored.

    ``InfluxDBAdapter.connect`` reads the token from ``INFLUXDB_V2_TOKEN`` and
    never looks at ``config.auth`` — so a source that declares basic or mTLS
    credentials connects with whatever the environment happened to hold.
    ``S3Adapter`` is the model: it names the type it cannot use and raises.
    """
    import asyncio

    from nautilus.adapters.base import AdapterError
    from nautilus.adapters.influxdb import InfluxDBAdapter
    from nautilus.config.models import SourceConfig

    config = SourceConfig.model_validate(
        {
            "id": "src",
            "type": "influxdb",
            "description": "a source",
            "classification": "unclassified",
            "data_types": ["x"],
            "connection": "http://localhost:8086",
            "table": "b",
            "auth": {"type": "basic", "username": "u", "password": "p"},
        }
    )

    async def _connect() -> None:
        adapter = InfluxDBAdapter()
        try:
            await adapter.connect(config)
        finally:
            await adapter.close()

    with pytest.raises(AdapterError, match="basic"):
        asyncio.run(_connect())


# ===========================================================================
# A6 -- a promotion the docs call a deploy does not survive a restart
# ===========================================================================


_PROMOTED_RULE = """
module: nautilus-routing
ruleset: wave-a-promoted
version: "1.0"
rules:
  - name: wave-a-promoted-probe
    description: "Attach a scope constraint for the promotion-persistence pin."
    salience: 50
    when:
      - template: agent
        conditions:
          - slot: purpose
            bind: ?purpose
          - test: '(eq ?purpose "wave-a-probe")'
      - template: source
        conditions:
          - slot: id
            bind: ?sid
    then:
      action: scope
      reason: "wave-a promotion probe"
      assert:
        - template: scope_constraint
          slots:
            source_id: "?sid"
            field: "classification"
            operator: "="
            value: "cui"
"""


def test_wa6_a_promoted_rule_survives_the_process_that_promoted_it(tmp_path: Path) -> None:
    """RKM promotion is a governance act with a lineage record; it must be durable.

    ``reload_rule`` writes the YAML to a ``NamedTemporaryFile``, loads it, and
    unlinks it. Nothing is written into ``rules.user_rules_dirs``, so the rule
    is gone at the next restart — while the proposal is now ``promoted``, which
    ``approve_proposal`` refuses to re-approve. The lifecycle doc warns about
    rollback and not about this, so an operator reads it as a deploy.

    The pin builds a second router over the same configured rules directory,
    which is what a restart does.
    """
    from nautilus.core.fathom_router import FathomRouter
    from nautilus.rules import BUILT_IN_RULES_DIR

    user_dir = tmp_path / "rules"
    user_dir.mkdir()

    router = FathomRouter(
        built_in_rules_dir=BUILT_IN_RULES_DIR,
        user_rules_dirs=[user_dir],
        check_consistency=False,
    )
    router.reload_rule("wave-a-promoted-probe", _PROMOTED_RULE)

    restarted = FathomRouter(
        built_in_rules_dir=BUILT_IN_RULES_DIR,
        user_rules_dirs=[user_dir],
        check_consistency=False,
    )
    assert restarted is not None
    persisted = list(user_dir.glob("*.yaml"))
    assert persisted, (
        "the promoted rule was loaded into this process and written nowhere; the next "
        "restart runs without it while the proposal reads 'promoted'"
    )


def test_wa6_a_promotion_with_nowhere_to_persist_is_refused(tmp_path: Path) -> None:
    """No rules directory means no deploy — say so instead of pretending."""
    from nautilus.core import PolicyEngineError
    from nautilus.core.fathom_router import FathomRouter
    from nautilus.rules import BUILT_IN_RULES_DIR

    router = FathomRouter(
        built_in_rules_dir=BUILT_IN_RULES_DIR,
        user_rules_dirs=[],
        check_consistency=False,
    )
    with pytest.raises(PolicyEngineError, match="user_rules_dirs"):
        router.reload_rule("wave-a-promoted-probe", _PROMOTED_RULE)


# ===========================================================================
# A7 -- the CLI approve path can never promote
# ===========================================================================


def test_wa7_rkm_queue_approve_requires_the_broker_it_must_promote_into(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Approving from the CLI must not report a promotion it cannot perform.

    ``_cmd_queue_approve`` passes ``router=None``, so the rule is never loaded
    into any engine, while ``docs/concepts/rkm-lifecycle.md`` states the CLI and
    REST paths are equivalent. ``nautilus key rotate`` already solves this: it
    requires ``--url`` and refuses to act locally on state that lives inside a
    running broker.
    """
    import argparse

    from nautilus.cli import rkm as rkm_cli
    from nautilus.rkm.queue import ProposalQueue
    from nautilus.rkm.types import Proposal

    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice")
    monkeypatch.chdir(tmp_path)
    ProposalQueue(Path(".nautilus/rkm/queue")).submit(
        Proposal(
            proposal_id="prop_x",
            schema_version=2,
            status="pending",
            proposer="pipeline",
            proposed_at=datetime.now(UTC),
            target_module="nautilus-routing",
            artifact={"yaml": _PROMOTED_RULE},
            artifact_type="rule",
            validation={},
            lineage={},
            decisions=[],
        )
    )
    args = argparse.Namespace(
        rkm_subcommand="queue",
        rkm_queue_subcommand="approve",
        proposal_id="prop_x",
        json=False,
        config=None,
        url=None,
    )
    rc = rkm_cli._cmd_queue_approve(args)  # pyright: ignore[reportPrivateUsage] # noqa: SLF001
    combined = capsys.readouterr()
    assert rc != 0, "approve without --url returned success without promoting anything"
    assert "--url" in (combined.out + combined.err)


# ===========================================================================
# A8 -- default_purpose is parsed, shipped, and read by nothing that routes
# ===========================================================================


def test_wa8_a_registered_agents_default_purpose_is_used_when_routing(
    tmp_path: Path,
) -> None:
    """``agents.<id>.default_purpose`` must mean what the config says it means.

    It is parsed, it appears in three shipped configs, and the only reader is
    the session-token minter. On the routing path ``purpose`` comes from
    ``context`` alone, so a registered agent that omits it is denied by
    ``deny-purpose-mismatch`` — "I registered my agent and it still denies me".

    The control is the second agent, which declares no default and must still be
    denied: otherwise this pin would pass on a broker that had stopped enforcing
    purpose at all.
    """
    import asyncio

    import yaml

    from nautilus import Broker

    config: dict[str, Any] = {
        "sources": [
            {
                "id": "src",
                "type": "postgres",
                "description": "a source",
                "classification": "unclassified",
                "data_types": ["patients"],
                "allowed_purposes": ["care"],
                "connection": "postgresql://127.0.0.1:1/none",
                "table": "public.t",
            }
        ],
        "agents": {
            "carer": {"id": "carer", "clearance": "unclassified", "default_purpose": "care"},
            "stranger": {"id": "stranger", "clearance": "unclassified"},
        },
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "rules": {"packs": [], "user_rules_dirs": []},
    }
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")

    async def _denied(agent_id: str) -> list[str]:
        broker = Broker.from_config(str(path))
        try:
            response = await broker.arequest(agent_id, "patients", {})
            return list(response.sources_denied)
        finally:
            await broker.aclose()

    assert asyncio.run(_denied("stranger")) == ["src"], (
        "the control agent, which declares no default_purpose, was not denied — "
        "purpose is not being enforced and this pin proves nothing"
    )
    assert asyncio.run(_denied("carer")) == [], (
        "the agent's declared default_purpose was ignored on the routing path"
    )


# ===========================================================================
# A9 / A10 -- the shipped image serves nothing and reports itself healthy
# ===========================================================================


def test_wa9_the_runtime_image_serves_beyond_its_own_loopback() -> None:
    """The published image must serve the network it is published onto.

    ``nautilus serve`` binds ``127.0.0.1`` by default, so the container accepts
    nothing from outside itself — and the HEALTHCHECK probes ``localhost`` from
    *inside* the container, so it passes anyway. The example image in
    ``examples/full-showcase/Dockerfile`` already binds ``0.0.0.0``.
    """
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    runtime = text.split("AS runtime", 1)[1].split("AS debug", 1)[0]
    assert "0.0.0.0" in runtime, (
        "the runtime stage starts the server on its default bind (127.0.0.1) and "
        "health-checks itself from inside, so a container that serves nobody is green"
    )


def test_wa10_the_runtime_image_can_serve_its_own_metrics_endpoint() -> None:
    """``GET /metrics`` is documented as the Prometheus scrape target.

    The builder runs ``uv sync --no-dev`` with no extras, so the runtime venv has
    no OpenTelemetry: every metric is a no-op, ``setup_otel`` swallows the
    ImportError, and ``/metrics`` raises ImportError — a 500 on every scrape the
    monitoring guide tells operators to configure. The showcase image passes the
    extra, so the requirement is already known.
    """
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    builder = text.split("AS builder", 1)[1].split("AS runtime", 1)[0]
    assert "otel" in builder, (
        "the runtime venv is built without the 'otel' extra, so /metrics raises "
        "ImportError on every Prometheus scrape"
    )


# ===========================================================================
# A11 -- the adapter reference documents signatures the broker refuses
# ===========================================================================


def test_wa11_the_adapter_sdk_reference_matches_the_protocol() -> None:
    """An author who copies the reference must get an adapter the broker loads.

    ``docs/reference/adapter-sdk.md`` shows ``connect(self)`` where the protocol
    takes a ``SourceConfig``, an ``execute`` without ``context``, and an entry
    point resolving to a module rather than a class — which ``_discover_adapters``
    skips with a warning, so the adapter silently never registers.
    """
    import inspect

    from nautilus.adapters.base import Adapter

    text = (REPO_ROOT / "docs" / "reference" / "adapter-sdk.md").read_text(encoding="utf-8")

    connect_params = list(inspect.signature(Adapter.connect).parameters)
    execute_params = list(inspect.signature(Adapter.execute).parameters)

    for param in connect_params[1:]:
        assert f"{param}:" in text, f"adapter-sdk.md documents connect() without '{param}'"
    for param in execute_params[1:]:
        assert f"{param}:" in text, f"adapter-sdk.md documents execute() without '{param}'"
    assert re.search(r'^\s*my-adapter\s*=\s*"[\w.]+:\w+"', text, flags=re.MULTILINE), (
        "the entry-point example resolves to a module, not a class — the broker "
        "skips it with a warning and the adapter never registers"
    )


# ===========================================================================
# A12 -- four version strings, four answers
# ===========================================================================


def test_wa12_the_docs_agree_with_the_package_on_what_version_this_is() -> None:
    """A user reading the README must be told the version they will install."""
    import tomllib

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version: str = pyproject["project"]["version"]
    requires: str = pyproject["project"]["requires-python"]
    floor = requires.lstrip(">=")

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    index = (REPO_ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    guide = (REPO_ROOT / "docs" / "how-to" / "operator-guide.md").read_text(encoding="utf-8")

    assert f"**Current version:** {version}" in readme, "README states a different version"
    assert f"`nautilus-rkm` {version}" in index, "docs/index.md states a different version"
    for name, text in (("docs/index.md", index), ("operator-guide.md", guide)):
        found = re.findall(r"Python (\d+\.\d+)\+", text)
        assert all(v == floor for v in found), (
            f"{name} requires Python {found}, pyproject requires {requires}"
        )


# ===========================================================================
# A13 -- the curator isolation check does not run where it says it runs
# ===========================================================================


def test_wa13_rules_validate_rejects_a_curator_rule_that_writes_routing_facts(
    tmp_path: Path,
) -> None:
    """Module isolation is the control that keeps a self-proposing curator honest.

    ``assert_module_isolation``'s own docstring says it is wired into
    ``validate_static`` "so violations surface via ``nautilus rules validate``".
    It is not: it runs once at router construction against the shipped
    meta-ruleset, which ships ``rules: []``. A curator rule that asserts a
    routing-owned template passes the gate an author actually runs.
    """
    from nautilus.rkm.validator.static import validate_static

    rule = tmp_path / "curator-breach.yaml"
    rule.write_text(
        """
module: curator
ruleset: breach
version: "1.0"
rules:
  - name: curator-writes-routing-facts
    description: "A curator rule that asserts a routing-owned template."
    salience: 10
    when:
      - template: agent
        conditions:
          - slot: id
            bind: ?aid
    then:
      action: scope
      reason: "isolation breach"
      assert:
        - template: scope_constraint
          slots:
            source_id: "?aid"
            field: "classification"
            operator: "="
            value: "cui"
""",
        encoding="utf-8",
    )
    result = validate_static(rule)
    assert not result.ok, (
        "validate_static accepted a curator rule that writes a routing-owned "
        "template — the isolation check never runs on a file an author validates"
    )


# ===========================================================================
# A14 -- schema-ack cannot reach the broker it is acknowledging for
# ===========================================================================


def test_wa14_an_ack_written_by_another_process_is_seen_by_a_running_broker(
    tmp_path: Path,
) -> None:
    """``schema-ack`` runs in its own process; the quarantine it lifts is in another.

    The CLI writes the new baseline to disk and prints success. The serving
    broker's fingerprint store answers from its in-memory cache first, so
    ``_clear_quarantine_if_acked`` compares against the *old* fingerprint
    forever: the ADAPTER_QUARANTINED message tells the operator to run a command
    that cannot work until they restart.

    Two stores rooted at one directory are the same situation without the
    subprocess. The control is the first read, which must see the original
    baseline — otherwise the second read proves nothing.
    """
    from nautilus.adapters.schema import SchemaFingerprintStore

    serving = SchemaFingerprintStore(root=str(tmp_path))
    cli = SchemaFingerprintStore(root=str(tmp_path))

    serving.record("src", "fingerprint-v1")
    assert serving.get("src") == "fingerprint-v1"

    cli.record_ack("src", "fingerprint-v2", reviewer="alice", reason="column added")

    assert serving.get("src") == "fingerprint-v2", (
        "the running broker still reads the pre-ack baseline, so the quarantine the "
        "ack was supposed to lift stays up until restart"
    )
