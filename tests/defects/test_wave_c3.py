"""One pin per Wave C3 item — packaging and the surfaces other systems see.

C5 is the scaffold that generates a package which cannot be installed, C6 is
the MCP tool surface a model has to read to use Nautilus at all, C7 is the six
database drivers every install pays for, and C11 is the deployment manifest set
the operator guide describes but never ships.
"""

from __future__ import annotations

import asyncio
import tomllib
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

pytestmark = pytest.mark.defect

_TEMPLATE = Path("nautilus/templates/adapter/template")
_DEPLOY = Path("deploy")


# ===========================================================================
# C5 -- the scaffold generates a package that cannot be installed
# ===========================================================================


def test_c5_the_scaffolded_package_depends_on_something_that_exists() -> None:
    """``nautilus adapters new`` output declares ``nautilus-adapter-sdk``.

    That distribution is a 404 on PyPI, so the first thing the scaffold tells
    you to run — ``pip install -e ".[test]"`` — fails for everyone who is not
    working inside this repo's uv workspace.
    """
    pyproject = (_TEMPLATE / "pyproject.toml.jinja").read_text(encoding="utf-8")
    assert "nautilus-adapter-sdk" not in pyproject, (
        "the scaffold still depends on an unpublished distribution"
    )
    assert "nautilus-rkm" in pyproject, pyproject

    for rendered in _TEMPLATE.rglob("*.jinja"):
        assert "nautilus_adapter_sdk" not in rendered.read_text(encoding="utf-8"), (
            f"{rendered} imports a package the generated project cannot install"
        )


def test_c5_the_compliance_suite_the_scaffold_runs_ships_with_nautilus() -> None:
    """The scaffold's tests import a compliance suite from the unpublished SDK.

    Control: the suite has to actually pass against a real in-tree adapter, or
    repointing the import has only moved the failure.
    """
    from nautilus.adapters import StaticAdapter
    from nautilus.adapters.testing import AdapterComplianceSuite
    from nautilus.config.models import SourceConfig

    suite = AdapterComplianceSuite(
        adapter_factory=StaticAdapter,
        source_config=SourceConfig(
            id="test-static",
            type="static",
            classification="unclassified",
            data_types=["generic"],
            rows=[{"id": "test", "name": "alpha"}],
        ),
    )

    async def _run() -> None:
        await suite.test_connect_execute_close_lifecycle()
        await suite.test_scope_enforcement_valid_operator()
        await suite.test_scope_enforcement_invalid_operator()
        await suite.test_idempotent_close()
        await suite.test_error_path_reports_the_failure()

    asyncio.run(_run())


# ===========================================================================
# C6 -- the MCP surface a model has to read
# ===========================================================================


def _tools(tmp_path: Path) -> dict[str, Any]:
    import yaml as _yaml

    from nautilus.transport.mcp_server import create_server

    config = tmp_path / "nautilus.yaml"
    config.write_text(
        _yaml.safe_dump(
            {
                "sources": [
                    {
                        "id": "orders",
                        "type": "static",
                        "description": "sample orders",
                        "classification": "unclassified",
                        "data_types": ["orders"],
                        "rows": [{"order_id": 1001}],
                    }
                ],
                "agents": {"agent-alpha": {"id": "agent-alpha", "clearance": "unclassified"}},
                "audit": {"path": str(tmp_path / "audit.jsonl")},
            }
        ),
        encoding="utf-8",
    )
    server = create_server(str(config))
    tools = asyncio.run(server.list_tools())
    return {tool.name: tool for tool in tools}


def test_c6_the_request_tool_says_what_to_put_in_context(tmp_path: Path) -> None:
    """The description a model reads is a Sphinx cross-reference to a private function.

    ``context`` is where purpose and session live — the inputs the policy
    engine decides on — and it is documented nowhere the client can see.
    """
    tool = _tools(tmp_path)["nautilus_request"]
    description = (tool.description or "").lower()

    assert ":meth:" not in description and ":func:" not in description, (
        f"the tool description is written for Sphinx, not for a model:\n{tool.description}"
    )
    assert "purpose" in description, tool.description
    schema = tool.inputSchema["properties"]["context"]
    assert schema.get("description"), f"the context argument has no description: {schema}"


def test_c6_a_client_can_ask_what_sources_exist(tmp_path: Path) -> None:
    """An MCP client has no way to discover what it may ask for.

    ``GET /v1/sources`` answers exactly this for REST callers; the MCP surface
    has one tool that queries and one that declares a handoff.
    """
    tools = _tools(tmp_path)
    assert "nautilus_sources" in tools, sorted(tools)

    listing = asyncio.run(_call_sources(tmp_path))
    assert listing, "the sources tool returned nothing"
    first = listing[0]
    assert first["id"] == "orders"
    assert set(first) >= {"id", "type", "classification", "data_types"}, first
    assert "connection" not in first, "the sources tool leaks the connection string"


async def _call_sources(tmp_path: Path) -> list[dict[str, Any]]:
    import json

    import yaml as _yaml

    from nautilus.transport.mcp_server import create_server

    config = tmp_path / "mcp.yaml"
    config.write_text(
        _yaml.safe_dump(
            {
                "sources": [
                    {
                        "id": "orders",
                        "type": "static",
                        "description": "sample orders",
                        "classification": "unclassified",
                        "data_types": ["orders"],
                        "rows": [{"order_id": 1001}],
                    }
                ],
                "audit": {"path": str(tmp_path / "audit.jsonl")},
            }
        ),
        encoding="utf-8",
    )
    server = create_server(str(config))
    result = await server.call_tool("nautilus_sources", {})
    payload: Any = result[1] if isinstance(result, tuple) else result
    if isinstance(payload, dict) and "result" in payload:
        payload = cast("dict[str, Any]", payload)["result"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return cast("list[dict[str, Any]]", list(cast("list[Any]", payload)))


# ===========================================================================
# C7 -- six drivers every install pays for
# ===========================================================================

_DRIVERS = {
    "asyncpg": "postgres",
    "pgvector": "pgvector",
    "elasticsearch": "elasticsearch",
    "neo4j": "neo4j",
    "influxdb-client": "influxdb",
    "aiobotocore": "s3",
}


def test_c7_the_database_drivers_are_optional_extras() -> None:
    """Six drivers are pinned unconditionally — roughly 60 MB of a 133 MB install.

    A user brokering a REST source pays for Postgres, Elasticsearch, Neo4j,
    InfluxDB and S3 clients they will never import.
    """
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    core = " ".join(project["dependencies"])
    extras = project["optional-dependencies"]

    for driver, extra in _DRIVERS.items():
        assert driver not in core, f"{driver} is still an unconditional dependency"
        assert extra in extras, f"no '{extra}' extra to install {driver} with"
        assert any(driver in dep for dep in extras[extra]), extras[extra]

    assert "all" in extras, "there is no way to ask for everything in one go"
    all_deps = " ".join(extras["all"])
    for driver in _DRIVERS:
        assert driver in all_deps, f"[all] does not cover {driver}"


def test_c7_a_source_whose_driver_is_missing_names_the_extra_to_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An extras split that fails with ``ModuleNotFoundError: asyncpg`` helps nobody."""
    import nautilus.core.broker as broker_mod
    from nautilus.adapters import missing_driver_adapter
    from nautilus.config.loader import ConfigError

    monkeypatch.setitem(
        broker_mod.ADAPTER_REGISTRY,
        "postgres",
        missing_driver_adapter("postgres", "postgres", ImportError("no module named asyncpg")),
    )
    config = tmp_path / "nautilus.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "sources": [
                    {
                        "id": "db",
                        "type": "postgres",
                        "classification": "unclassified",
                        "data_types": ["orders"],
                        "connection": "postgresql://127.0.0.1:1/none",
                        "table": "public.t",
                    }
                ],
                "audit": {"path": str(tmp_path / "audit.jsonl")},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=r"nautilus-rkm\[postgres\]"):
        broker_mod.Broker.from_config(config)


# ===========================================================================
# C11 -- no deployment manifests
# ===========================================================================


def test_c11_the_repo_ships_a_kubernetes_example() -> None:
    """Every deployment claim in the operator guide is prose."""
    assert _DEPLOY.is_dir(), "there is no deploy/ directory"
    docs = list(_DEPLOY.glob("*.yaml"))
    assert docs, "deploy/ has no manifests"

    kinds: dict[str, dict[str, Any]] = {}
    for path in docs:
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if doc:
                kinds[doc["kind"]] = doc
    assert {"Deployment", "Service", "ConfigMap", "Secret"} <= set(kinds), sorted(kinds)


def test_c11_the_deployment_probes_and_secrets_are_wired_the_way_the_docs_say() -> None:
    """Manifests that do not probe or that inline the API key are worse than none."""
    kinds: dict[str, dict[str, Any]] = {}
    for path in _DEPLOY.glob("*.yaml"):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if doc:
                kinds[doc["kind"]] = doc

    container = kinds["Deployment"]["spec"]["template"]["spec"]["containers"][0]
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz", container
    assert container["readinessProbe"]["httpGet"]["path"] == "/readyz", container

    rendered = " ".join(path.read_text(encoding="utf-8") for path in sorted(_DEPLOY.glob("*.yaml")))
    assert "secretKeyRef" in rendered or "secretName" in rendered, (
        "the API key is not read from the Secret"
    )
    # Nothing in the ConfigMap may be a credential: every field that carries
    # one has to be an ${ENV} reference resolved from the Secret at load.
    broker_config = yaml.safe_load(kinds["ConfigMap"]["data"]["nautilus.yaml"])
    secrets: list[str] = [
        *(source.get("connection", "") for source in broker_config.get("sources", [])),
        *broker_config.get("api", {}).get("keys", []),
        broker_config.get("session_store", {}).get("dsn", ""),
    ]
    for value in secrets:
        assert value.startswith("${") and value.endswith("}"), (
            f"the ConfigMap carries a literal credential: {value!r}"
        )
