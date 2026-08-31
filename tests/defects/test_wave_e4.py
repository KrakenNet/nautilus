"""WAVE E4 — the package a stranger installs is not the one CI tests.

Every finding here was reproduced first-hand before a line of fix was written.

1. ``import nautilus`` fails outright without the optional Postgres driver::

       File "nautilus/core/broker.py", line 47, in <module>
         from nautilus.adapters.pgvector import PgVectorAdapter
       ModuleNotFoundError: No module named 'asyncpg'

   Three lines below that import, ``_build_adapter`` already handles a missing
   driver properly: ``nautilus.adapters`` keeps a stand-in in
   ``ADAPTER_REGISTRY`` for every optional adapter and the broker turns it into
   a ConfigError naming the extra. The top-level import bypasses all of it.

2. ``uv.lock`` still records the six driver extras as *required* dependencies
   of ``nautilus-rkm``. pyproject moved them to
   ``[project.optional-dependencies]`` — its own comment says "six of them
   accounted for roughly 60 MB of a 133 MB install" — and the lockfile was
   never regenerated. So CI, which installs ``--frozen``, tests with every
   driver present, which is why nobody hit (1); and the runtime image carries
   about 112 MB of drivers it was never asked for.

3. ``session_store.backend: redis`` is accepted, silently falls back to
   in-memory, and reports nothing::

       backend: redis -> InMemorySessionStore

   Cumulative exposure is what escalation rules read. An operator who
   configured a shared store and got a per-process one has replicas that each
   see a fraction of a caller's history, and no signal that this is happening.

4. ``mcp>=1.12`` is uncapped and mcp 2.1.1 is what a fresh install resolves
   to. 2.x renamed the class and moved the module, so the MCP transport dies
   on import::

       ModuleNotFoundError: No module named 'mcp.server.fastmcp'. This is
       mcp 2.x, where FastMCP was renamed to MCPServer …

   It is not a rename a shim can absorb: ``MCPServer.__init__`` takes neither
   ``stateless_http`` nor ``json_response`` and accepts no ``**kwargs``, and
   ``Context`` takes two type parameters rather than three. Supporting 2.x is
   a port. Until it is done the range has to exclude what does not work.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]

_REPO_ROOT = Path(__file__).resolve().parents[2]
# The extras a lean install must not drag in — one per driver-backed adapter.
_DRIVER_EXTRAS = {
    "aiobotocore",
    "asyncpg",
    "elasticsearch",
    "influxdb-client",
    "neo4j",
    "pgvector",
}


def _pyproject() -> dict[str, Any]:
    with (_REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def _locked_required_dependencies() -> set[str]:
    """Names ``uv.lock`` records as required for the root package."""
    with (_REPO_ROOT / "uv.lock").open("rb") as handle:
        lock = tomllib.load(handle)
    for package in lock.get("package", []):
        if package.get("name") == "nautilus-rkm":
            deps = package.get("dependencies", [])
            return {str(d["name"]) for d in deps}
    pytest.fail("uv.lock has no entry for nautilus-rkm")


# ---------------------------------------------------------------------------
# The lean install.
# ---------------------------------------------------------------------------


def test_e4_the_package_imports_without_the_optional_drivers() -> None:
    """``pip install nautilus-rkm`` then ``import nautilus`` must work.

    Run in a subprocess with the drivers hidden rather than by uninstalling
    them: the point is what a lean install does, and this suite's own venv is
    not one.
    """
    program = (
        "import sys\n"
        "class Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in {'asyncpg', 'pgvector'}:\n"
        "            raise ModuleNotFoundError(f'No module named {name!r}')\n"
        "        return None\n"
        "sys.meta_path.insert(0, Block())\n"
        "import nautilus\n"
        "from nautilus.core.broker import Broker\n"
        "print('ok')\n"
    )
    result = subprocess.run(  # noqa: S603 — this interpreter, a literal program
        [sys.executable, "-c", program],
        check=False,
        capture_output=True,
        cwd=str(_REPO_ROOT),
        timeout=120,
    )
    assert result.returncode == 0, (
        f"importing nautilus without the optional drivers failed:\n"
        f"{result.stderr.decode('utf-8', errors='replace')}"
    )


def test_e4_the_lockfile_agrees_with_the_declared_dependencies() -> None:
    """The lock is what CI and the image install; it must match pyproject.

    A lock that still requires the drivers means CI never once ran the lean
    install it ships, and the image carries every driver anyway.
    """
    declared = {
        # "uvicorn[standard]>=0.30" → "uvicorn"; PEP 508 name is up to the
        # first of the extras bracket or a version specifier.
        _requirement_name(spec)
        for spec in _pyproject()["project"]["dependencies"]
    }
    locked = _locked_required_dependencies()
    strays = locked - declared
    assert not strays, (
        f"uv.lock requires {sorted(strays)} for nautilus-rkm, which pyproject "
        f"declares as optional extras. Run `uv lock` — until then --frozen "
        f"installs them for everyone."
    )
    assert not (declared - locked), (
        f"uv.lock is missing declared dependencies {sorted(declared - locked)}"
    )


def _requirement_name(spec: str) -> str:
    """The bare distribution name from a PEP 508 requirement string."""
    for stop in "[<>=!~; ":
        spec = spec.split(stop)[0]
    return spec.strip().lower()


def test_e4_no_driver_extra_is_a_required_dependency() -> None:
    """Control: the six drivers stay optional in pyproject too.

    Without this, regenerating the lock to match a pyproject that had quietly
    re-required them would also pass.
    """
    declared = {_requirement_name(s) for s in _pyproject()["project"]["dependencies"]}
    assert not (declared & _DRIVER_EXTRAS), (
        f"pyproject requires driver extras {sorted(declared & _DRIVER_EXTRAS)}; "
        f"they belong in [project.optional-dependencies]"
    )


# ---------------------------------------------------------------------------
# Config that is accepted must be config that is honoured.
# ---------------------------------------------------------------------------


def test_e4_a_redis_session_store_is_refused_not_ignored(tmp_path: Path) -> None:
    """``backend: redis`` has no implementation, so it must not load.

    Falling back to in-memory gives an operator who asked for a store shared
    across replicas one that is per-process, and says nothing. Cumulative
    exposure is what escalation rules read, so each replica sees a fraction of
    a caller's history and every rule keyed on it under-fires.
    """
    from nautilus.core.broker import Broker

    document: dict[str, Any] = {
        "sources": [
            {
                "id": "s",
                "type": "static",
                "classification": "unclassified",
                "data_types": ["x"],
                "rows": [{"id": 1}],
            }
        ],
        "agents": {"a1": {"id": "a1", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "session_store": {"backend": "redis"},
    }
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    with pytest.raises(Exception, match="(?i)redis"):
        broker = Broker.from_config(str(path))
        broker.close()


def test_e4_the_supported_backends_still_load(tmp_path: Path) -> None:
    """Control: refusing redis must not refuse the backends that do exist."""
    from nautilus.core.broker import Broker

    document: dict[str, Any] = {
        "sources": [
            {
                "id": "s",
                "type": "static",
                "classification": "unclassified",
                "data_types": ["x"],
                "rows": [{"id": 1}],
            }
        ],
        "agents": {"a1": {"id": "a1", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
        "session_store": {"backend": "sqlite", "sqlite_path": str(tmp_path / "s.db")},
    }
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    broker = Broker.from_config(str(path))
    try:
        assert type(broker.session_store).__name__ == "SqliteSessionStore"
    finally:
        broker.close()


# ---------------------------------------------------------------------------
# The MCP dependency range.
# ---------------------------------------------------------------------------


def test_e4_the_mcp_range_excludes_the_2x_rename() -> None:
    """A fresh install must not resolve to an mcp the transport cannot import.

    Measured against mcp 2.1.1: ``mcp.server.fastmcp`` is gone,
    ``MCPServer.__init__`` accepts neither ``stateless_http`` nor
    ``json_response`` and takes no ``**kwargs``, and ``Context`` is generic
    over two parameters rather than three. That is a port, not a shim, so
    until it is done the range must exclude it.
    """
    from packaging.requirements import Requirement
    from packaging.version import Version

    specs = [
        Requirement(s)
        for s in _pyproject()["project"]["dependencies"]
        if _requirement_name(s) == "mcp"
    ]
    assert specs, "pyproject no longer declares mcp"
    assert not specs[0].specifier.contains(Version("2.1.1")), (
        f"mcp specifier {str(specs[0].specifier)!r} admits 2.1.1, where "
        f"mcp.server.fastmcp does not exist and the MCP transport dies on import"
    )
    assert specs[0].specifier.contains(Version("1.27.0")), (
        f"mcp specifier {str(specs[0].specifier)!r} excludes the 1.x line the "
        f"transport is written against"
    )
