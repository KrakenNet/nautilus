"""WAVE ops12 — a running instance could not say which build it was.

A sealed 12-goal-state operator trial failed the goal state *"instances say
which build they are, and the answer tracks the build not the run"*. Four
separate things were wrong at once:

* The only network-readable build stamp was the ``GET /`` JSON index, which
  exists on no released build (0.2.0/0.2.1/0.2.5 answer ``/`` with a ``302`` to
  the credentialed ``/admin``), so a ``curl -L`` lands on ``401``.
* ``GET /openapi.json`` reported ``info.version`` ``"0.1.0"`` — the literal
  FastAPI's ``version=`` defaults to, naming no build that ever existed.
* ``/metrics`` published ``target_info`` with no ``service_version``.
* ``nautilus.__version__`` was a second hand-maintained literal beside
  ``[project] version`` in ``pyproject.toml``. Two sources, one of which had
  already drifted once (0.1.4 shipped needing a re-sync commit).

The fix picks ``GET /healthz`` as the credential-free build surface — it has no
optional dependency (``/metrics`` needs the ``otel`` extra for both
``prometheus_client`` and ``target_info``) and no off-switch
(``OTEL_SDK_DISABLED=true`` erases ``target_info``) — and makes every reported
version derive from the installed distribution's metadata.
"""

from __future__ import annotations

from importlib.metadata import version as distribution_version
from typing import TYPE_CHECKING, Any

import pytest
import yaml
from fastapi.testclient import TestClient

from nautilus import __version__
from nautilus.build import build_rev
from nautilus.transport.fastapi_app import create_app

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = [pytest.mark.integration]


def _config(path: Path, *, ui_enabled: bool = False) -> str:
    document: dict[str, Any] = {
        "sources": [
            {
                "id": "orders",
                "type": "static",
                "description": "order rows",
                "classification": "unclassified",
                "data_types": ["orders"],
                "rows": [{"order_id": 1}],
            }
        ],
        "agents": {"analyst": {"id": "analyst", "clearance": "unclassified"}},
        "audit": {"path": str(path / "audit.jsonl")},
        "api": {"keys": ["secret-key"]},
        "ui": {"enabled": ui_enabled},
    }
    config = path / "nautilus.yaml"
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(config)


def test_version_has_exactly_one_source() -> None:
    """``__version__`` is read back from the distribution, not typed twice."""
    assert __version__ == distribution_version("nautilus-rkm")


def test_healthz_names_the_build_without_a_credential(tmp_path: Path) -> None:
    """The pin. No API key, no otel extra, no config — still an answer.

    ``build`` joined ``version`` here later: a version is shared by every commit
    between two releases, so it cannot tell two builds of one release line
    apart. See ``test_wave_ops12_build_identity.py`` for that half.
    """
    with TestClient(create_app(_config(tmp_path))) as client:
        response = client.get("/healthz")  # note: no X-API-Key
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__, "build": build_rev()}


def test_openapi_info_version_is_the_build_not_fastapis_default(tmp_path: Path) -> None:
    """``0.1.0`` is what ``FastAPI(version=...)`` defaults to; it named no build."""
    with TestClient(create_app(_config(tmp_path, ui_enabled=True))) as client:
        response = client.get("/openapi.json")
    assert response.status_code == 200, "released builds 500 here; this one must not"
    assert response.json()["info"]["version"] == __version__


def test_metrics_is_an_optional_extra_so_healthz_carries_the_build() -> None:
    """Why ``/healthz`` and not ``/metrics``, pinned so the reason cannot rot.

    ``rest-api.md`` now documents ``GET /metrics`` as ``500`` without the
    ``otel`` extra, and ``/healthz`` as the surface that always answers. If
    ``prometheus_client`` ever becomes a base dependency, that paragraph is
    wrong and this fails.
    """
    import tomllib
    from pathlib import Path as _Path

    root = _Path(__file__).resolve().parents[2]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    base = " ".join(pyproject["project"]["dependencies"])
    otel = " ".join(pyproject["project"]["optional-dependencies"]["otel"])

    assert "prometheus" not in base, (
        "prometheus_client is now a base dependency; GET /metrics no longer 500s "
        "without the otel extra and rest-api.md says it does"
    )
    assert "prometheus-client" in otel


def test_every_uncredentialed_version_surface_agrees(tmp_path: Path) -> None:
    """One build, one string. A disagreement means a stale literal came back."""
    with TestClient(create_app(_config(tmp_path))) as client:
        healthz = client.get("/healthz").json()["version"]
        openapi = client.get("/openapi.json").json()["info"]["version"]
        root = client.get("/").json()["version"]
    assert healthz == openapi == root == distribution_version("nautilus-rkm")
