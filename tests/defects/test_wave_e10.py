# pyright: reportPrivateUsage=false, reportUnknownLambdaType=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false
"""WAVE E10 — what an unrelated ``pip install`` can quietly take over.

Three majors, all about a name resolving to something the operator never chose.

1. **An entry point shadows a built-in adapter.** ``Broker.from_config`` builds
   its registry as ``{**ADAPTER_REGISTRY, **_discover_adapters(), ...}``, so an
   entry point in the ``nautilus.adapters`` group whose name collides with a
   built-in *overrides* it. Scope enforcement lives in the adapter — it is the
   adapter that pushes the predicate into the query — so a third-party package
   can take over the ``postgres`` source type and return rows the policy engine
   explicitly scoped out. Nothing shows it: discovery logs at DEBUG,
   ``nautilus adapters list`` still prints ``type=postgres status=configured``,
   the ruleset hash is unchanged, and the audit entry and its Ed25519
   attestation still record the scope constraint that was never enforced. The
   receipt says the control ran; the data says it did not.

2. **A distribution can win a shipped rule pack's name.** ``fathom``'s pack
   loader returns the first ``fathom.packs`` entry whose name matches, and
   entry points are ordered by distribution name — so any distribution sorting
   before ``nautilus-rkm`` deterministically wins. An operator who wrote
   ``rules: {packs: [data-routing-nist]}`` got a different pack's rules with no
   error and no warning; in the audit's run the NIST AC-6 least-privilege scope
   constraint vanished and the broker returned rows whose ``purpose`` was
   outside the requesting agent's ``allowed_purposes``.

3. **The shipped default is 39 WARNING/ERROR lines a minute, and the off-switch
   blinds the dashboards.** ``setup_otel`` runs unconditionally and builds
   ``OTLPSpanExporter()`` with no endpoint, which defaults to localhost:4318.
   Nothing listens there in the shipped manifest, so every span batch produces
   three WARNING retries plus an ERROR. The only documented off-switch,
   ``OTEL_SDK_DISABLED=true``, also removes the ``PrometheusMetricReader`` and
   takes ``/metrics`` from 89 series to 16 — every ``nautilus_*`` series with
   it, which is exactly what the Dockerfile says the otel extra is for. The
   operator had to pick between the noise and blind dashboards.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.integration]


class _Impostor:
    """A stand-in with the full Adapter protocol and none of the enforcement."""

    source_type = "postgres"

    async def connect(self, config: Any) -> None: ...
    async def execute(self, intent: Any, scope: Any, context: Any) -> Any: ...
    async def close(self) -> None: ...
    async def health_check(self) -> bool:
        return True

    async def schema(self) -> Any: ...


class _FakeEntryPoint:
    def __init__(self, name: str, obj: object, dist: str) -> None:
        self.name = name
        self.value = f"{dist}:{name}"
        self.obj = obj
        self.dist = type("Dist", (), {"name": dist})()

    def load(self) -> object:
        return self.obj


def _config(tmp_path: Path, **extra: Any) -> str:
    document: dict[str, Any] = {
        "sources": [
            {
                "id": "orders",
                "type": "static",
                "classification": "unclassified",
                "data_types": ["orders"],
                "rows": [{"id": 1}],
            }
        ],
        "agents": {"a1": {"id": "a1", "clearance": "unclassified"}},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
    }
    document.update(extra)
    path = tmp_path / "nautilus.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# 1. A plugin cannot take over a built-in source type.
# ---------------------------------------------------------------------------


def test_e10_an_entry_point_cannot_replace_a_built_in_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installing a package must not change what ``type: postgres`` means.

    The adapter is what pushes a scope predicate into the query, so replacing
    it removes the enforcement while every receipt still claims it ran.
    Replacing a built-in deliberately is what the ``adapters:`` config block is
    for — that path is explicit and an operator wrote it.
    """
    from nautilus.adapters import ADAPTER_REGISTRY
    from nautilus.core.broker import _discover_adapters

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **_: [_FakeEntryPoint("postgres", _Impostor, "totally-unrelated-pkg")],
    )
    discovered = _discover_adapters()

    assert "postgres" not in discovered, (
        f"an entry point from 'totally-unrelated-pkg' took over the built-in "
        f"'postgres' source type: {discovered['postgres']!r}. The built-in is "
        f"{ADAPTER_REGISTRY['postgres']!r}."
    )


def test_e10_a_shadowing_entry_point_is_logged_loudly(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Refusing it silently swaps one invisible outcome for another.

    The operator installed something that tried to replace a security control.
    That is worth a line naming the distribution.
    """
    import logging

    from nautilus.core.broker import _discover_adapters

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **_: [_FakeEntryPoint("postgres", _Impostor, "totally-unrelated-pkg")],
    )
    with caplog.at_level(logging.ERROR, logger="nautilus.core.broker"):
        _discover_adapters()

    assert any("totally-unrelated-pkg" in r.getMessage() for r in caplog.records), (
        f"nothing at ERROR named the distribution that tried to shadow a "
        f"built-in: {[r.getMessage() for r in caplog.records]}"
    )


def test_e10_a_new_source_type_from_an_entry_point_still_loads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: only collisions are refused, not third-party adapters.

    Entry-point discovery is a documented extension point. Without this pin,
    disabling discovery entirely would satisfy the two above.
    """
    from nautilus.core.broker import _discover_adapters

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **_: [_FakeEntryPoint("acme_warehouse", _Impostor, "acme-nautilus")],
    )
    discovered = _discover_adapters()

    assert discovered.get("acme_warehouse") is _Impostor, (
        f"a third-party source type was refused along with the shadowing ones: {discovered}"
    )


# ---------------------------------------------------------------------------
# 2. A rule pack name resolves to one distribution, or to an error.
# ---------------------------------------------------------------------------


class _FakePack:
    def __init__(self, name: str, dist: str) -> None:
        self.name = name
        self.value = f"{dist}.packs:{name}"
        self.dist = type("Dist", (), {"name": dist})()


def test_e10_two_distributions_claiming_one_pack_name_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """First-match on a shipped pack name is a silent policy substitution.

    Entry points are ordered by distribution name, so a package sorting before
    ``nautilus-rkm`` deterministically wins. The operator who wrote
    ``packs: [data-routing-nist]`` got someone else's rules, with no error and
    nothing anywhere saying the pack they named is not the pack they got --
    and in the audit's run the NIST least-privilege constraint simply vanished.
    """

    def _fake(**kwargs: Any) -> list[Any]:
        if kwargs.get("group") == "fathom.packs":
            return [
                _FakePack("data-routing-nist", "aaa-impostor"),
                _FakePack("data-routing-nist", "nautilus-rkm"),
            ]
        return list(importlib.metadata.entry_points(**kwargs))

    real = importlib.metadata.entry_points
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda **kw: _fake(**kw) if kw.get("group") == "fathom.packs" else real(**kw),
    )

    from nautilus.core.broker import Broker

    with pytest.raises(Exception, match="aaa-impostor"):
        broker = Broker.from_config(_config(tmp_path, rules={"packs": ["data-routing-nist"]}))
        broker.close()


def test_e10_one_distribution_claiming_a_pack_name_still_loads(tmp_path: Path) -> None:
    """Control: the shipped packs must keep loading.

    Only ``nautilus-rkm`` claims them in a normal install, and refusing that
    would satisfy the pin above by breaking every deployment that uses a pack.
    """
    from nautilus.core.broker import Broker

    broker = Broker.from_config(_config(tmp_path, rules={"packs": ["data-routing-nist"]}))
    try:
        assert broker.ruleset_hash
    finally:
        broker.close()


# ---------------------------------------------------------------------------
# The documented remedy has to work.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("extra", "present"),
    [
        ("postgres", ["asyncpg"]),
        ("pgvector", ["asyncpg", "pgvector"]),
        ("elasticsearch", ["elasticsearch"]),
        ("neo4j", ["neo4j"]),
        ("influxdb", ["influxdb_client"]),
        ("s3", ["aiobotocore"]),
    ],
)
def test_e10_every_driver_extra_yields_an_importable_install(
    extra: str, present: list[str]
) -> None:
    """``pip install 'nautilus-rkm[postgres]'`` then ``import nautilus``.

    Every place the project tells an operator how to fix a missing driver --
    the README, getting-started, the k8s manifest, the code's own error
    message -- names an extra. Of the six, only ``[pgvector]`` used to produce
    an importable install, because the broker imported
    ``nautilus.adapters.pgvector`` unguarded and the ``pgvector`` distribution
    is in no other extra. The documented remedy was as broken as the problem.

    Closed by the wave that guarded that import; this is the check that keeps
    it closed, run for every extra rather than the one that happened to work.
    """
    import subprocess
    import sys
    import tomllib

    repo_root = Path(__file__).resolve().parents[2]
    with (repo_root / "pyproject.toml").open("rb") as handle:
        extras = tomllib.load(handle)["project"]["optional-dependencies"]
    assert extra in extras, f"pyproject declares no [{extra}] extra"

    every_driver = {
        "aiobotocore",
        "asyncpg",
        "elasticsearch",
        "influxdb_client",
        "neo4j",
        "pgvector",
    }
    blocked = sorted(every_driver - set(present))
    program = (
        "import sys\n"
        f"BLOCKED = {blocked!r}\n"
        "class Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in BLOCKED:\n"
        '            raise ModuleNotFoundError("no driver")\n'
        "        return None\n"
        "sys.meta_path.insert(0, Block())\n"
        "import nautilus\n"
        "from nautilus.core.broker import Broker\n"
    )
    result = subprocess.run(  # noqa: S603 — this interpreter, a literal program
        [sys.executable, "-c", program],
        check=False,
        capture_output=True,
        cwd=str(repo_root),
        timeout=120,
    )
    assert result.returncode == 0, (
        f"an install with only {present} -- what [{extra}] gives you -- cannot "
        f"import nautilus:\n{result.stderr.decode('utf-8', errors='replace')}"
    )


# ---------------------------------------------------------------------------
# 3. Silent by default, and still instrumented.
# ---------------------------------------------------------------------------


def test_e10_no_span_exporter_without_an_endpoint_to_export_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exporter pointed at nothing retries three times and logs an ERROR.

    Under load that is 39 WARNING/ERROR lines a minute per replica, which trips
    any "alert on ERROR logs" rule and buries the broker's own diagnostics. The
    shipped manifest runs nothing at localhost:4318 and sets no endpoint.
    """
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace import TracerProvider

    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)

    added: list[Any] = []
    monkeypatch.setattr(TracerProvider, "add_span_processor", lambda self, p: added.append(p))

    from fastapi import FastAPI

    from nautilus.observability.instrumentation import setup

    setup(FastAPI(), "e10-test")

    assert added == [], f"a span processor was installed with no endpoint configured: {added}"


def test_e10_metrics_are_installed_even_with_no_tracing_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: silencing the exporter must not be ``OTEL_SDK_DISABLED`` again.

    That switch also drops the ``PrometheusMetricReader``, taking ``/metrics``
    from 89 series to 16 and every ``nautilus_*`` series with it -- which is
    what the Dockerfile says the otel extra exists to provide.
    """
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry import metrics
    from opentelemetry.sdk.metrics import MeterProvider

    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)

    from fastapi import FastAPI

    from nautilus.observability.instrumentation import setup

    setup(FastAPI(), "e10-test")

    assert isinstance(metrics.get_meter_provider(), MeterProvider), (
        "no MeterProvider was installed, so every nautilus_* metric is discarded"
    )


def test_e10_an_endpoint_turns_tracing_back_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: pointing at a collector must still export spans."""
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace import TracerProvider

    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.invalid:4318")

    added: list[Any] = []
    monkeypatch.setattr(TracerProvider, "add_span_processor", lambda self, p: added.append(p))

    from fastapi import FastAPI

    from nautilus.observability.instrumentation import setup

    setup(FastAPI(), "e10-test")

    assert added, "an explicit OTLP endpoint installed no span processor"
