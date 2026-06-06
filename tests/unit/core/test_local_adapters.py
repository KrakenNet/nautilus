"""Unit tests for local-path adapter loading + entry-point discovery (#17)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from nautilus.adapters.influxdb import InfluxDBAdapter
from nautilus.adapters.s3 import S3Adapter
from nautilus.config.loader import ConfigError, load_config
from nautilus.config.models import LocalAdapterConfig
from nautilus.core.broker import (
    Broker,
    _adapter_protocol_gaps,  # pyright: ignore[reportPrivateUsage]
    _discover_adapters,  # pyright: ignore[reportPrivateUsage]
    _load_local_adapters,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.unit

_ADAPTER_MODULE = '''\
"""Single-file local adapter used by tests (#17)."""

from __future__ import annotations

from typing import Any, ClassVar

from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint


class DemoLocalAdapter:
    source_type: ClassVar[str] = "demo-local"

    def __init__(self) -> None:
        self._connected = False

    async def connect(self, config: SourceConfig) -> None:
        self._connected = True

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        return AdapterResult(
            source_id="local_rows",
            rows=[{"id": 1, "cve": "CVE-1"}],
            duration_ms=0,
        )

    async def close(self) -> None:
        self._connected = False


NOT_A_CLASS = "just a string"


class NotAnAdapter:
    source_type: ClassVar[str] = "demo-local"
'''


def _write_module(tmp_path: Path, name: str = "demo_local_adapter.py") -> Path:
    path = tmp_path / name
    path.write_text(_ADAPTER_MODULE, encoding="utf-8")
    return path


def _entry(
    module_path: str,
    *,
    class_name: str = "DemoLocalAdapter",
    source_type: str = "demo-local",
) -> LocalAdapterConfig:
    return LocalAdapterConfig.model_validate(
        {"module_path": module_path, "class": class_name, "source_type": source_type}
    )


# ---------------------------------------------------------------------------
# _load_local_adapters
# ---------------------------------------------------------------------------


def test_loads_adapter_class_from_absolute_path(tmp_path: Path) -> None:
    module = _write_module(tmp_path)
    loaded = _load_local_adapters([_entry(str(module))], base_dir=tmp_path)
    assert set(loaded) == {"demo-local"}
    assert loaded["demo-local"].__name__ == "DemoLocalAdapter"


def test_relative_path_resolves_against_base_dir(tmp_path: Path) -> None:
    _write_module(tmp_path)
    loaded = _load_local_adapters([_entry("demo_local_adapter.py")], base_dir=tmp_path)
    assert set(loaded) == {"demo-local"}


def test_missing_module_path_raises_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="does not exist"):
        _load_local_adapters([_entry("nope.py")], base_dir=tmp_path)


def test_missing_class_raises_config_error(tmp_path: Path) -> None:
    module = _write_module(tmp_path)
    with pytest.raises(ConfigError, match="not found"):
        _load_local_adapters([_entry(str(module), class_name="Missing")], base_dir=tmp_path)


def test_non_class_attribute_raises_config_error(tmp_path: Path) -> None:
    module = _write_module(tmp_path)
    with pytest.raises(ConfigError, match="not a class"):
        _load_local_adapters([_entry(str(module), class_name="NOT_A_CLASS")], base_dir=tmp_path)


def test_protocol_gaps_raise_config_error(tmp_path: Path) -> None:
    module = _write_module(tmp_path)
    with pytest.raises(ConfigError, match="Adapter protocol"):
        _load_local_adapters([_entry(str(module), class_name="NotAnAdapter")], base_dir=tmp_path)


def test_source_type_mismatch_raises_config_error(tmp_path: Path) -> None:
    module = _write_module(tmp_path)
    with pytest.raises(ConfigError, match="does not match"):
        _load_local_adapters([_entry(str(module), source_type="other")], base_dir=tmp_path)


def test_broken_module_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "broken.py"
    bad.write_text("raise RuntimeError('boom at import')\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="error executing"):
        _load_local_adapters([_entry(str(bad))], base_dir=tmp_path)


def test_failure_rolls_back_all_sys_modules_entries(tmp_path: Path) -> None:
    """A later entry's failure must not leave earlier modules in sys.modules."""
    import sys

    good = _write_module(tmp_path)
    with pytest.raises(ConfigError, match="does not exist"):
        _load_local_adapters([_entry(str(good)), _entry("nope.py")], base_dir=tmp_path)
    assert "nautilus_local_adapter_0_demo_local_adapter" not in sys.modules


# ---------------------------------------------------------------------------
# _adapter_protocol_gaps + entry-point discovery regression
# ---------------------------------------------------------------------------


def test_adapter_protocol_gaps_on_builtin_is_empty() -> None:
    assert _adapter_protocol_gaps(S3Adapter) == []


def test_adapter_protocol_gaps_reports_missing_members() -> None:
    class Empty:
        pass

    assert _adapter_protocol_gaps(Empty) == ["connect", "execute", "close", "source_type"]


def test_discover_adapters_finds_own_entry_points() -> None:
    """Regression: issubclass() on the runtime_checkable Adapter protocol
    raised TypeError, silently skipping every entry-point adapter."""
    discovered = _discover_adapters()
    assert discovered.get("s3") is S3Adapter
    assert discovered.get("influxdb") is InfluxDBAdapter


# ---------------------------------------------------------------------------
# load_config: source type extension
# ---------------------------------------------------------------------------

_CONFIG_TEMPLATE = """\
sources:
  - id: local_rows
    type: demo-local
    description: "Local-path adapter source (test)"
    classification: unclassified
    data_types: [vulnerability]
    allowed_purposes: [threat-analysis]
    connection: "memory://"

{adapters_block}
rules:
  user_rules_dirs: []

analysis:
  keyword_map:
    vulnerability: [vulnerability, vuln]

audit:
  path: {audit_path}

attestation:
  enabled: true
"""


def _write_config(tmp_path: Path, *, with_adapters: bool = True) -> Path:
    adapters_block = (
        "adapters:\n"
        "  - module_path: ./demo_local_adapter.py\n"
        "    class: DemoLocalAdapter\n"
        "    source_type: demo-local\n"
        if with_adapters
        else ""
    )
    config = tmp_path / "nautilus.yaml"
    config.write_text(
        _CONFIG_TEMPLATE.format(
            adapters_block=adapters_block,
            audit_path=str(tmp_path / "audit.jsonl"),
        ),
        encoding="utf-8",
    )
    return config


def test_load_config_accepts_declared_local_source_type(tmp_path: Path) -> None:
    _write_module(tmp_path)
    config = load_config(_write_config(tmp_path))
    assert config.sources[0].type == "demo-local"
    assert config.adapters[0].class_name == "DemoLocalAdapter"


def test_load_config_rejects_undeclared_source_type(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Unsupported source type"):
        load_config(_write_config(tmp_path, with_adapters=False))


# ---------------------------------------------------------------------------
# Broker end-to-end: local adapter serves a request
# ---------------------------------------------------------------------------


async def test_broker_serves_request_through_local_adapter(tmp_path: Path) -> None:
    _write_module(tmp_path)
    broker = Broker.from_config(_write_config(tmp_path))
    try:
        adapter = broker._adapters["local_rows"]  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        assert type(adapter).__name__ == "DemoLocalAdapter"

        context: dict[str, Any] = {
            "clearance": "unclassified",
            "purpose": "threat-analysis",
            "session_id": "s1",
        }
        resp = await broker.arequest("agent-alpha", "vulnerability scan", context)
        assert "local_rows" in resp.sources_queried
        assert resp.data["local_rows"] == [{"id": 1, "cve": "CVE-1"}]
    finally:
        await broker.aclose()
