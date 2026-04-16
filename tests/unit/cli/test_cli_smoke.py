"""Smoke tests for :mod:`nautilus.cli` (VERIFY 2.19 coverage gate).

Monkey-patched: never binds a real socket, never calls real uvicorn or
the real Broker. Covers ``version``, ``health``, and ``serve`` branches
including ``--air-gapped`` override emission and ``--bind`` host/port
splitting.
"""
# pyright: reportPrivateUsage=false, reportUnknownLambdaType=false, reportUnknownArgumentType=false

from __future__ import annotations

import argparse
import urllib.error
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from nautilus import cli

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def _make_fake_broker() -> MagicMock:
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()
    return broker


def _patch_broker_factory(
    monkeypatch: pytest.MonkeyPatch,
    *,
    raises: Exception | None = None,
) -> MagicMock:
    broker = _make_fake_broker()

    def fake_from_config(path: Any) -> Any:
        if raises is not None:
            raise raises
        return broker

    from nautilus.core import broker as broker_mod

    monkeypatch.setattr(
        broker_mod.Broker,
        "from_config",
        classmethod(lambda _cls, _p: fake_from_config(_p)),
    )
    return broker


# ---------------------------------------------------------------------------
# top-level dispatch / version / health
# ---------------------------------------------------------------------------


def test_main_no_args_fails() -> None:
    """argparse ``required=True`` rejects bare invocation."""
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code != 0


def test_main_unknown_subcommand_fails() -> None:
    with pytest.raises(SystemExit):
        cli.main(["bogus"])


def test_version_prints_package_version(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli.metadata, "version", lambda _name: "9.9.9")
    rc = cli.main(["version"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out == "9.9.9"


def test_version_handles_missing_package(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def _raise(_name: str) -> str:
        raise cli.metadata.PackageNotFoundError("nautilus")

    monkeypatch.setattr(cli.metadata, "version", _raise)
    rc = cli.main(["version"])
    assert rc == 1
    assert "version unknown" in capsys.readouterr().err


def test_health_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli.urllib.request,
        "urlopen",
        lambda *_a, **_kw: _FakeResponse(200),
    )
    rc = cli.main(["health", "--url", "http://x/readyz"])
    assert rc == 0
    assert "OK 200" in capsys.readouterr().out


def test_health_non_200(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli.urllib.request,
        "urlopen",
        lambda *_a, **_kw: _FakeResponse(503),
    )
    rc = cli.main(["health", "--url", "http://x/readyz"])
    assert rc == 1
    assert "FAIL 503" in capsys.readouterr().err


def test_health_http_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def _raise(*_a: Any, **_kw: Any) -> None:
        raise urllib.error.HTTPError("http://x", 500, "boom", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(cli.urllib.request, "urlopen", _raise)
    rc = cli.main(["health", "--url", "http://x/readyz"])
    assert rc == 1
    assert "FAIL 500" in capsys.readouterr().err


def test_health_unreachable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def _raise(*_a: Any, **_kw: Any) -> None:
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(cli.urllib.request, "urlopen", _raise)
    rc = cli.main(["health", "--url", "http://127.0.0.1:0/readyz"])
    assert rc == 1
    assert "unreachable" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# _split_bind
# ---------------------------------------------------------------------------


def test_split_bind_valid() -> None:
    host, port = cli._split_bind("0.0.0.0:1234")
    assert host == "0.0.0.0"
    assert port == 1234


def test_split_bind_missing_colon_raises() -> None:
    with pytest.raises(ValueError, match="HOST:PORT"):
        cli._split_bind("nocolon")


def test_split_bind_empty_host_raises() -> None:
    with pytest.raises(ValueError, match="HOST:PORT"):
        cli._split_bind(":9999")


def test_split_bind_non_integer_port_raises() -> None:
    with pytest.raises(ValueError, match="integer"):
        cli._split_bind("host:abc")


# ---------------------------------------------------------------------------
# _enforce_air_gap
# ---------------------------------------------------------------------------


def test_enforce_air_gap_overrides_llm_mode(
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw: dict[str, Any] = {
        "analysis": {
            "mode": "llm",
            "provider": {"type": "openai", "model": "gpt-4"},
        },
    }
    out = cli._enforce_air_gap(raw)
    err = capsys.readouterr().err
    assert out["analysis"]["mode"] == "pattern"
    assert out["analysis"]["provider"] is None
    assert "--air-gapped overrides analysis.mode" in err
    assert "--air-gapped refuses analysis.provider" in err


def test_enforce_air_gap_noop_on_pattern_config(
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw: dict[str, Any] = {"analysis": {"mode": "pattern"}}
    out = cli._enforce_air_gap(raw)
    assert out["analysis"]["mode"] == "pattern"
    assert capsys.readouterr().err == ""


def test_enforce_air_gap_handles_missing_analysis_block(
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw: dict[str, Any] = {}
    out = cli._enforce_air_gap(raw)
    # Creates an empty analysis block; no WARN because default mode is 'pattern'.
    assert out["analysis"] == {}
    assert capsys.readouterr().err == ""


def test_enforce_air_gap_non_dict_provider_emits_warn(
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw: dict[str, Any] = {"analysis": {"mode": "pattern", "provider": "oops-string"}}
    out = cli._enforce_air_gap(raw)
    assert out["analysis"]["provider"] is None
    assert "refuses analysis.provider" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# _load_config_for_serve
# ---------------------------------------------------------------------------


def test_load_config_for_serve_no_air_gap_is_passthrough(tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("analysis: {mode: pattern}\n", encoding="utf-8")
    assert cli._load_config_for_serve(cfg, air_gapped=False) == cfg


def test_load_config_for_serve_rewrites_llm_config(tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        yaml.safe_dump({"analysis": {"mode": "llm", "provider": {"type": "openai"}}}),
        encoding="utf-8",
    )
    out_path = cli._load_config_for_serve(cfg, air_gapped=True)
    # Rewritten to a new temp file.
    assert out_path != cfg
    new_raw = yaml.safe_load(Path(out_path).read_text(encoding="utf-8"))
    assert new_raw["analysis"]["mode"] == "pattern"
    assert new_raw["analysis"]["provider"] is None


def test_load_config_for_serve_passthrough_when_already_pattern(
    tmp_path: Path,
) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        yaml.safe_dump({"analysis": {"mode": "pattern"}}),
        encoding="utf-8",
    )
    # Already conformant → returned unchanged.
    assert cli._load_config_for_serve(cfg, air_gapped=True) == cfg


def test_load_config_for_serve_non_dict_yaml_returns_original(
    tmp_path: Path,
) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("just a string\n", encoding="utf-8")
    assert cli._load_config_for_serve(cfg, air_gapped=True) == cfg


def test_load_config_for_serve_unreadable_raises(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="Unable to read config"):
        cli._load_config_for_serve(tmp_path / "does-not-exist.yaml", air_gapped=True)


# ---------------------------------------------------------------------------
# serve — error paths (no real network)
# ---------------------------------------------------------------------------


def test_serve_missing_config_returns_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli.main(["serve", "--config", "/definitely/not/here.yaml"])
    assert rc == 2
    assert "config path does not exist" in capsys.readouterr().err


def test_serve_bad_bind_returns_2(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("analysis: {mode: pattern}\n", encoding="utf-8")
    rc = cli.main(["serve", "--config", str(cfg), "--bind", "bogus"])
    assert rc == 2
    assert "HOST:PORT" in capsys.readouterr().err


def test_serve_broker_construction_failure_returns_2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("analysis: {mode: pattern}\n", encoding="utf-8")

    def _boom(_cls: Any, _p: Any) -> Any:
        raise RuntimeError("wiring blew up")

    from nautilus.core import broker as broker_mod

    monkeypatch.setattr(broker_mod.Broker, "from_config", classmethod(_boom))
    rc = cli.main(["serve", "--config", str(cfg)])
    assert rc == 2
    assert "broker construction failed" in capsys.readouterr().err


def test_serve_config_error_returns_2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from nautilus.config.loader import ConfigError
    from nautilus.core import broker as broker_mod

    cfg = tmp_path / "c.yaml"
    cfg.write_text("analysis: {mode: pattern}\n", encoding="utf-8")

    def _boom(_cls: Any, _p: Any) -> Any:
        raise ConfigError("bad yaml")

    monkeypatch.setattr(broker_mod.Broker, "from_config", classmethod(_boom))
    rc = cli.main(["serve", "--config", str(cfg)])
    assert rc == 2
    assert "invalid config" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# serve — happy paths with monkeypatched runners
# ---------------------------------------------------------------------------


def _install_fake_runners(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    """Replace CLI runners with recorders so serve() returns cleanly."""
    captured: dict[str, Any] = {}

    async def fake_rest(broker: Any, host: str, port: int) -> None:
        captured["rest"] = (broker, host, port)

    async def fake_mcp(broker: Any, mode: str, host: str, port: int) -> None:
        captured["mcp"] = (broker, mode, host, port)

    async def fake_both(broker: Any, host: str, port: int, mcp_mode: str) -> None:
        captured["both"] = (broker, host, port, mcp_mode)

    monkeypatch.setattr(cli, "_run_rest", fake_rest)
    monkeypatch.setattr(cli, "_run_mcp", fake_mcp)
    monkeypatch.setattr(cli, "_run_both", fake_both)
    return captured


def test_serve_rest_transport_runs_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("analysis: {mode: pattern}\n", encoding="utf-8")
    fake_broker = _patch_broker_factory(monkeypatch)
    captured = _install_fake_runners(monkeypatch)

    rc = cli.main(
        [
            "serve",
            "--config",
            str(cfg),
            "--transport",
            "rest",
            "--bind",
            "127.0.0.1:9999",
        ],
    )
    assert rc == 0
    assert captured["rest"] == (fake_broker, "127.0.0.1", 9999)
    fake_broker.aclose.assert_called()


def test_serve_mcp_transport_runs_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("analysis: {mode: pattern}\n", encoding="utf-8")
    _patch_broker_factory(monkeypatch)
    captured = _install_fake_runners(monkeypatch)

    rc = cli.main(
        [
            "serve",
            "--config",
            str(cfg),
            "--transport",
            "mcp",
            "--mcp-mode",
            "http",
            "--bind",
            "127.0.0.1:7777",
        ],
    )
    assert rc == 0
    assert captured["mcp"][1] == "http"
    assert captured["mcp"][2] == "127.0.0.1"
    assert captured["mcp"][3] == 7777


def test_serve_both_transport_runs_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("analysis: {mode: pattern}\n", encoding="utf-8")
    _patch_broker_factory(monkeypatch)
    captured = _install_fake_runners(monkeypatch)

    rc = cli.main(
        [
            "serve",
            "--config",
            str(cfg),
            "--transport",
            "both",
            "--mcp-mode",
            "stdio",
        ],
    )
    assert rc == 0
    assert "both" in captured


def test_serve_air_gapped_flips_analysis_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--air-gapped emits WARN and rewrites config before Broker.from_config."""
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "analysis": {"mode": "llm", "provider": {"type": "openai"}},
                "sources": [],
            },
        ),
        encoding="utf-8",
    )

    seen_paths: list[str] = []

    from nautilus.core import broker as broker_mod

    def _capture(_cls: Any, path: Any) -> Any:
        seen_paths.append(str(path))
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        # Verify air-gap normalization happened before we were called.
        assert raw["analysis"]["mode"] == "pattern"
        assert raw["analysis"]["provider"] is None
        return _make_fake_broker()

    monkeypatch.setattr(broker_mod.Broker, "from_config", classmethod(_capture))
    _install_fake_runners(monkeypatch)

    rc = cli.main(["serve", "--config", str(cfg), "--air-gapped"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "--air-gapped overrides analysis.mode" in err
    assert "--air-gapped refuses analysis.provider" in err
    # Broker was handed a rewritten path (different from the input).
    assert seen_paths and seen_paths[0] != str(cfg)


def test_serve_keyboard_interrupt_is_swallowed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("analysis: {mode: pattern}\n", encoding="utf-8")
    _patch_broker_factory(monkeypatch)

    async def _raise_kbi(*_a: Any, **_kw: Any) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_run_rest", _raise_kbi)
    rc = cli.main(["serve", "--config", str(cfg)])
    assert rc == 0


# ---------------------------------------------------------------------------
# dispatch fallthrough — defensive branch in main()
# ---------------------------------------------------------------------------


def test_main_unknown_command_hits_defensive_branch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """argparse normally prevents this — rebuild parser to bypass required=True."""

    class _FakeParser:
        def parse_args(self, _argv: list[str] | None) -> argparse.Namespace:
            return argparse.Namespace(command="mystery")

        def print_help(self, _file: Any) -> None:
            print("USAGE", file=_file)

    monkeypatch.setattr(cli, "_build_parser", lambda: _FakeParser())
    rc = cli.main([])
    assert rc == 2
    assert "USAGE" in capsys.readouterr().err
