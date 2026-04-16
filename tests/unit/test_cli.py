"""Canonical CLI unit suite (Task 3.13, FR-30, AC-15.5, AC-6.4, NFR-1).

Four cases covering the three :mod:`nautilus.cli` subcommands:

    a. ``nautilus version`` → exit 0 and the installed version on stdout.
    b. ``nautilus health --url http://bogus…`` → non-zero exit (the target
       is unreachable).
    c. ``nautilus serve --config /bogus`` → non-zero exit WITH error on
       stderr BEFORE any socket bind attempt (AC-15.5).
    d. ``--air-gapped`` overrides ``analysis.mode`` to ``"pattern"`` and
       emits a WARN on stderr (AC-6.4, NFR-1).

All cases invoke :func:`nautilus.cli.main` in-process with an explicit
``argv`` list — faster and more deterministic than spawning a subprocess,
and sidesteps Windows-specific subprocess quirks. The CLI is structured
so ``main([...])`` returns the process exit code directly.

Case (c) installs a ``_run_rest`` monkeypatch that raises if reached —
this is how we prove the error surfaces BEFORE network bind. For (c) we
rely on argparse / config-existence validation (which happens before any
broker construction or uvicorn config instantiation), mirroring the
``_cmd_serve`` control flow.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from nautilus import cli

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# (a) nautilus version → exit 0
# ---------------------------------------------------------------------------


def test_a_version_exits_zero_and_prints_version(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Pin the reported version so the assertion is environment-independent.
    def _fake_version(_name: str) -> str:
        return "3.13.0"

    monkeypatch.setattr(cli.metadata, "version", _fake_version)
    rc = cli.main(["version"])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out.strip() == "3.13.0"
    # No errors — version should be a clean stdout-only path.
    assert captured.err == ""


# ---------------------------------------------------------------------------
# (b) nautilus health --url http://bogus → exit non-zero
# ---------------------------------------------------------------------------


def test_b_health_against_bogus_url_exits_non_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # An unroutable IP with an invalid port — urllib raises URLError,
    # which the CLI translates into a "FAIL unreachable" line + exit 1.
    # No monkeypatching: exercises the real urllib error path, the whole
    # point of (b) being the "real" unreachable-endpoint assertion.
    rc = cli.main(["health", "--url", "http://127.0.0.1:1/readyz"])
    assert rc != 0
    err = capsys.readouterr().err
    # Either the unreachable branch (URLError) or the OSError branch —
    # both satisfy the "exit non-zero with error to stderr" contract.
    assert "FAIL" in err


# ---------------------------------------------------------------------------
# (c) nautilus serve --config /bogus → exit non-zero BEFORE bind
# ---------------------------------------------------------------------------


def test_c_serve_missing_config_exits_before_network_bind(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Install a tripwire on every runner — if any of them were invoked,
    # the config-existence check failed to short-circuit the CLI (AC-15.5).
    async def _tripwire(*_a: Any, **_kw: Any) -> None:
        raise AssertionError("network runner reached despite missing config")

    monkeypatch.setattr(cli, "_run_rest", _tripwire)
    monkeypatch.setattr(cli, "_run_mcp", _tripwire)
    monkeypatch.setattr(cli, "_run_both", _tripwire)

    rc = cli.main(["serve", "--config", "/definitely/not/a/real/path.yaml"])
    captured = capsys.readouterr()
    # Non-zero exit (2 — argparse convention for usage/config errors).
    assert rc != 0
    # Error message names the missing config path on stderr.
    assert "config path does not exist" in captured.err


# ---------------------------------------------------------------------------
# (d) --air-gapped overrides analysis.mode and emits WARN
# ---------------------------------------------------------------------------


def test_d_air_gapped_overrides_analysis_mode_and_warns(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Build a config that declares analysis.mode="llm-first" + a provider
    # stanza. --air-gapped MUST rewrite both (AC-6.4, NFR-1).
    cfg = tmp_path / "nautilus.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "analysis": {
                    "mode": "llm-first",
                    "provider": {"type": "openai", "model": "gpt-4"},
                },
                "sources": [],
            },
        ),
        encoding="utf-8",
    )

    seen_paths: list[Path] = []

    def _capture_from_config(_cls: Any, path: Any) -> Any:
        # Inspect the config that Broker.from_config actually sees. The
        # normalization happens in _load_config_for_serve — by the time
        # we get here the file on disk already has mode="pattern".
        seen_paths.append(Path(path))
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        assert raw["analysis"]["mode"] == "pattern"
        # Provider stanza neutralized (dropped to None).
        assert raw["analysis"]["provider"] is None
        broker = MagicMock()
        broker.setup = AsyncMock()
        broker.aclose = AsyncMock()
        return broker

    from nautilus.core import broker as broker_mod

    monkeypatch.setattr(
        broker_mod.Broker,
        "from_config",
        classmethod(_capture_from_config),
    )

    # Stub the runner so we don't bind a socket.
    async def _noop_rest(_b: Any, _h: str, _p: int) -> None:
        return None

    monkeypatch.setattr(cli, "_run_rest", _noop_rest)

    rc = cli.main(["serve", "--config", str(cfg), "--air-gapped"])
    captured = capsys.readouterr()
    assert rc == 0
    # WARN emitted on stderr for each overridden field.
    assert "--air-gapped overrides analysis.mode" in captured.err
    assert "--air-gapped refuses analysis.provider" in captured.err
    # The rewritten path is a *different* file from the input (the air-gap
    # helper writes to a temp file so it never mutates the operator's
    # config on disk).
    assert seen_paths, "Broker.from_config was never called"
    assert seen_paths[0] != cfg
