"""Unit tests for ``nautilus adapters`` config handling."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from nautilus.cli import main

if TYPE_CHECKING:
    from pathlib import Path


def test_unloadable_config_is_an_error_not_a_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every ``adapters`` subcommand that loads a config must report a bad one.

    ``adapters list`` already did: ``_configured_adapters`` catches the load
    failure and calls ``err``. The four schema subcommands went through
    ``_live_adapter_schema``, which called ``Broker.from_config`` bare, so the
    same operator typo came back as a ``ConfigError`` traceback. The control
    is ``list``: the four must match what it does with the identical input,
    message and exit code alike.
    """
    config = tmp_path / "nautilus.yaml"
    config.write_text("sources: [not: a: mapping\n")
    # schema-ack checks the reviewer identity before it loads the config; without
    # this the assertion below would pass on the wrong error.
    monkeypatch.setenv("NAUTILUS_REVIEWER", "tester")

    control = main(["adapters", "list", "--config", str(config)])
    expected = capsys.readouterr().err
    assert control == 1
    assert expected.startswith(f"ERROR: could not load {config}: ")

    for argv in (
        ["adapters", "schema", "src"],
        ["adapters", "schema-fingerprint", "src"],
        ["adapters", "schema-diff", "src"],
        ["adapters", "schema-ack", "src", "--reason", "drifted", "--yes"],
    ):
        # An unguarded load raises out of main() here rather than returning.
        rc = main([*argv, "--config", str(config)])
        assert rc == control, f"{' '.join(argv)} exited {rc}, `adapters list` exits {control}"
        assert capsys.readouterr().err == expected, f"{' '.join(argv)} reported it differently"
