"""Unit tests for :mod:`nautilus.cli.adapters` (#21)."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from nautilus.cli import adapters as cli_adapters

pytestmark = pytest.mark.unit


def test_ac_21_f_add_subparser_registers_adapters_group() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    cli_adapters.add_subparser(sub)
    args = parser.parse_args(["adapters", "list"])
    assert args.cmd == "adapters"


def test_ac_21_g_schema_ack_without_yes_exits_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice@example.com")
    args = argparse.Namespace(
        cmd="adapters",
        adapters_subcommand="schema-ack",
        name="postgres-1",
        reason="acked",
        yes=False,
    )
    rc = cli_adapters.dispatch(args)
    assert rc == 1


# ---------------------------------------------------------------------------
# adapters new (#17)
# ---------------------------------------------------------------------------


def _new_args(name: str, parent: object) -> argparse.Namespace:
    return argparse.Namespace(
        cmd="adapters",
        adapters_subcommand="new",
        name=name,
        dir=str(parent),
    )


def test_ac_17_new_parser_accepts_name_and_dir() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    cli_adapters.add_subparser(sub)
    args = parser.parse_args(["adapters", "new", "my-csv-adapter", "--dir", "/tmp"])
    assert args.adapters_subcommand == "new"
    assert args.name == "my-csv-adapter"
    assert args.dir == "/tmp"


def test_ac_17_scaffold_names_derivation() -> None:
    names = cli_adapters._scaffold_names("my-csv-adapter")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert names == {
        "adapter_name": "my-csv-adapter",
        "package_name": "my_csv_adapter",
        "class_name": "MyCsvAdapter",
        "source_type": "my-csv",
    }
    # No trailing -adapter token: keep everything.
    names = cli_adapters._scaffold_names("foo")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert names["class_name"] == "FooAdapter"
    assert names["source_type"] == "foo"


def test_ac_17_new_invalid_name_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli_adapters.dispatch(_new_args("Bad_Name", tmp_path))
    assert rc == 1
    assert "invalid adapter name" in capsys.readouterr().err


def test_ac_17_new_existing_nonempty_dest_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "my-adapter"
    dest.mkdir()
    (dest / "keep.txt").write_text("x", encoding="utf-8")
    rc = cli_adapters.dispatch(_new_args("my-adapter", tmp_path))
    assert rc == 1
    assert "not empty" in capsys.readouterr().err


def test_ac_17_new_renders_package(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli_adapters.dispatch(_new_args("my-csv-adapter", tmp_path))
    captured = capsys.readouterr()
    assert rc == 0
    assert "OK:" in captured.out

    dest = tmp_path / "my-csv-adapter"
    module = dest / "src" / "my_csv_adapter" / "__init__.py"
    pyproject = dest / "pyproject.toml"
    tests_file = dest / "tests" / "test_compliance.py"
    readme = dest / "README.md"
    for f in (module, pyproject, tests_file, readme):
        assert f.is_file(), f"missing scaffold file: {f}"

    # Entry point wired to the rendered class.
    assert 'my-csv = "my_csv_adapter:MyCsvAdapter"' in pyproject.read_text(encoding="utf-8")
    # Rendered sources are valid Python.
    import ast

    ast.parse(module.read_text(encoding="utf-8"))
    ast.parse(tests_file.read_text(encoding="utf-8"))


async def test_ac_17_generated_adapter_passes_compliance_suite(tmp_path: Path) -> None:
    """The scaffolded adapter must pass the SDK compliance suite as generated."""
    rc = cli_adapters.dispatch(_new_args("demo-rows-adapter", tmp_path))
    assert rc == 0

    import importlib.util

    module_path = tmp_path / "demo-rows-adapter" / "src" / "demo_rows_adapter" / "__init__.py"
    spec = importlib.util.spec_from_file_location("demo_rows_adapter", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    adapter_cls = module.DemoRowsAdapter

    from nautilus_adapter_sdk.config import SourceConfig
    from nautilus_adapter_sdk.testing.compliance import AdapterComplianceSuite

    suite = AdapterComplianceSuite(
        adapter_factory=adapter_cls,
        source_config=SourceConfig(id="t1", type="demo-rows"),
    )
    await suite.test_connect_execute_close_lifecycle()
    await suite.test_scope_enforcement_valid_operator()
    await suite.test_scope_enforcement_invalid_operator()
    await suite.test_idempotent_close()
    await suite.test_error_path_returns_error_record()
