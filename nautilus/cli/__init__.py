"""Nautilus CLI — orchestrator (FR-30, D-15).

Subcommands are implemented in sibling modules:
    * :mod:`nautilus.cli.version` — ``version``
    * :mod:`nautilus.cli.health`  — ``health``
    * :mod:`nautilus.cli.serve`   — ``serve`` runners + config helpers

Shared helpers (``--json``, ``--yes``, ``NAUTILUS_REVIEWER``, output
prefixes) live in :mod:`nautilus.cli._common`.

The entry-point ``nautilus.cli:main`` remains stable — pyproject.toml
does not need changes (OQ4 LOCKED).

Note on test monkeypatching: ``_run_rest``, ``_run_mcp``, ``_run_both``
are re-exported here so that tests patching ``cli._run_rest`` etc. affect
the dispatch inside ``_cmd_serve``, which calls them via this module's
namespace.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys
import urllib  # noqa: F401 - re-exported for test monkeypatching
import urllib.request  # noqa: F401 - re-exported for test monkeypatching
from importlib import metadata

from nautilus.cli.health import (
    _DEFAULT_HEALTH_URL,
    _cmd_health,
)
from nautilus.cli.serve import (
    _DEFAULT_BIND,
    _enforce_air_gap,
    _load_config_for_serve,
    _run_both,
    _run_mcp,
    _run_rest,
    _split_bind,
)
from nautilus.cli.version import _cmd_version

__all__ = [
    "_DEFAULT_BIND",
    "_DEFAULT_HEALTH_URL",
    "_cmd_health",
    "_cmd_serve",
    "_cmd_version",
    "_enforce_air_gap",
    "_load_config_for_serve",
    "_run_both",
    "_run_mcp",
    "_run_rest",
    "_split_bind",
    "main",
    "metadata",
]


def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argparse parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="nautilus",
        description="Nautilus reasoning-engine CLI (serve / health / version).",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    # version ---------------------------------------------------------
    sub.add_parser("version", help="Print the installed nautilus package version.")

    # health ----------------------------------------------------------
    p_health = sub.add_parser(
        "health",
        help="Probe a nautilus /readyz endpoint over HTTP (exit 0 on 200).",
    )
    p_health.add_argument(
        "--url",
        default=_DEFAULT_HEALTH_URL,
        help=f"Readiness URL (default: {_DEFAULT_HEALTH_URL}).",
    )

    # serve -----------------------------------------------------------
    p_serve = sub.add_parser(
        "serve",
        help="Run the nautilus transport(s): REST, MCP, or both.",
    )
    p_serve.add_argument(
        "--config",
        required=True,
        help="Path to nautilus.yaml.",
    )
    p_serve.add_argument(
        "--transport",
        choices=("rest", "mcp", "both"),
        default="rest",
        help="Transport surface to expose (default: rest).",
    )
    p_serve.add_argument(
        "--mcp-mode",
        choices=("stdio", "http"),
        default="stdio",
        help="MCP transport mode when --transport is mcp or both (default: stdio).",
    )
    p_serve.add_argument(
        "--bind",
        default=_DEFAULT_BIND,
        help=f"HOST:PORT for REST (and MCP http) bind (default: {_DEFAULT_BIND}).",
    )
    p_serve.add_argument(
        "--air-gapped",
        action="store_true",
        help=(
            "Force analysis.mode='pattern' and refuse any LLM provider "
            "config (NFR-1). WARN is emitted naming each overridden field."
        ),
    )

    # rkm -----------------------------------------------------------------
    from nautilus.cli import rkm as _rkm_mod
    _rkm_mod.add_subparser(sub)

    # rule ----------------------------------------------------------------
    from nautilus.cli import rule as _rule_mod
    _rule_mod.add_subparser(sub)

    return parser


# ----------------------------------------------------------------------
# serve dispatch — kept here so monkeypatching cli._run_rest etc. works
# ----------------------------------------------------------------------

from pathlib import Path as _Path  # noqa: E402


def _cmd_serve(args: argparse.Namespace) -> int:
    """Dispatch the ``serve`` subcommand.

    Calls ``_run_rest`` / ``_run_mcp`` / ``_run_both`` via *this* module's
    namespace so that test monkeypatches on ``cli._run_rest`` etc. are
    honoured.
    """
    import nautilus.cli as _cli_module

    config_path = _Path(args.config)
    if not config_path.is_file():
        print(
            f"ERROR: config path does not exist or is not a file: {config_path}",
            file=sys.stderr,
        )
        return 2

    try:
        host, port = _split_bind(args.bind)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        effective_path = _load_config_for_serve(
            config_path,
            air_gapped=bool(args.air_gapped),
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # Broker.from_config surfaces ConfigError / validation errors with
    # readable messages; propagate as a non-zero exit before any bind.
    from nautilus.config.loader import ConfigError
    from nautilus.core.broker import Broker

    try:
        broker = Broker.from_config(effective_path)
    except ConfigError as exc:
        print(f"ERROR: invalid config: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - surface wiring failures cleanly
        print(f"ERROR: broker construction failed: {exc}", file=sys.stderr)
        return 2

    transport = args.transport
    mcp_mode = args.mcp_mode

    try:
        if transport == "rest":
            asyncio.run(_cli_module._run_rest(broker, host, port))
        elif transport == "mcp":
            asyncio.run(_cli_module._run_mcp(broker, mcp_mode, host, port))
        else:
            asyncio.run(_cli_module._run_both(broker, host, port, mcp_mode))
    except KeyboardInterrupt:
        pass
    finally:
        # For --transport rest the FastAPI lifespan already closed the
        # broker; aclose() is idempotent so the extra call is safe. A
        # stale/already-closed event loop surfaces as RuntimeError — we
        # silence it since the broker state is what matters here.
        with contextlib.suppress(RuntimeError):
            asyncio.run(broker.aclose())
    return 0


# ----------------------------------------------------------------------
# entry point
# ----------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code.

    TODO(forge): OQ4 — wire new subcommand groups (rkm, rule, rules,
    adapters, key, events) into :func:`_build_parser` and the dispatch
    ladder. Stubs live in :mod:`nautilus.cli.rkm`, :mod:`nautilus.cli.rule`,
    :mod:`nautilus.cli.rules`, :mod:`nautilus.cli.adapters`,
    :mod:`nautilus.cli.key`, :mod:`nautilus.cli.events`.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        return _cmd_version()
    if args.command == "health":
        return _cmd_health(args.url)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "rkm":
        from nautilus.cli import rkm as _rkm_mod
        return _rkm_mod.dispatch(args)
    if args.command == "rule":
        from nautilus.cli import rule as _rule_mod
        return _rule_mod.dispatch(args)
    # argparse enforces required=True; this is defensive.
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
