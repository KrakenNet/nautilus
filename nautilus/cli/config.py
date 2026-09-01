"""``nautilus config`` subcommand — read a config the way ``serve`` reads it.

Subcommands:
    config check <file>

Nautilus has no config hot-reload (see ``docs/how-to/hardening.md``), so a
config is only ever adopted by a process start. Before this command the only
way to find out whether a change was adoptable was to restart the broker with
it and watch: a syntax error, a source type that does not exist, a driver that
is not installed, a classification label that is not a level of the hierarchy —
all of them showed up as a process that did not come up.

``check`` runs :func:`nautilus.cli.serve.broker_for_serve`, which is the exact
sequence ``serve`` runs before it binds, so a refusal here is the refusal the
operator would have read in the startup log, in the same words and with the
same exit code.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
from pathlib import Path
from typing import TYPE_CHECKING

from nautilus.cli._common import err

if TYPE_CHECKING:
    from nautilus.core.broker import Broker


def add_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    """Add the ``config`` group to the top-level argparse subparsers."""
    p_config = sub.add_parser("config", help="Configuration file subcommands.")
    config_sub = p_config.add_subparsers(dest="config_subcommand", metavar="subcommand")

    p_check = config_sub.add_parser(
        "check",
        help="Load a nautilus.yaml exactly as `serve` does, without serving it.",
    )
    p_check.add_argument("file", help="Path to the nautilus.yaml to check.")


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``config`` invocation. Returns process exit code."""
    if getattr(args, "config_subcommand", None) == "check":
        return _cmd_check(args)
    err("config: no subcommand given (try: check)")
    return 2


def _cmd_check(args: argparse.Namespace) -> int:
    """Build the broker ``serve`` would build, report it, and throw it away.

    Exit ``0`` and print what the config asks for; exit ``2`` with the text
    ``serve`` would have failed with. Two exit codes, because there is one
    question: would ``serve`` come up on this file.
    """
    import logging

    from nautilus.cli.serve import ConfigRefusedError, broker_for_serve
    from nautilus.observability.logging import configure_logging

    # Startup warnings are half of what a check is for -- an undeclared
    # ``agents:`` block is not a refusal but it is the largest posture
    # difference between a demo and a deployment, and the broker says so at
    # construction. Configured at WARNING rather than ``serve``'s INFO: the
    # INFO lines are adapter discovery and would bury the one line that is
    # about this operator's config.
    configure_logging("text", logging.WARNING)

    path = Path(args.file)
    try:
        broker = broker_for_serve(path, air_gapped=False)
    except ConfigRefusedError as exc:
        err(str(exc))
        return 2

    try:
        _report(broker, path)
    finally:
        # Same teardown ``serve`` runs in its ``finally``: the check built a
        # real broker, and a real broker holds adapter clients and a session
        # store. A stale/closed loop surfaces as RuntimeError, which says
        # nothing about the config.
        with contextlib.suppress(RuntimeError):
            asyncio.run(broker.aclose())
    return 0


def _report(broker: Broker, path: Path) -> None:
    """Print what ``serve`` would come up as on this config.

    The fields are the ones an operator is about to change and cannot see
    from the file alone: the bind that ``api.host``/``api.port`` resolve to,
    the sources and agents the broker registered, how many rules the engine
    built, and where the state that survives a restart lives.
    """
    config = broker.config
    sources = broker.sources
    agents = sorted(config.agents)
    audit_path = broker.audit_path

    print(f"OK: {path} — serve would start on this config")
    # Named, because ``serve --bind`` overrides both and a reader who has
    # only ever started the broker with --bind would otherwise read this
    # line as the port the next start listens on.
    print(
        f"  bind:          {broker.api_config.host}:{broker.api_config.port}"
        f"   (api.host/api.port; serve --bind overrides)"
    )
    print(f"  sources:       {_listing(len(sources), [s.id for s in sources])}")
    print(f"  agents:        {_listing(len(agents), agents)}")
    print(f"  rules:         {len(broker.rules_in_force())} in force")
    print(f"  session store: {config.session_store.backend}")
    print(f"  audit log:     {audit_path if audit_path is not None else '(none)'}")


def _listing(count: int, names: list[str]) -> str:
    """``"2 (orders, tickets)"`` — or ``"0"``, since ``0 ()`` reads as a bug."""
    return f"{count} ({', '.join(names)})" if names else "0"


__all__ = ["add_subparser", "dispatch"]
