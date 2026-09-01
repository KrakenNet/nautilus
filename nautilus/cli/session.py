# pyright: reportPrivateUsage=false, reportMissingTypeStubs=false
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false
"""``nautilus session`` — read the session store's schema stamp.

The broker refuses a store stamped for a schema version it does not
understand, and ``/readyz`` re-checks it while running. Both report the number
they found; nothing reported what a store actually carries, so the first step
in diagnosing a stuck rollout was reading Nautilus's source.

There is one schema version. This command exists to answer "which one is on
disk", not to migrate between versions that do not exist yet.
"""

from __future__ import annotations

import argparse
import asyncio
import sqlite3
import sys
from pathlib import Path

from nautilus.core.session_pg import _SCHEMA_VERSION


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Add the ``session`` subcommand tree to the top-level parser."""
    parser = sub.add_parser(
        "session",
        help="Inspect a session store (schema version).",
    )
    inner = parser.add_subparsers(dest="session_command", required=True, metavar="subcommand")
    version = inner.add_parser(
        "version",
        help="Print the schema version a session store carries.",
    )
    version.add_argument(
        "--sqlite-path",
        default=None,
        help="Path to a sqlite session database.",
    )
    version.add_argument(
        "--dsn",
        default=None,
        help="Postgres DSN of a session store.",
    )


def dispatch(args: argparse.Namespace) -> int:
    """Run the requested ``session`` subcommand. Returns the process exit code."""
    if args.session_command != "version":  # pragma: no cover — argparse gates this
        print(f"ERROR: unknown session subcommand {args.session_command!r}", file=sys.stderr)
        return 2
    if bool(args.sqlite_path) == bool(args.dsn):
        print("ERROR: pass exactly one of --sqlite-path or --dsn", file=sys.stderr)
        return 2
    found = _sqlite_version(Path(args.sqlite_path)) if args.sqlite_path else _pg_version(args.dsn)
    if found is None:
        return 1
    print(f"store schema version: {found}")
    print(f"this build understands: {_SCHEMA_VERSION}")
    if found != _SCHEMA_VERSION:
        print(
            "\nThey do not match, so this build refuses the store. Run the "
            "build that wrote it, or point the config at a fresh store.",
            file=sys.stderr,
        )
        return 1
    return 0


def _sqlite_version(path: Path) -> int | None:
    if not path.exists():
        print(f"ERROR: no such file: {path}", file=sys.stderr)
        return None
    conn = sqlite3.connect(path)
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


def _pg_version(dsn: str) -> int | None:
    async def _read() -> int | None:
        try:
            import asyncpg
        except ImportError:
            print("ERROR: asyncpg is not installed", file=sys.stderr)
            return None
        try:
            conn = await asyncpg.connect(dsn=dsn)
        except Exception as exc:  # noqa: BLE001 — any connect failure is the answer
            print(f"ERROR: could not connect: {exc}", file=sys.stderr)
            return None
        try:
            row = await conn.fetchrow("SELECT version FROM nautilus_schema_version")
        except Exception as exc:  # noqa: BLE001 — a missing table is the answer too
            print(f"ERROR: could not read nautilus_schema_version: {exc}", file=sys.stderr)
            return None
        finally:
            await conn.close()
        if row is None:
            print("ERROR: nautilus_schema_version holds no row", file=sys.stderr)
            return None
        return int(row["version"])

    return asyncio.run(_read())
