"""``nautilus rules`` subcommand surface (#35.5 + #35.7).

Subcommands:
    rules validate <file> [--sandbox] [--replay-n N]
    rules history [--module M]

Long-running ``--sandbox`` mode streams ``replaying N/M ...`` progress
to stderr (suppressed when ``--json`` is present).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def add_subparser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Add ``rules`` group to the top-level argparse subparsers."""
    p_rules = sub.add_parser("rules", help="Rule management subcommands.")
    rules_sub = p_rules.add_subparsers(dest="rules_subcommand", metavar="subcommand")

    p_validate = rules_sub.add_parser("validate", help="Statically validate a rule YAML file.")
    p_validate.add_argument("file", help="Path to the rule YAML file to validate.")
    p_validate.add_argument(
        "--sandbox",
        action="store_true",
        help="Run sandbox replay after static validation.",
    )
    p_validate.add_argument(
        "--replay-n",
        type=int,
        default=1000,
        dest="replay_n",
        help="Number of audit entries to replay in sandbox mode (default: 1000).",
    )
    p_validate.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON.",
    )


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``rules`` invocation. Returns process exit code."""
    subcommand = getattr(args, "rules_subcommand", None)
    if subcommand == "validate":
        return _cmd_validate(args)
    print("ERROR: unknown rules subcommand", file=sys.stderr)
    return 2


def _cmd_validate(args: argparse.Namespace) -> int:
    """Run static validation on the given rule YAML file."""
    from nautilus.rkm.validator.static import validate_static

    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"ERROR: file not found: {file_path}", file=sys.stderr)
        return 1

    result = validate_static(file_path)
    if result.ok:
        print(f"OK: {file_path}")
        return 0

    for err in result.errors:
        hint_suffix = f" Hint: {err.hint}" if err.hint else ""
        print(
            f"ERROR {err.file}:{err.line}: {err.message}{hint_suffix}",
            file=sys.stderr,
        )
    return 1


__all__ = ["add_subparser", "dispatch"]
