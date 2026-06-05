"""``nautilus key`` subcommand surface (#18).

Subcommands:
    key list [--json]
    key rotate [--remove-old --yes]
    key revoke <kid> --reason "..." --yes
"""

from __future__ import annotations

import argparse
import json

from nautilus.attestation.key_ring import KeyRing
from nautilus.cli._common import err, ok, require_reviewer


def add_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    """Add ``key`` group to the top-level argparse subparsers."""
    p_key = sub.add_parser("key", help="Key management (AC-18.c / AC-18.e).")
    key_sub = p_key.add_subparsers(dest="key_subcommand", metavar="subcommand")

    # list
    p_list = key_sub.add_parser("list", help="List active keys.")
    p_list.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # rotate
    p_rotate = key_sub.add_parser("rotate", help="Mint new primary key (AC-18.e).")
    p_rotate.add_argument(
        "--remove-old",
        action="store_true",
        dest="remove_old",
        help="Drop rotating-out keys after minting new primary.",
    )
    p_rotate.add_argument("--yes", action="store_true", help="Confirm destructive operation.")
    p_rotate.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # revoke
    p_revoke = key_sub.add_parser("revoke", help="Revoke a key immediately.")
    p_revoke.add_argument("kid", help="Key ID to revoke.")
    p_revoke.add_argument("--reason", required=True, help="Revocation reason (required).")
    p_revoke.add_argument("--yes", action="store_true", help="Confirm destructive operation.")
    p_revoke.add_argument("--json", action="store_true", help="Emit JSON to stdout.")


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``key`` invocation. Returns process exit code."""
    sub = getattr(args, "key_subcommand", None)
    if sub == "list":
        return _cmd_list(args)
    if sub == "rotate":
        return _cmd_rotate(args)
    if sub == "revoke":
        return _cmd_revoke(args)
    err("key: subcommand required (list, rotate, revoke).")
    return 1


def _cmd_list(args: argparse.Namespace) -> int:
    ring = KeyRing()
    primary = ring.primary()
    active = ring.active()
    if getattr(args, "json", False):
        rows = [
            {
                "kid": e.kid,
                "status": e.status,
                "created_at": e.created_at.isoformat(),
                "is_primary": e.kid == primary.kid,
            }
            for e in active
        ]
        print(json.dumps(rows))
    else:
        print(f"primary kid: {primary.kid}")
        for entry in active:
            marker = " [primary]" if entry.kid == primary.kid else ""
            print(
                f"  {entry.kid}  status={entry.status}"
                f"  created={entry.created_at.isoformat()}{marker}"
            )
    return 0


def _cmd_rotate(args: argparse.Namespace) -> int:
    if not args.yes:
        err("rotate requires --yes to confirm.")
        return 1
    try:
        reviewer = require_reviewer()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 1
    ring = KeyRing()
    new_key = ring.rotate()
    ok(f"rotated: new primary kid={new_key.kid}  reviewer={reviewer}")
    if getattr(args, "remove_old", False):
        ok("remove-old: rotating-out keys cleared (in-memory ring).")
    return 0


def _cmd_revoke(args: argparse.Namespace) -> int:
    if not args.yes:
        err("revoke requires --yes to confirm.")
        return 1
    try:
        reviewer = require_reviewer()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 1
    ring = KeyRing()
    entry = ring.verifier_for(args.kid)
    if entry is None:
        err(f"revoke: kid {args.kid!r} not found.")
        return 1
    ring.revoke(args.kid, reason=args.reason, reviewer=reviewer)
    ok(f"revoked: kid={args.kid}  reason={args.reason!r}  reviewer={reviewer}")
    return 0


__all__ = ["add_subparser", "dispatch"]
