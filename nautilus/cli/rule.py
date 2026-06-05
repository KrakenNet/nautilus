"""``nautilus rule`` subcommand surface (#35.10).

Subcommands:
    rule list [--status STATUS] [--json]
    rule retract <name> --reason TEXT --yes [--cascade | --orphan-children]
    rule lineage <name> [--depth N] [--json]
    rule history <name> [--json]
    rule rollback <name> --to-version VERSION --reason TEXT --yes

Direct Python imports — broker not required at CLI time.
Reviewer identity from ``NAUTILUS_REVIEWER`` env (DQ4 LOCKED).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nautilus.cli._common import err, ok, require_reviewer, warn

if TYPE_CHECKING:
    from nautilus.rkm.lineage import LineageStore

_DEFAULT_LINEAGE_DIR = Path(".nautilus/rkm/lineage")


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def add_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    """Add ``rule`` group to the top-level argparse subparsers."""
    p_rule = sub.add_parser("rule", help="Rule lifecycle management.")
    rule_sub = p_rule.add_subparsers(dest="rule_subcommand", metavar="subcommand")

    # list ----------------------------------------------------------------
    p_list = rule_sub.add_parser("list", help="List rules.")
    p_list.add_argument("--status", default=None, help="Filter by status.")
    p_list.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # retract -------------------------------------------------------------
    p_retract = rule_sub.add_parser("retract", help="Retract (retire) a rule. Destructive.")
    p_retract.add_argument("name", help="Rule name.")
    p_retract.add_argument("--reason", required=True, help="Retraction reason (required).")
    p_retract.add_argument("--yes", action="store_true", help="Confirm destructive operation.")
    p_retract.add_argument(
        "--cascade",
        action="store_true",
        default=False,
        help="Cascade retirement to all transitive descendants (AC-35.10.d).",
    )
    p_retract.add_argument(
        "--orphan-children",
        action="store_true",
        default=False,
        dest="orphan_children",
        help="Flag direct descendants as orphaned without retiring them (AC-35.10.d).",
    )

    # lineage -------------------------------------------------------------
    p_lineage = rule_sub.add_parser("lineage", help="Show rule lineage DAG.")
    p_lineage.add_argument("name", help="Rule name.")
    p_lineage.add_argument(
        "--depth",
        type=int,
        default=5,
        dest="depth",
        help="Maximum ancestor depth to traverse (default: 5).",
    )
    p_lineage.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # history -------------------------------------------------------------
    p_history = rule_sub.add_parser("history", help="Show version history for a rule.")
    p_history.add_argument("name", help="Rule name.")
    p_history.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # rollback ------------------------------------------------------------
    p_rollback = rule_sub.add_parser("rollback", help="Roll back a rule to a prior version.")
    p_rollback.add_argument("name", help="Rule name.")
    p_rollback.add_argument(
        "--to-version",
        required=True,
        type=int,
        dest="to_version",
        help="Target version number to restore.",
    )
    p_rollback.add_argument("--reason", required=True, help="Rollback reason (required).")
    p_rollback.add_argument("--yes", action="store_true", help="Confirm destructive operation.")


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``rule`` invocation. Returns process exit code."""
    try:
        subcommand = getattr(args, "rule_subcommand", None)
        if subcommand == "list":
            return _cmd_list(args)
        if subcommand == "retract":
            return _cmd_retract(args)
        if subcommand == "lineage":
            return _cmd_lineage(args)
        if subcommand == "history":
            return _cmd_history(args)
        if subcommand == "rollback":
            return _cmd_rollback(args)
        err("rule: no subcommand given (try: list, retract, lineage, history, rollback)")
        return 2
    except SystemExit as exc:
        # require_reviewer() calls sys.exit(1); surface as return code.
        return int(exc.code) if exc.code is not None else 1


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------


def _cmd_list(args: argparse.Namespace) -> int:
    lineage = _open_lineage()
    records = lineage._all_records()  # pyright: ignore[reportPrivateUsage]
    status_filter = getattr(args, "status", None)
    if status_filter == "active":
        records = [r for r in records if r.retired_at is None]
    elif status_filter == "retired":
        records = [r for r in records if r.retired_at is not None]
    if getattr(args, "json", False):
        out = [
            {"name": r.rule_name, "version": r.version, "retired": r.retired_at is not None}
            for r in records
        ]
        print(json.dumps(out))
    else:
        for r in records:
            status = "retired" if r.retired_at else "active"
            print(f"  {r.rule_name} v{r.version} [{status}]")
    return 0


def _cmd_retract(args: argparse.Namespace) -> int:
    if not args.yes:
        err("--yes required for destructive op")
        return 1
    if not getattr(args, "reason", "").strip():
        err("--reason required for retract")
        return 1
    if args.cascade and args.orphan_children:
        err("--cascade and --orphan-children are mutually exclusive")
        return 1
    if not args.cascade and not args.orphan_children:
        # Default: no cascade, no orphan — retire only the named rule
        cascade_mode = "none"
    elif args.cascade:
        cascade_mode = "cascade"
    else:
        cascade_mode = "orphan-children"

    reviewer = require_reviewer()

    from nautilus.rkm.review import retract_rule

    lineage = _open_lineage()
    latest = lineage.get(args.name)
    if latest is None:
        err(f"rule {args.name!r} not found in lineage")
        return 1

    affected = retract_rule(
        args.name,
        version=latest.version,
        reason=args.reason,
        reviewer=reviewer,
        cascade=cascade_mode,
        lineage=lineage,
        audit_logger=None,
    )
    ok(f"rule {args.name!r} v{latest.version} retracted by {reviewer}")
    if affected:
        warn(f"affected descendants: {', '.join(affected)}")
    return 0


def _cmd_lineage(args: argparse.Namespace) -> int:
    lineage = _open_lineage()
    records = lineage.history(args.name)

    if not records:
        warn(f"no lineage records for {args.name!r}")
        if getattr(args, "json", False):
            print(json.dumps({"proposer": None, "versions": []}))
        return 0

    depth = getattr(args, "depth", 5)
    records = records[-depth:]

    if getattr(args, "json", False):
        versions: list[dict[str, Any]] = []
        for r in records:
            d = dataclasses.asdict(r)
            d["promoted_at"] = r.promoted_at.isoformat()
            if r.retired_at is not None:
                d["retired_at"] = r.retired_at.isoformat()
            d["derived_from"] = list(r.derived_from)
            d["reviewer"] = r.approver
            versions.append(d)
        out = {"proposer": records[-1].proposer, "versions": versions}
        print(json.dumps(out, default=str))
        return 0

    for r in records:
        retired = " [retired]" if r.retired_at else ""
        print(
            f"  {r.rule_name} v{r.version}"
            f"  approver={r.approver}"
            f"  promoted={r.promoted_at.isoformat()}{retired}"
        )
        if r.derived_from:
            print(f"    derived_from: {', '.join(r.derived_from)}")
    return 0


def _cmd_history(args: argparse.Namespace) -> int:
    lineage = _open_lineage()
    records = lineage.history(args.name)

    if not records:
        warn(f"no history for {args.name!r}")
        if getattr(args, "json", False):
            print(json.dumps([]))
        return 0

    if getattr(args, "json", False):
        out: list[dict[str, Any]] = []
        for r in records:
            d = dataclasses.asdict(r)
            d["promoted_at"] = r.promoted_at.isoformat()
            if r.retired_at is not None:
                d["retired_at"] = r.retired_at.isoformat()
            d["derived_from"] = list(r.derived_from)
            out.append(d)
        print(json.dumps(out, default=str))
        return 0

    for r in records:
        retired = " [retired]" if r.retired_at else ""
        print(f"  v{r.version}  promoted={r.promoted_at.isoformat()}{retired}")
    return 0


def _cmd_rollback(args: argparse.Namespace) -> int:
    if not args.yes:
        err("--yes required for destructive op")
        return 1

    reviewer = require_reviewer()

    lineage = _open_lineage()
    target = lineage.get(args.name, args.to_version)
    if target is None:
        err(f"rule {args.name!r} v{args.to_version} not found in lineage")
        return 1

    # Determine next version number (latest + 1).
    latest = lineage.get(args.name)
    next_version: int = (latest.version + 1) if latest is not None else args.to_version + 1

    from datetime import UTC, datetime

    restored = dataclasses.replace(
        target,
        version=next_version,
        approver=reviewer,
        promoted_at=datetime.now(UTC),
        retired_at=None,
        retire_reason=None,
        retire_reviewer=None,
    )
    lineage.insert(restored)
    ok(
        f"rule {args.name!r} rolled back to v{args.to_version}"
        f" as v{next_version} by {reviewer}: {args.reason}"
    )
    return 0


def _open_lineage() -> LineageStore:
    from nautilus.rkm.lineage import LineageStore

    return LineageStore(_DEFAULT_LINEAGE_DIR)


__all__ = ["add_subparser", "dispatch"]
