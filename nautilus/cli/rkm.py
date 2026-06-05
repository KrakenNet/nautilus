"""``nautilus rkm`` subcommand surface (#35.9 + #35.10).

Subcommands:
    rkm queue list [--status STATUS] [--min-confidence FLOAT] [--json]
    rkm queue show <proposal_id> [--json]
    rkm queue approve <proposal_id> [--note TEXT]
    rkm queue reject <proposal_id> --reason TEXT
    rkm queue diff <proposal_id>
    rkm lineage <proposal_id|rule_name> [--depth N] [--json]

Direct Python imports (no HTTP) — broker not required at CLI time.
Reviewer identity from ``NAUTILUS_REVIEWER`` env (DQ4 LOCKED).

Peer heuristic for ``diff`` (DQ6): derive peer from
``proposal.lineage.derived_from`` via longest-common-prefix of rule names.
Falls back to "no peer" when ``derived_from`` is empty.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nautilus.cli._common import err, ok, require_reviewer, warn

if TYPE_CHECKING:
    from nautilus.rkm.queue import ProposalQueue
    from nautilus.rkm.types import Proposal

# Default queue/lineage dirs (relative to cwd / project root convention)
_DEFAULT_QUEUE_DIR = Path(".nautilus/rkm/queue")
_DEFAULT_LINEAGE_DIR = Path(".nautilus/rkm/lineage")


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def add_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    """Add ``rkm`` group to the top-level argparse subparsers."""
    p_rkm = sub.add_parser("rkm", help="Review-queue and lineage management.")
    rkm_sub = p_rkm.add_subparsers(dest="rkm_subcommand", metavar="subcommand")

    # -- queue group -------------------------------------------------------
    p_queue = rkm_sub.add_parser("queue", help="Proposal queue operations.")
    queue_sub = p_queue.add_subparsers(dest="queue_subcommand", metavar="op")

    # queue list
    p_list = queue_sub.add_parser("list", help="List proposals in the review queue.")
    p_list.add_argument("--status", default=None, help="Filter by status (pending, approved, …).")
    p_list.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        dest="min_confidence",
        help="Minimum confidence score (0.0–1.0).",
    )
    p_list.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # queue show
    p_show = queue_sub.add_parser("show", help="Show details of a specific proposal.")
    p_show.add_argument("proposal_id", help="Proposal ID (prop_<hex>).")
    p_show.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # queue approve
    p_approve = queue_sub.add_parser("approve", help="Approve a pending proposal (DQ4).")
    p_approve.add_argument("proposal_id", help="Proposal ID.")
    p_approve.add_argument("--note", default=None, help="Optional reviewer note.")
    p_approve.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # queue reject
    p_reject = queue_sub.add_parser("reject", help="Reject a pending proposal.")
    p_reject.add_argument("proposal_id", help="Proposal ID.")
    p_reject.add_argument("--reason", required=True, help="Rejection reason (required).")
    p_reject.add_argument("--json", action="store_true", help="Emit JSON to stdout.")

    # queue diff
    # Peer heuristic (DQ6): longest-common-prefix of rule names from derived_from.
    p_diff = queue_sub.add_parser(
        "diff",
        help=(
            "Show schema diff for a proposal vs its peer rule. "
            "Peer determined via DQ6 heuristic: lineage.derived_from → "
            "longest-common-prefix of rule names → 'no peer' if empty."
        ),
    )
    p_diff.add_argument("proposal_id", help="Proposal ID.")

    # -- lineage -----------------------------------------------------------
    p_lineage = rkm_sub.add_parser("lineage", help="Show rule lineage DAG.")
    p_lineage.add_argument("id", help="Proposal ID or rule name.")
    p_lineage.add_argument(
        "--depth",
        type=int,
        default=5,
        dest="depth",
        help="Maximum ancestor depth to traverse (default: 5).",
    )
    p_lineage.add_argument("--json", action="store_true", help="Emit JSON to stdout.")


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``rkm`` invocation. Returns process exit code."""
    try:
        subcommand = getattr(args, "rkm_subcommand", None)
        if subcommand == "queue":
            return _dispatch_queue(args)
        if subcommand == "lineage":
            return _cmd_lineage(args)
        err("rkm: no subcommand given (try: queue, lineage)")
        return 2
    except SystemExit as exc:
        # require_reviewer() calls sys.exit(1); surface as return code.
        return int(exc.code) if exc.code is not None else 1


# ---------------------------------------------------------------------------
# Queue dispatch
# ---------------------------------------------------------------------------


def _dispatch_queue(args: argparse.Namespace) -> int:
    op = getattr(args, "queue_subcommand", None)
    if op == "list":
        return _cmd_queue_list(args)
    if op == "show":
        return _cmd_queue_show(args)
    if op == "approve":
        return _cmd_queue_approve(args)
    if op == "reject":
        return _cmd_queue_reject(args)
    if op == "diff":
        return _cmd_queue_diff(args)
    err("rkm queue: no op given (try: list, show, approve, reject, diff)")
    return 2


def _open_queue() -> ProposalQueue:
    from nautilus.rkm.queue import ProposalQueue

    return ProposalQueue(_DEFAULT_QUEUE_DIR)


def _proposal_as_dict(proposal: Proposal) -> dict[str, Any]:
    d = dataclasses.asdict(proposal)
    d["proposed_at"] = proposal.proposed_at.isoformat()
    return d


def _cmd_queue_list(args: argparse.Namespace) -> int:
    queue = _open_queue()
    proposals = queue.list(
        status=args.status,
        min_confidence=args.min_confidence,
    )
    if getattr(args, "json", False):
        print(json.dumps([_proposal_as_dict(p) for p in proposals], default=str))
        return 0
    if not proposals:
        ok("no proposals")
        return 0
    for p in proposals:
        conf = p.validation.get("confidence", "?")
        print(f"  {p.proposal_id}  status={p.status}  confidence={conf}")
    return 0


def _cmd_queue_show(args: argparse.Namespace) -> int:
    queue = _open_queue()
    proposal = queue.get(args.proposal_id)
    if proposal is None:
        err(f"proposal {args.proposal_id} not found")
        return 1
    if getattr(args, "json", False):
        print(json.dumps(_proposal_as_dict(proposal), default=str))
        return 0
    d = _proposal_as_dict(proposal)
    for k, v in d.items():
        print(f"  {k}: {v}")
    return 0


def _cmd_queue_approve(args: argparse.Namespace) -> int:
    reviewer = require_reviewer()  # exits 1 if not set (DQ4)
    queue = _open_queue()
    proposal = queue.get(args.proposal_id)
    if proposal is None:
        err(f"proposal {args.proposal_id} not found")
        return 1

    # Idempotency: already approved/promoted → treat as success
    if proposal.status in ("approved", "promoted"):
        msg = f"proposal {args.proposal_id} already_approved (status={proposal.status})"
        if getattr(args, "json", False):
            print(json.dumps({"status": "already_approved", "proposal_id": args.proposal_id}))
        else:
            ok(msg)
        return 0

    from nautilus.rkm.lineage import LineageStore
    from nautilus.rkm.review import AlreadyDecidedError, approve_proposal

    lineage = LineageStore(_DEFAULT_LINEAGE_DIR)
    try:
        result = approve_proposal(
            args.proposal_id,
            reviewer,
            queue=queue,
            lineage=lineage,
            router=None,
            audit_logger=None,
        )
    except AlreadyDecidedError as exc:
        msg = f"proposal {args.proposal_id} already_approved (status={exc.current_status})"
        if getattr(args, "json", False):
            print(json.dumps({"status": "already_approved", "proposal_id": args.proposal_id}))
        else:
            ok(msg)
        return 0
    except KeyError:
        err(f"proposal {args.proposal_id} not found")
        return 1

    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "proposal_id": result.proposal_id,
                    "reviewer": result.reviewer,
                    "approved_at": result.approved_at.isoformat(),
                    "promoted": result.promoted,
                }
            )
        )
    else:
        ok(f"proposal {result.proposal_id} approved by {result.reviewer}")
    return 0


def _cmd_queue_reject(args: argparse.Namespace) -> int:
    reviewer = require_reviewer()  # exits 1 if not set (DQ4)
    queue = _open_queue()
    proposal = queue.get(args.proposal_id)
    if proposal is None:
        err(f"proposal {args.proposal_id} not found")
        return 1

    from nautilus.rkm.review import AlreadyDecidedError, reject_proposal

    try:
        result = reject_proposal(
            args.proposal_id,
            reviewer,
            args.reason,
            queue=queue,
            audit_logger=None,
        )
    except AlreadyDecidedError as exc:
        err(f"proposal {args.proposal_id} already decided: status={exc.current_status}")
        return 1
    except KeyError:
        err(f"proposal {args.proposal_id} not found")
        return 1

    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "proposal_id": result.proposal_id,
                    "reviewer": result.reviewer,
                    "rejected_at": result.rejected_at.isoformat(),
                    "reason": result.reason,
                }
            )
        )
    else:
        ok(f"proposal {result.proposal_id} rejected by {result.reviewer}: {result.reason}")
    return 0


def _cmd_queue_diff(args: argparse.Namespace) -> int:
    """Show schema diff. Peer determined by DQ6 heuristic (longest-common-prefix)."""
    queue = _open_queue()
    proposal = queue.get(args.proposal_id)
    if proposal is None:
        err(f"proposal {args.proposal_id} not found")
        return 1

    derived_from: list[str] = list(proposal.lineage.get("derived_from", []))
    peer = _peer_from_derived_from(derived_from)

    artifact = proposal.artifact
    print(f"  proposal : {args.proposal_id}")
    print(f"  peer     : {peer}")
    print(f"  artifact : {json.dumps(artifact, indent=2, default=str)}")
    return 0


def _peer_from_derived_from(derived_from: list[str]) -> str:
    """DQ6 heuristic: longest-common-prefix of derived_from rule names.

    Returns the longest prefix shared by all names, or 'no peer' if empty.
    """
    if not derived_from:
        return "no peer"
    if len(derived_from) == 1:
        return derived_from[0]
    # Longest-common-prefix at character level across all names
    prefix = derived_from[0]
    for name in derived_from[1:]:
        while not name.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return "no peer"
    return prefix or "no peer"


# ---------------------------------------------------------------------------
# Lineage
# ---------------------------------------------------------------------------


def _cmd_lineage(args: argparse.Namespace) -> int:
    from nautilus.rkm.lineage import LineageStore

    lineage = LineageStore(_DEFAULT_LINEAGE_DIR)

    # Try as rule_name first; if not found try to resolve proposal_id → rule_name
    rule_name = args.id
    records = lineage.history(rule_name)

    if not records:
        # Try looking up via queue proposal
        queue = _open_queue()
        proposal = queue.get(args.id)
        if proposal is not None:
            rule_name = proposal.artifact.get("name", args.id)
            records = lineage.history(rule_name)

    if not records:
        warn(f"no lineage records for {args.id!r}")
        if getattr(args, "json", False):
            print(json.dumps([]))
        return 0

    depth = getattr(args, "depth", 5)
    records = records[-depth:]

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
        promoted_iso = r.promoted_at.isoformat()
        print(
            f"  {r.rule_name} v{r.version}  approver={r.approver}  promoted={promoted_iso}{retired}"
        )
        if r.derived_from:
            print(f"    derived_from: {', '.join(r.derived_from)}")
    return 0


__all__ = ["add_subparser", "dispatch"]
