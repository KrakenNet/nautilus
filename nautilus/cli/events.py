"""``nautilus events`` subcommand surface (DQ5 LOCKED).

Subcommands:
    events list [--json]

Source of truth for the runtime-side enumeration of all known
``event_type`` values. Paired with the Literal at
``nautilus/core/models.py:218`` via a drift-guard test
(``tests/unit/test_event_type_drift.py``).
"""

from __future__ import annotations

import argparse
import json

from nautilus.cli._common import err


def list_event_types() -> list[str]:
    """Return the canonical set of known ``event_type`` values.

    Paired with the Literal at ``nautilus/core/models.py:218`` via
    a drift-guard test.
    """
    return [
        "request",
        "handoff_declared",
        "attestation_emitted",
        "session_token_issued",
        "session_token_verification_failed",
        "signing_key_rotated",
        "signing_key_revoked",
        "proposal_emitted",
        "proposal_validated",
        "proposal_approved",
        "proposal_rejected",
        "proposal_promoted",
        "meta_rule_fired",
        "relationship_observed",
        "rule_promoted",
        "rule_retracted",
        "rule_rolled_back",
        "adapter_quarantined",
        "adapter_unquarantined",
        "schema_drift_detected",
        "schema_drift_severity_overridden",
    ]


def add_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    """Add ``events`` group to the top-level argparse subparsers."""
    p_events = sub.add_parser("events", help="Event type enumeration (DQ5).")
    events_sub = p_events.add_subparsers(dest="events_subcommand", metavar="subcommand")

    # list
    p_list = events_sub.add_parser("list", help="List all known event_type values.")
    p_list.add_argument("--json", action="store_true", help="Emit JSON array to stdout.")


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``events`` invocation. Returns process exit code."""
    sub = getattr(args, "events_subcommand", None)
    if sub == "list":
        return _cmd_list(args)
    err("events: subcommand required (list).")
    return 1


def _cmd_list(args: argparse.Namespace) -> int:
    """Print all known event_type values."""
    types = list_event_types()
    if getattr(args, "json", False):
        print(json.dumps(types))
    else:
        for t in types:
            print(t)
    return 0


__all__ = ["add_subparser", "dispatch", "list_event_types"]
