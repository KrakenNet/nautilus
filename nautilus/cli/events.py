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


def add_subparser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Add ``events`` group to the top-level argparse subparsers."""
    raise NotImplementedError(
        "DQ5: nautilus.cli.events.add_subparser not implemented"
    )


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``events`` invocation. Returns process exit code."""
    raise NotImplementedError(
        "DQ5: nautilus.cli.events.dispatch not implemented"
    )


__all__ = ["add_subparser", "dispatch", "list_event_types"]
