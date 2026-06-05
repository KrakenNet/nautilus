"""``nautilus attestation`` subcommand surface.

Subcommands:
    attestation verify <log> [--pubkey PEM] [--expected-head HEX]
                             [--anchor-token JWS] [--json]

Offline verification of a chained attestation log written by
:class:`nautilus.core.attestation_sink.ChainedFileAttestationSink`
(``attestation.sink.chained: true``). Checks hash linkage and every line's
EdDSA JWS; with ``--expected-head`` / ``--anchor-token`` it also detects
tail truncation against an out-of-band anchor.

Exit codes follow the CLI contract: 0 chain valid, 1 user error (missing
file/key), 2 verification failure.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from nautilus.cli._common import err, ok


def add_subparser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Add ``attestation`` group to the top-level argparse subparsers."""
    p_att = sub.add_parser(
        "attestation", help="Chained attestation log tools (offline verify)."
    )
    att_sub = p_att.add_subparsers(dest="attestation_subcommand", metavar="subcommand")

    p_verify = att_sub.add_parser(
        "verify", help="Offline-verify a chained attestation log (chain + JWS)."
    )
    p_verify.add_argument("log", help="Chained attestation JSONL log path.")
    p_verify.add_argument(
        "--pubkey",
        default=None,
        help="Ed25519 public key PEM (default: <log>.pub.pem beside the log).",
    )
    p_verify.add_argument(
        "--expected-head",
        default=None,
        dest="expected_head",
        help="Out-of-band mirrored line hash; fails if absent (tail truncation).",
    )
    p_verify.add_argument(
        "--anchor-token",
        default=None,
        dest="anchor_token",
        help="Checkpoint JWS token; its checkpoint line must appear in the log.",
    )
    p_verify.add_argument("--json", action="store_true", help="Emit JSON to stdout.")


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``attestation`` invocation. Returns exit code."""
    sub = getattr(args, "attestation_subcommand", None)
    if sub == "verify":
        return _cmd_verify(args)
    err("attestation: subcommand required (verify).")
    return 1


def _cmd_verify(args: argparse.Namespace) -> int:
    from dataclasses import asdict

    from fathom.chained_log import verify_chain

    log_path = Path(args.log)
    # Matches fathom's ChainedAttestationLog.public_key_path derivation.
    pubkey_path = (
        Path(args.pubkey)
        if args.pubkey
        else log_path.with_name(log_path.name + ".pub.pem")
    )

    if not log_path.exists():
        err(f"attestation verify: log not found: {log_path}")
        return 1
    if not pubkey_path.exists():
        err(f"attestation verify: pubkey not found: {pubkey_path}")
        return 1

    result = verify_chain(
        log_path,
        pubkey_path,
        expected_head=args.expected_head,
        anchor_token=args.anchor_token,
    )

    if args.json:
        print(json.dumps(asdict(result)))
    elif result.ok:
        anchored = " (anchor ok)" if result.anchor_ok else ""
        ok(f"chain valid — {result.count} records, head {result.head_sha256}{anchored}")
    else:
        err(f"attestation verify: {result.error}")

    return 0 if result.ok else 2
