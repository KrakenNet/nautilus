"""``nautilus init`` — write a ``nautilus.yaml`` that loads and answers.

Every other scaffold in the CLI exists — ``adapters new`` generates a whole
adapter package — but the one file every user needs first had to be copied out
of the docs by hand, and the copy in the README did not load. The config this
writes serves rows declared in itself (source type ``static``), so it runs with
no database, no driver and no adapter code.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from nautilus.cli._common import err, ok

# Written verbatim rather than dumped from a model: the comments are the point.
_TEMPLATE = """\
# Written by 'nautilus init'. See https://github.com/ (docs/getting-started.md).
#
# This config serves the rows below with no database attached. Point a real
# source at your data by replacing the 'static' block with, say:
#
#   - id: main-db
#     type: postgres
#     classification: confidential
#     data_types: [users, orders]
#     connection: ${DATABASE_URL}
#     table: public.orders

sources:
  - id: orders
    type: static
    description: Sample order rows, served from this file.
    classification: unclassified
    data_types: [orders]
    allowed_purposes: [support]
    rows:
      - {order_id: 1001, user_id: 42, total: 19.99}
      - {order_id: 1002, user_id: 43, total: 7.50}

# Declared agents are how clearance and purpose stop being whatever the caller
# claims. Undeclared, the broker takes the caller's word for both and warns.
agents:
  agent-alpha:
    id: agent-alpha
    clearance: confidential
    allowed_purposes: [support]

attestation:
  enabled: true

audit:
  path: ./audit.jsonl
"""


def add_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # pyright: ignore[reportPrivateUsage]
    """Add the ``init`` command to the top-level subparsers."""
    p = sub.add_parser("init", help="Write a runnable nautilus.yaml in the current directory.")
    p.add_argument(
        "--dir",
        default=".",
        dest="dir",
        help="Directory to write nautilus.yaml into (default: current directory).",
    )


def dispatch(args: argparse.Namespace) -> int:
    """Write the config. Returns the process exit code."""
    target = Path(getattr(args, "dir", ".")) / "nautilus.yaml"
    if target.exists():
        err(f"{target} already exists — refusing to overwrite it")
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_TEMPLATE, encoding="utf-8")

    ok(f"wrote {target}")
    print("  next steps :")
    print(f"    nautilus serve --config {target}   # REST on 127.0.0.1:8000")
    print("    nautilus demo                       # a governed handoff decision")
    return 0


__all__ = ["add_subparser", "dispatch"]
