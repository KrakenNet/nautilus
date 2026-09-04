"""``nautilus init`` — write a ``nautilus.yaml`` that loads and answers.

Every other scaffold in the CLI exists — ``adapters new`` generates a whole
adapter package — but the one file every user needs first had to be copied out
of the docs by hand, and the copy in the README did not load. The config this
writes serves rows declared in itself (source type ``static``), so it runs with
no database, no driver and no adapter code.
"""

from __future__ import annotations

import argparse
import os
import secrets
from pathlib import Path

from nautilus.cli._common import err, ok

# Written verbatim rather than dumped from a model: the comments are the point.
_TEMPLATE = """\
# Written by 'nautilus init'. See https://github.com/KrakenNet/nautilus
# (docs/getting-started.md).
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

# Every route that reads data needs a key. An empty list fails closed, which is
# the right default and a poor first run: without this block 'nautilus serve'
# starts clean and answers 401 to /v1/sources and /v1/request. Replace this
# generated key before anyone else can reach the port.
api:
  keys:
    - __API_KEY__
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
    # A fresh key per scaffold: a constant here would ship one shared secret to
    # everyone who ever ran the command.
    api_key = secrets.token_hex(16)
    # 0600 at creation, not chmod after: the file holds a live credential, and
    # a write_text() at the default 0644 leaves it world-readable for however
    # long the chmod takes. O_EXCL also makes the exists() check above race-free.
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(_TEMPLATE.replace("__API_KEY__", api_key))

    ok(f"wrote {target} (mode 0600)")
    print("  next steps :")
    print(f"    nautilus serve --config {target}   # REST on 127.0.0.1:8000")
    print("    nautilus demo                       # a governed handoff decision")
    print()
    # The key is printed nowhere: stdout is scrollback, CI logs and screen
    # shares. It is in the file, at 0600, which is the one place it belongs.
    print(f"  the generated api key is the api.keys entry in {target}:")
    print("    curl -H 'X-API-Key: <that key>' http://127.0.0.1:8000/v1/sources")
    return 0


__all__ = ["add_subparser", "dispatch"]
