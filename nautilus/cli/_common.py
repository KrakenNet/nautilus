"""Shared CLI helpers — ``--json`` / ``--yes`` / ``NAUTILUS_REVIEWER`` / prefixes.

Per ``.forge/shared.md`` CLI contract:
- Exit codes: 0 success, 1 user error, 2 validation/policy failure.
  Code 3 explicitly NOT used (OQ5 LOCKED).
- Output prefixes: ``OK:`` / ``ERROR:`` / ``WARN:`` / ``FAIL:`` (no
  Unicode sigils). Matches existing ``nautilus/cli/__init__.py:124,170,184``.
- ANSI color only when ``sys.stdout.isatty()`` AND ``NO_COLOR`` unset.
"""

from __future__ import annotations

import os
import sys


def require_reviewer() -> str:
    """Return ``NAUTILUS_REVIEWER`` env or raise ``SystemExit(1)`` w/ hint.

    Reviewer identity is sourced from the env var only — no ``$USER``
    auto-detection (DQ4 LOCKED, anti-spoofing).
    """
    reviewer = os.environ.get("NAUTILUS_REVIEWER", "").strip()
    if not reviewer:
        print(
            "ERROR: NAUTILUS_REVIEWER env var required for this command."
            " Set it to your operator identity.",
            file=sys.stderr,
        )
        sys.exit(1)
    return reviewer


def ok(message: str) -> None:
    """Print ``OK: <message>`` to stdout."""
    print(f"OK: {message}")


def warn(message: str) -> None:
    """Print ``WARN: <message>`` to stderr."""
    print(f"WARN: {message}", file=sys.stderr)


def err(message: str) -> None:
    """Print ``ERROR: <message>`` to stderr."""
    print(f"ERROR: {message}", file=sys.stderr)


def fail(message: str) -> None:
    """Print ``FAIL: <message>`` to stderr (used for unreachable / network)."""
    print(f"FAIL: {message}", file=sys.stderr)


__all__ = ["err", "fail", "ok", "require_reviewer", "warn"]
