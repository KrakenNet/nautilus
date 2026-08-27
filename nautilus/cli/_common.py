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
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nautilus.audit.logger import AuditLogger


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


def open_audit_logger(config_path: str | None = None) -> AuditLogger:
    """Audit sink for a governance decision made outside ``Broker.arequest``.

    Approving, rejecting, retracting, and rolling back a rule are the changes
    the audit log exists to record, and every one of them ran with
    ``audit_logger=None`` because these subcommands never had a config to read
    a sink from. There is no "no sink" answer here: without ``--config`` the
    default :class:`~nautilus.config.models.AuditConfig` path is used, which is
    the same ``./audit.jsonl`` that ``rules validate --sandbox`` already reads
    by default.

    A config that cannot be loaded is not fatal to the decision, but the
    operator must see where the record actually went, so the fallback warns.
    """
    from fathom.audit import FileSink

    from nautilus.audit.logger import AuditLogger

    return AuditLogger(sink=FileSink(path=audit_path_for(config_path)))


def audit_path_for(config_path: str | None = None) -> Path:
    """The audit log a config names, resolved the way the broker resolves it.

    A relative ``audit.path`` is relative to the config file's directory, not
    to the process's working directory — see
    :meth:`nautilus.core.Broker._resolve`. Without a config the default
    ``./audit.jsonl`` is used, which is what ``rules validate --sandbox``
    already reads by default.
    """
    from nautilus.config.models import AuditConfig

    path = Path(AuditConfig().path)
    if not config_path:
        return path
    from nautilus.config.loader import load_config

    try:
        declared = Path(load_config(config_path).audit.path)
    except Exception as exc:  # noqa: BLE001 — the decision still gets logged
        warn(f"could not read audit path from {config_path!r} ({exc}); using {path}")
        return path
    return declared if declared.is_absolute() else Path(config_path).parent / declared


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


__all__ = [
    "audit_path_for",
    "err",
    "fail",
    "ok",
    "open_audit_logger",
    "require_reviewer",
    "warn",
]
