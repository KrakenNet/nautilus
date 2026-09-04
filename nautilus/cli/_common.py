"""Shared CLI helpers — ``--json`` / ``--yes`` / ``NAUTILUS_*`` env / prefixes.

Per ``.forge/shared.md`` CLI contract:
- Exit codes: 0 success, 1 user error, 2 validation/policy failure.
  Code 3 explicitly NOT used (OQ5 LOCKED).
- Output prefixes: ``OK:`` / ``ERROR:`` / ``WARN:`` / ``FAIL:`` (no
  Unicode sigils). Matches existing ``nautilus/cli/__init__.py:124,170,184``.

The CLI emits no ANSI colour at all, so it needs no ``NO_COLOR`` handling. This
docstring used to promise both, which is the sort of claim an operator checks by
exporting ``NO_COLOR`` and concluding the tool is broken.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fathom.attestation import AttestationService

    from nautilus.audit.logger import AuditLogger
    from nautilus.config.models import NautilusConfig


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

    The sink comes from :func:`nautilus.audit.sink.build_audit_sink`, the same
    function the broker builds its own with. Opening a plain ``FileSink`` here
    ignored ``audit.chained``, so approving a rule from the CLI appended an
    unchained line into a hash chain and destroyed offline verification of the
    log — the one file the approval exists to be recorded in.
    """
    from fathom.audit import FileSink

    from nautilus.audit.logger import AuditLogger
    from nautilus.audit.sink import build_audit_sink

    audit_path = audit_path_for(config_path)
    config = _config_or_none(config_path)
    if config is None:
        return AuditLogger(sink=FileSink(path=audit_path))
    sink = build_audit_sink(config, audit_path, _signing_key(config, config_path))
    refuse_unless_writable(sink)
    return AuditLogger(sink=sink)


def refuse_unless_writable(
    sink: Any,
    *,
    act: str = "this decision cannot be recorded, so it will not be taken",
    remedy: str = (
        "Take the decision through the running server's governance API, or stop the server first."
    ),
) -> None:
    """Stop now if this process cannot record the act it is about to perform.

    A chained log admits exactly one writer, and the lock is claimed at the
    first write — which in :func:`nautilus.rkm.review.approve` is *after* the
    rule has been promoted and the lineage row inserted. Failing there leaves a
    governance act in force with nothing in the log that says it happened.
    Probing here claims the lock before anything has been decided, so a refusal
    is a refusal rather than an unrecorded change.

    ``act`` and ``remedy`` are the two clauses that are not about the lock. The
    defaults are the governance wording, and ``nautilus adapters schema-ack``
    overrides both: it acknowledges a schema change rather than taking a
    governance decision, and the server exposes no API to do it through, so the
    default remedy would send an operator looking for a route that is not
    there. Everything between them is one sentence for one situation, because
    an operator meeting the audit writer lock should meet it once.
    """
    probe = getattr(sink, "probe", None)
    if not callable(probe):
        return
    problem: object = probe()
    if problem is None:
        return
    err(f"{act}: another process is writing the chained audit log. {remedy} ({problem})")
    sys.exit(2)


def _config_or_none(config_path: str | None) -> NautilusConfig | None:
    """The loaded config, or ``None`` when there is none to load.

    ``audit_path_for`` has already warned about an unreadable config by the
    time this runs; a second warning for the same file would be noise.
    """
    if not config_path:
        return None
    from nautilus.config.loader import load_config

    try:
        return load_config(config_path)
    except Exception:  # noqa: BLE001 — the decision still gets logged
        return None


def _signing_key(config: NautilusConfig, config_path: str | None) -> AttestationService | None:
    """The key a chained line is signed with, or ``None`` if there is none.

    Unlike the broker, a CLI process must never fall back to generating a
    keypair: it would sign one line with a key the rest of the chain was not
    signed by, which reads as corruption for the life of the file.
    ``build_audit_sink`` raises ``audit.chained requires attestation.enabled
    with a signing key`` when this returns ``None`` under ``audit.chained`` —
    for the CLI the unmet half is the key, not the switch.
    """
    if not config.audit.chained or not config.attestation.enabled:
        return None
    key_path = config.attestation.private_key_path
    if not key_path:
        return None
    from fathom.attestation import AttestationService

    resolved = Path(key_path)
    if not resolved.is_absolute():
        base = Path(config_path).parent if config_path else Path()
        resolved = base / resolved
    return AttestationService.from_private_key_bytes(resolved.read_bytes())


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


API_KEY_ENV = "NAUTILUS_API_KEY"
"""Environment variable every broker-facing subcommand reads its credential from.

Named to match ``NAUTILUS_REVIEWER`` — the CLI's other identity variable — and
to match the name the deployment manifests, the operator guide and the CLI
reference already use for this exact value (``deploy/secret.yaml``,
``deploy/configmap.yaml``, which interpolate it into ``api.keys``). Reusing it
means the broker host that already exports the key for the server exports it for
the operator shell too.
"""

API_KEY_HELP = (
    "X-API-Key for the broker. Omitted, the NAUTILUS_API_KEY environment "
    "variable is used instead — prefer that, because a credential passed here is "
    "readable by every local user in `ps` and is written to shell history."
)
"""``--api-key`` help text, written once so all three parsers say the same thing."""


def resolve_api_key(args: Any) -> str | None:
    """The broker credential for this invocation: ``--api-key``, then the env.

    A credential passed as a command-line argument sits in
    ``/proc/<pid>/cmdline`` for the life of the process, world-readable, so any
    local user reads it out of ``ps``; an interactive shell also writes it to
    history. ``--api-key`` stays, because every existing script passes it and it
    is a reasonable thing to do on a host nobody else logs into — but it is no
    longer the only way in.

    Resolved here, not in each parser, so the precedence is decided once for
    every subcommand that reaches a running broker, present and future:

    - an explicitly passed ``--api-key`` always wins, *including* an empty one,
      which means "send no credential" rather than "fall back to the
      environment" — a flag the operator typed is never silently overridden;
    - otherwise :data:`API_KEY_ENV`, stripped and treated as unset when blank.

    The environment value is stripped for the same reason
    :func:`require_reviewer` strips its own: a value produced by ``$(...)`` or
    read out of a file arrives with a trailing newline, and an ``X-API-Key``
    header with one on the end matches no configured key.

    There is deliberately no third path. Reading the key from stdin would close
    nothing the environment does not already close — the hazard is ``argv``, and
    ``argv`` is what this removes — while adding a mode in which the CLI blocks
    on a terminal that CI does not have.
    """
    flag: str | None = getattr(args, "api_key", None)
    if flag is not None:
        return flag
    return os.environ.get(API_KEY_ENV, "").strip() or None


__all__ = [
    "API_KEY_ENV",
    "API_KEY_HELP",
    "audit_path_for",
    "err",
    "fail",
    "ok",
    "open_audit_logger",
    "refuse_unless_writable",
    "require_reviewer",
    "resolve_api_key",
    "warn",
]
