"""The one place ``audit.chained`` is turned into an audit sink.

Every writer of the audit log has to agree on its shape, because the shape is
the integrity guarantee: with ``audit.chained`` on, each line is a signed
envelope carrying ``prev_sha256`` linkage, and a single plain line appended
into the middle of that chain breaks offline verification of the file
permanently. There is no repair — the plain line has no predecessor hash to
rebuild from.

This lived as ``Broker._build_audit_sink``, where the other writers could not
reach it without importing the broker, so they opened a ``FileSink`` instead
and corrupted chained logs. It is a config-to-sink function with no broker
state, so it belongs beside :class:`~nautilus.audit.logger.AuditLogger` in the
package every writer already depends on.

Reaching it is not always the answer. A chained log admits exactly one writer,
so a caller running inside a process that already has an ``AuditLogger`` — the
REST rule-validation route inside the broker — must be handed that logger
rather than build a second sink here: two sinks over one chain is the same
corruption by a different route, and the writer lock would refuse the second
anyway.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fathom.audit import FileSink

if TYPE_CHECKING:
    from pathlib import Path

    from fathom.attestation import AttestationService

    from nautilus.config.models import NautilusConfig

log = logging.getLogger(__name__)

__all__ = ["build_audit_sink"]


def build_audit_sink(
    config: NautilusConfig,
    audit_path: Path,
    attestation: AttestationService | None,
) -> Any:
    """``FileSink``, or a hash-chained log when ``audit.chained`` is set.

    ``ChainedAttestationLog.write`` satisfies the same ``AuditSink``
    protocol ``FileSink`` does, so chaining is a swap of the sink rather
    than a second write path. It signs each line, so it fails closed on a
    config that asks for integrity without a key to sign with.
    """
    if not config.audit.chained:
        return FileSink(path=audit_path)
    if attestation is None:
        msg = (
            "audit.chained requires attestation.enabled with a signing key: "
            "each chained line carries a JWS, and there is nothing to sign with"
        )
        raise ValueError(msg)
    if not config.attestation.private_key_path and audit_path.exists():
        msg = (
            f"audit.chained cannot append to the existing chain at {audit_path} "
            f"with an auto-generated signing key: attestation.private_key_path is "
            f"unset, so this process signs with a key the lines already on disk "
            f"were not signed by, and every request would fail closed on a log "
            f"that reads as corrupt. Set attestation.private_key_path to the key "
            f"that wrote them, or start a new chain at a new audit.path."
        )
        raise ValueError(msg)
    if not config.attestation.private_key_path:
        log.warning(
            "audit.chained is on with an auto-generated attestation key: this "
            "chain is signed by this process only and the next boot will refuse "
            "to append to it. Set attestation.private_key_path to keep it.",
        )
    from fathom.chained_log import ChainedAttestationLog

    from nautilus.core.attestation_sink import SingleWriterAuditSink

    return SingleWriterAuditSink(
        ChainedAttestationLog(
            audit_path,
            attestation,
            checkpoint_interval=config.audit.checkpoint_interval,
        ),
        audit_path,
    )
