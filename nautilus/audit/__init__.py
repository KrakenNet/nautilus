"""Nautilus audit package — :class:`AuditLogger` facade (design §3.7)."""

from __future__ import annotations

from nautilus.audit.logger import (
    NAUTILUS_METADATA_KEY,
    AuditLogger,
    AuditSink,
    decode_nautilus_entry,
)

__all__ = [
    "NAUTILUS_METADATA_KEY",
    "AuditLogger",
    "AuditSink",
    "decode_nautilus_entry",
]
