"""Shared type aliases for nautilus core persistence stores."""

from __future__ import annotations

from typing import Literal

__all__ = ["FailureMode"]

FailureMode = Literal["fail_closed", "fallback_memory"]
"""Shared failure-mode enum for persistence stores with degraded-memory fallback.

Used by ``BasePostgresStore`` and all store subclasses (``PostgresSessionStore``,
``SourceStateStore``, ``IngestBaselineStore``, ``QuarantineLogStore``, ``SchemaAckStore``)
to express the standard ``fail_closed`` vs ``fallback_memory`` contract.
"""
