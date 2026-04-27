"""Ingest-integrity subsystem (US-4, design §"Ingest Integrity").

This package houses the schema validation, baseline tracking, schema-change
detection, and corroboration machinery layered over ``Source.ingest()`` so
downstream pipeline stages see either validated rows or an explicit pause.

Task 25 lands only the config model + error hierarchy; subsequent Phase-5
tasks (26-31) add the validator, baseline store/tracker, schema-change
detector, ack store, and the orchestration hook on ``RESTAdapter.execute()``.
"""

from __future__ import annotations

from nautilus.ingest.config import IngestIntegrityConfig
from nautilus.ingest.errors import IngestPausedError, SchemaViolationError

__all__ = [
    "IngestIntegrityConfig",
    "IngestPausedError",
    "SchemaViolationError",
]
