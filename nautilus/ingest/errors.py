"""Ingest-integrity error hierarchy (US-4, design §"Ingest Integrity").

These are raised by the ingest orchestrator and its collaborators
(:class:`~nautilus.ingest.validator.SchemaValidator`,
:class:`~nautilus.ingest.schema_change.SchemaChangeDetector`) when the
per-source :class:`~nautilus.ingest.config.IngestIntegrityConfig` dictates
fail-closed behaviour. Both are simple markers; callers use ``isinstance``
to branch on failure mode.
"""

from __future__ import annotations


class SchemaViolationError(Exception):
    """Raised when a row fails JSON-schema validation under ``on_schema_violation="reject"``."""


class IngestPausedError(Exception):
    """Raised on publisher schema drift when ``on_publisher_schema_change="pause"``."""
