"""Shared audit-JSONL helpers for integration tests.

Each broker request emits one ``event_type == "request"`` entry plus an
``attestation_emitted`` companion event (AC-19.b); the NFR-8 / NFR-15
one-line-per-request invariants apply to the request entries, so tests
count lines through :func:`request_lines`.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from nautilus.audit.logger import NAUTILUS_METADATA_KEY

if TYPE_CHECKING:
    from pathlib import Path


def request_lines(audit_path: Path) -> list[str]:
    """Return only request-level audit lines from the JSONL file."""
    lines: list[str] = []
    for raw in audit_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        record = cast("dict[str, Any]", json.loads(raw))
        entry = cast(
            "dict[str, Any]", json.loads(record["metadata"][NAUTILUS_METADATA_KEY])
        )
        if entry.get("event_type", "request") == "request":
            lines.append(raw)
    return lines
