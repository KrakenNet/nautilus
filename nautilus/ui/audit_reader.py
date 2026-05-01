"""Seek-based JSONL audit reader for the Admin UI (design SS 9.1, FR-6/7/8).

Provides O(1) page access on GB-sized audit files by encoding byte offsets
as opaque base64 cursors.  Each JSONL line is an outer Fathom
:class:`AuditRecord`; the inner Nautilus :class:`AuditEntry` is extracted
via :func:`decode_nautilus_entry` (double-parse).

Filters (agent_id, source_id, event_type, start/end) are applied in-memory
after reading a page of lines.  This is acceptable because page sizes are
small (default 50) and the seek avoids scanning from the start of the file.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from fathom.models import AuditRecord

from nautilus.audit.logger import decode_nautilus_entry
from nautilus.core.models import AuditEntry

log = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE: int = 50


@dataclass
class AuditPage:
    """One page of audit entries with cursor-based navigation."""

    entries: list[AuditEntry] = field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]
    next_cursor: str | None = None
    prev_cursor: str | None = None
    total_estimate: int = 0


class AuditReader:
    """Seek-based JSONL audit reader with cursor pagination.

    Cursors are base64-encoded byte offsets into the audit file.  Invalid or
    tampered cursors silently fall back to offset 0 (page 1).

    For descending sort (default) the reader starts from the end of the file
    and reads backwards.  For ascending sort it starts from the beginning.
    """

    def __init__(self, audit_path: str | Path, page_size: int = DEFAULT_PAGE_SIZE) -> None:
        self._path = Path(audit_path)
        self._page_size = page_size

    # -- cursor helpers ------------------------------------------------

    @staticmethod
    def _encode_cursor(offset: int) -> str:
        """Encode a byte offset as a base64 cursor string."""
        return base64.urlsafe_b64encode(str(offset).encode()).decode()

    @staticmethod
    def _decode_cursor(cursor: str | None) -> int:
        """Decode a base64 cursor to a byte offset.  Falls back to 0."""
        if cursor is None:
            return 0
        try:
            decoded = base64.urlsafe_b64decode(cursor.encode()).decode()
            offset = int(decoded)
            return max(offset, 0)
        except (ValueError, Exception):
            log.warning("Invalid audit cursor %r — resetting to page 1", cursor)
            return 0

    # -- core reader ---------------------------------------------------

    def read_page(
        self,
        cursor: str | None = None,
        *,
        agent_id: str | None = None,
        source_id: str | None = None,
        event_type: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        sort: Literal["asc", "desc"] = "desc",
    ) -> AuditPage:
        """Read one page of audit entries from the JSONL file.

        Args:
            cursor: Opaque base64 cursor from a previous page (byte offset).
            agent_id: Filter entries to this agent.
            source_id: Filter entries that queried this source.
            event_type: Filter by ``AuditEntry.event_type``.
            start: Include entries at or after this timestamp.
            end: Include entries at or before this timestamp.
            sort: ``"desc"`` (default, newest first) or ``"asc"``.

        Returns:
            An :class:`AuditPage` with up to ``page_size`` entries and
            navigation cursors.
        """
        if not self._path.exists():
            log.warning("Audit file not found: %s — returning empty page", self._path)
            return AuditPage()

        file_size = self._path.stat().st_size
        if file_size == 0:
            return AuditPage()

        total_estimate = self._estimate_total()
        offset = self._decode_cursor(cursor)

        args = (offset, file_size, total_estimate, agent_id, source_id, event_type, start, end)
        if sort == "desc":
            return self._read_desc(*args)
        return self._read_asc(*args)

    # -- ascending (forward) -------------------------------------------

    def _read_asc(
        self,
        offset: int,
        file_size: int,
        total_estimate: int,
        agent_id: str | None,
        source_id: str | None,
        event_type: str | None,
        start: datetime | None,
        end: datetime | None,
    ) -> AuditPage:
        entries: list[AuditEntry] = []
        next_offset: int | None = None
        prev_cursor: str | None = self._encode_cursor(max(offset - 1, 0)) if offset > 0 else None

        with open(self._path, encoding="utf-8") as fh:
            fh.seek(offset)
            # If we seeked into the middle of a line, skip to next newline
            if offset > 0:
                fh.readline()

            while len(entries) < self._page_size:
                line = fh.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                entry = self._parse_line(line)
                if entry is None:
                    continue
                if self._matches(entry, agent_id, source_id, event_type, start, end):
                    entries.append(entry)
                next_offset = fh.tell()

        next_cursor: str | None = None
        if next_offset is not None and next_offset < file_size:
            next_cursor = self._encode_cursor(next_offset)
        return AuditPage(
            entries=entries,
            next_cursor=next_cursor,
            prev_cursor=prev_cursor,
            total_estimate=total_estimate,
        )

    # -- descending (backward) -----------------------------------------

    def _read_desc(
        self,
        offset: int,
        file_size: int,
        total_estimate: int,
        agent_id: str | None,
        source_id: str | None,
        event_type: str | None,
        start: datetime | None,
        end: datetime | None,
    ) -> AuditPage:
        """Read pages from the end of the file backwards."""
        # For desc, cursor=0 means "start from the end".
        # A non-zero cursor means "start reading backwards from this offset".
        read_end = file_size if offset == 0 else offset
        lines = self._read_lines_backwards(read_end, self._page_size * 2)

        entries: list[AuditEntry] = []
        consumed_up_to = read_end  # track where we stopped
        first_line_offset: int | None = None

        for line_text, line_offset in lines:
            entry = self._parse_line(line_text)
            if entry is None:
                continue
            if self._matches(entry, agent_id, source_id, event_type, start, end):
                entries.append(entry)
                if first_line_offset is None or line_offset < first_line_offset:
                    first_line_offset = line_offset
                if len(entries) >= self._page_size:
                    consumed_up_to = line_offset
                    break

        # next_cursor = further back in the file (older entries)
        has_older = consumed_up_to > 0 and len(entries) >= self._page_size
        next_cursor = self._encode_cursor(consumed_up_to) if has_older else None
        # prev_cursor = toward end of file (newer entries)
        prev_cursor = self._encode_cursor(read_end) if read_end < file_size else None

        return AuditPage(
            entries=entries,
            next_cursor=next_cursor,
            prev_cursor=prev_cursor,
            total_estimate=total_estimate,
        )

    def _read_lines_backwards(self, from_offset: int, max_lines: int) -> list[tuple[str, int]]:
        """Read up to ``max_lines`` complete lines backwards from ``from_offset``.

        Returns list of (line_text, line_start_offset) tuples, ordered
        newest-first (highest offset first).
        """
        if from_offset <= 0:
            return []

        chunk_size = 8192
        result: list[tuple[str, int]] = []
        remaining = from_offset
        leftover = ""

        with open(self._path, encoding="utf-8") as fh:
            while remaining > 0 and len(result) < max_lines:
                read_size = min(chunk_size, remaining)
                start_pos = remaining - read_size
                fh.seek(start_pos)
                chunk = fh.read(read_size)
                remaining = start_pos

                chunk = chunk + leftover
                parts = chunk.split("\n")
                # First part may be a partial line (split mid-line); save it
                leftover = parts[0]

                # Process remaining parts in reverse (newest first)
                for part in reversed(parts[1:]):
                    text = part.strip()
                    if not text:
                        continue
                    # Approximate offset for this line
                    line_offset = start_pos + chunk.rfind(part)
                    result.append((text, max(line_offset, 0)))
                    if len(result) >= max_lines:
                        break

            # Handle leftover (the very first line in the read region)
            if leftover.strip() and len(result) < max_lines:
                result.append((leftover.strip(), 0))

        return result

    # -- parsing / filtering -------------------------------------------

    @staticmethod
    def _parse_line(line: str) -> AuditEntry | None:
        """Parse a JSONL line: outer AuditRecord -> inner AuditEntry."""
        try:
            raw = json.loads(line)
            record = AuditRecord.model_validate(raw)
            return decode_nautilus_entry(record)
        except (json.JSONDecodeError, KeyError, Exception):
            log.warning("Skipping corrupt audit line: %.120s", line)
            return None

    @staticmethod
    def _matches(
        entry: AuditEntry,
        agent_id: str | None,
        source_id: str | None,
        event_type: str | None,
        start: datetime | None,
        end: datetime | None,
    ) -> bool:
        """Return True if entry passes all provided filters."""
        if agent_id is not None and entry.agent_id != agent_id:
            return False
        if source_id is not None and source_id not in entry.sources_queried:
            return False
        if event_type is not None and entry.event_type != event_type:
            return False
        if start is not None and entry.timestamp < start:
            return False
        return not (end is not None and entry.timestamp > end)

    def _estimate_total(self) -> int:
        """Estimate total lines by sampling average line length."""
        if not self._path.exists():
            return 0
        file_size = self._path.stat().st_size
        if file_size == 0:
            return 0
        # Sample first few lines to estimate average line length
        sample_bytes = min(file_size, 4096)
        with open(self._path, encoding="utf-8") as fh:
            sample = fh.read(sample_bytes)
        lines = [ln for ln in sample.split("\n") if ln.strip()]
        if not lines:
            return 0
        avg_len = sum(len(ln) for ln in lines) / len(lines)
        return max(1, int(file_size / avg_len)) if avg_len > 0 else 0


__all__ = ["AuditPage", "AuditReader"]
