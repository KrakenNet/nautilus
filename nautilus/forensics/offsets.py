"""Processed-offsets state for forensic log tailers (design §3.7).

Tracks the last byte offset consumed from a source log plus a bounded LRU of
already-seen line SHA-256 hashes so crash-restart does not re-ingest lines.
Persisted to disk via atomic temp-file-rename so partial writes cannot corrupt
the on-disk state. Load rejects malformed JSON and structurally-invalid payloads
by raising :class:`OffsetsCorruptError`; save refuses to regress the on-disk
``last_byte_offset`` (monotonic guard).
"""

from __future__ import annotations

import json
import os
from collections import deque
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, PrivateAttr

SEEN_HASH_CAP: int = 10**6


class OffsetsCorruptError(Exception):
    """Raised when a persisted offsets file is unreadable or structurally invalid."""


class ProcessedOffsets(BaseModel):
    """Persisted tailer state: byte offset + bounded seen-hash set."""

    last_byte_offset: int = 0
    seen_line_sha256: set[str] = Field(default_factory=set)

    _order: deque[str] = PrivateAttr(default_factory=lambda: deque(maxlen=SEEN_HASH_CAP))

    def model_post_init(self, __context: Any) -> None:
        """Rehydrate the LRU deque from the persisted hash set.

        Pydantic v2 hook invoked after field validation. Set ordering is
        best-effort across restarts; the cap on ``_order`` is the
        load-bearing invariant. If the persisted set exceeds the cap, it is
        trimmed down to the deque contents.

        Args:
            __context: Pydantic validation context (unused).
        """
        # Reconstruct the LRU deque from whatever order the set yields. Ordering
        # is best-effort across restarts (Python sets do not preserve insertion
        # order); the cap is the load-bearing invariant.
        self._order = deque(self.seen_line_sha256, maxlen=SEEN_HASH_CAP)
        # If a caller passed in a set already over the cap, trim to cap.
        if len(self.seen_line_sha256) > SEEN_HASH_CAP:
            self.seen_line_sha256 = set(self._order)

    def mark_seen(self, sha: str) -> None:
        """Record a line hash; evicts the oldest entry once the cap is reached."""
        if sha in self.seen_line_sha256:
            return
        if len(self._order) == SEEN_HASH_CAP:
            evicted = self._order[0]
            # deque with maxlen will drop evicted on append; mirror that in the set.
            self.seen_line_sha256.discard(evicted)
        self._order.append(sha)
        self.seen_line_sha256.add(sha)

    @classmethod
    def load(cls, path: Path) -> ProcessedOffsets:
        """Load offsets from ``path``; return a fresh empty instance if absent."""
        if not path.exists():
            return cls()
        try:
            raw = path.read_text(encoding="utf-8")
            payload: object = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise OffsetsCorruptError(f"unreadable offsets file {path}: {exc}") from exc

        if not isinstance(payload, dict):
            raise OffsetsCorruptError(
                f"offsets payload must be a JSON object, got {type(payload).__name__}"
            )
        payload_dict: dict[str, object] = {str(k): v for k, v in payload.items()}  # type: ignore[redundant-cast]

        offset_raw: object = payload_dict.get("last_byte_offset", 0)
        if isinstance(offset_raw, bool) or not isinstance(offset_raw, int):
            raise OffsetsCorruptError(
                f"last_byte_offset must be int, got {type(offset_raw).__name__}"
            )
        if offset_raw < 0:
            raise OffsetsCorruptError(f"last_byte_offset must be non-negative, got {offset_raw}")

        seen_raw: object = payload_dict.get("seen_line_sha256", [])
        if not isinstance(seen_raw, list):
            raise OffsetsCorruptError(
                f"seen_line_sha256 must be list, got {type(seen_raw).__name__}"
            )
        seen_strs: list[str] = []
        for item in seen_raw:  # type: ignore[misc]
            if not isinstance(item, str):
                raise OffsetsCorruptError(
                    f"seen_line_sha256 entries must be str, got {type(item).__name__}"  # type: ignore[unreachable]
                )
            seen_strs.append(item)

        return cls(last_byte_offset=offset_raw, seen_line_sha256=set(seen_strs))

    def save(self, path: Path) -> None:
        """Atomically persist state to ``path`` via temp-file-rename.

        Refuses to regress ``last_byte_offset`` vs. the on-disk state
        (monotonic guard): raises :class:`OffsetsCorruptError` if the current
        instance's offset is less than the persisted one.
        """
        if path.exists():
            try:
                existing = ProcessedOffsets.load(path)
            except OffsetsCorruptError:
                # Existing file is corrupt; overwriting it is the intended recovery path.
                existing = None
            if existing is not None and self.last_byte_offset < existing.last_byte_offset:
                raise OffsetsCorruptError(
                    f"refusing non-monotonic save: current={self.last_byte_offset} "
                    f"< persisted={existing.last_byte_offset}"
                )

        tmp = path.with_suffix(path.suffix + ".tmp")
        payload = {
            "last_byte_offset": self.last_byte_offset,
            "seen_line_sha256": sorted(self.seen_line_sha256),
        }
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, path)


__all__ = ["OffsetsCorruptError", "ProcessedOffsets", "SEEN_HASH_CAP"]
