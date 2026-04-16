"""Nautilus forensics package (design §3.7).

Exposes :class:`ProcessedOffsets` (atomic on-disk tailer state with bounded
seen-hash LRU), :class:`OffsetsCorruptError` (raised on malformed or
non-monotonic persisted state), and the :class:`ForensicSink` Protocol with
its two concrete implementations (:class:`JSONLForensicSink`,
:class:`HttpForensicSink`).
"""

from nautilus.forensics.offsets import (
    SEEN_HASH_CAP,
    OffsetsCorruptError,
    ProcessedOffsets,
)
from nautilus.forensics.sinks import (
    ForensicSink,
    HttpForensicSink,
    JSONLForensicSink,
)

__all__ = [
    "SEEN_HASH_CAP",
    "ForensicSink",
    "HttpForensicSink",
    "JSONLForensicSink",
    "OffsetsCorruptError",
    "ProcessedOffsets",
]
