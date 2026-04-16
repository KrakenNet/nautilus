"""PatternMatchingIntentAnalyzer — design §3.3.

Keyword-map scanning + regex entity extraction (CVE IDs). Deterministic ordering
is enforced by alphabetically sorting ``data_types_needed`` and ``entities``
before returning (NFR-13, AC-2.2).
"""

from __future__ import annotations

import re
from typing import Any

from nautilus.core.models import IntentAnalysis

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


class PatternMatchingIntentAnalyzer:
    """Deterministic keyword + regex based :class:`IntentAnalyzer` implementation."""

    def __init__(self, keyword_map: dict[str, list[str]]) -> None:
        # Lower-case keywords once for case-insensitive scanning.
        self._keyword_map: dict[str, list[str]] = {
            data_type: [kw.lower() for kw in keywords]
            for data_type, keywords in keyword_map.items()
        }

    def analyze(self, intent: str, context: dict[str, Any]) -> IntentAnalysis:
        """Scan ``intent`` for configured keywords and CVE identifiers.

        Args:
            intent: Raw agent intent string.
            context: Per-request context (unused by this analyzer; kept
                for Protocol compatibility).

        Returns:
            An :class:`IntentAnalysis` with alphabetically-sorted
            ``data_types_needed`` and ``entities`` for determinism
            (NFR-13, AC-2.2).
        """
        lowered = intent.lower()
        data_types_needed = [
            data_type
            for data_type, keywords in self._keyword_map.items()
            if any(kw in lowered for kw in keywords)
        ]
        entities = _CVE_PATTERN.findall(intent)
        return IntentAnalysis(
            raw_intent=intent,
            data_types_needed=sorted(set(data_types_needed)),
            entities=sorted(set(entities)),
        )
