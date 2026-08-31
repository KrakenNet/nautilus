"""PatternMatchingIntentAnalyzer — design §3.3.

Keyword-map scanning + regex entity extraction (CVE IDs). Deterministic ordering
is enforced by alphabetically sorting ``data_types_needed`` and ``entities``
before returning (NFR-13, AC-2.2).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from nautilus.core.models import IntentAnalysis

if TYPE_CHECKING:
    from collections.abc import Iterable

    from nautilus.config.models import SourceConfig

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


def build_keyword_map(
    sources: Iterable[SourceConfig],
    explicit_keyword_map: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Materialize the analyzer keyword map: generated base vocab + explicit overlay.

    For every ``data_type`` token declared across ``sources``
    (:attr:`SourceConfig.data_types`) a base entry is generated mapping that
    data type to two keywords: the raw token and a normalized form with
    underscores replaced by spaces (e.g. ``"scan_result"`` →
    ``["scan_result", "scan result"]``). The space form is omitted when it
    equals the raw token, so single-word types yield a single keyword.

    ``explicit_keyword_map`` entries from ``analysis.keyword_map`` are then
    overlaid by **union**, explicit keywords first: an operator who curates
    synonyms for a data type adds to its vocabulary and never subtracts from
    it. Replacing the generated base wholesale used to mean that adding
    ``orders: ["purchase order"]`` silently removed the word *orders* — the
    name every source advertises and ``/v1/sources`` publishes — so an intent
    naming the advertised data type verbatim matched nothing. Keys the
    generated base does not cover are carried through as given.

    Pure function: no I/O, deterministic output for a given input.
    """
    generated: dict[str, list[str]] = {}
    for source in sources:
        for data_type in source.data_types:
            if data_type in generated:
                continue
            normalized = data_type.replace("_", " ")
            keywords = [data_type] if normalized == data_type else [data_type, normalized]
            generated[data_type] = keywords
    merged: dict[str, list[str]] = dict(generated)
    for data_type, keywords in explicit_keyword_map.items():
        base = merged.get(data_type, [])
        merged[data_type] = keywords + [kw for kw in base if kw not in keywords]
    return merged


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
