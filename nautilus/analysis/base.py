"""IntentAnalyzer Protocol — design §3.3."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from nautilus.core.models import IntentAnalysis


@runtime_checkable
class IntentAnalyzer(Protocol):
    """Extracts structured :class:`IntentAnalysis` from a raw intent string."""

    def analyze(self, intent: str, context: dict[str, Any]) -> IntentAnalysis:
        """Classify ``intent`` into a structured :class:`IntentAnalysis`.

        Args:
            intent: Raw natural-language request from the agent.
            context: Per-request context (clearance, purpose, session id,
                optional embedding override, etc.).

        Returns:
            A populated :class:`IntentAnalysis` consumed by the router.
        """
        ...
