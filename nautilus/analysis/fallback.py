"""`FallbackIntentAnalyzer` — design §3.8, FR-14.

Wraps a primary :class:`LLMIntentProvider` with a deterministic
:class:`IntentAnalyzer` fallback and per-call timeout. Catches the
exhaustive failure surface enumerated in AC-6.2 —
:class:`asyncio.TimeoutError` / :class:`builtins.TimeoutError`,
:class:`LLMProviderError`, :class:`pydantic.ValidationError` — and
delegates to the deterministic fallback when ``mode == "llm-first"``.
``mode == "llm-only"`` re-raises so the broker can fail closed with a
structured audit entry (AC-6.3).

Every call returns a :class:`LLMProvenance` record so the broker can
stamp ``llm_provider`` / ``llm_model`` / ``raw_response_hash`` /
``fallback_used`` into the audit entry (AC-6.5, design §3.10).
"""

from __future__ import annotations

import asyncio
from typing import Any, Literal

from pydantic import ValidationError

from nautilus.analysis.base import IntentAnalyzer
from nautilus.analysis.llm.base import (
    LLMIntentProvider,
    LLMProvenance,
    LLMProviderError,
)
from nautilus.core.models import IntentAnalysis

FallbackMode = Literal["llm-first", "llm-only"]


class FallbackIntentAnalyzer:
    """LLM-first intent analyzer with deterministic pattern-matcher fallback.

    See design §3.8. The primary/fallback split is intentional — the LLM
    path gives richer classification; the deterministic path gives the
    air-gap guarantee + bounded-latency envelope the routing layer
    depends on.
    """

    def __init__(
        self,
        primary: LLMIntentProvider,
        fallback: IntentAnalyzer,
        *,
        timeout_s: float = 2.0,
        mode: FallbackMode = "llm-first",
    ) -> None:
        self._primary = primary
        self._fallback = fallback
        self._timeout_s = timeout_s
        self._mode: FallbackMode = mode

    @property
    def mode(self) -> FallbackMode:
        """Selected fallback policy — ``llm-first`` or ``llm-only``."""
        return self._mode

    @property
    def timeout_s(self) -> float:
        """Per-call primary-provider timeout in seconds."""
        return self._timeout_s

    async def analyze(
        self,
        intent: str,
        context: dict[str, Any],
    ) -> tuple[IntentAnalysis, LLMProvenance]:
        """Classify ``intent`` via the primary provider with fallback.

        Contract (AC-6.2 / AC-6.3 / D-6):

        * Wrap the primary call in :func:`asyncio.timeout` using
          ``self.timeout_s``.
        * On :class:`TimeoutError` (raised by :func:`asyncio.timeout`),
          :class:`LLMProviderError`, or :class:`pydantic.ValidationError`:
          - ``mode == "llm-first"`` → delegate to the fallback and
            return ``fallback_used=True`` provenance.
          - ``mode == "llm-only"`` → re-raise; broker fails closed.
        * On success, return the primary's :class:`IntentAnalysis` plus
          a :class:`LLMProvenance` stamped with ``fallback_used=False``.

        The deterministic fallback is called synchronously
        (:class:`IntentAnalyzer` is sync per design §3.3); we don't run
        it under the timeout (AC-6.2 covers only the primary).
        """
        try:
            async with asyncio.timeout(self._timeout_s):
                analysis = await self._primary.analyze(intent, context)
        except TimeoutError, LLMProviderError, ValidationError:
            if self._mode == "llm-only":
                raise
            fallback_analysis = self._fallback.analyze(intent, context)
            return fallback_analysis, self._build_provenance(fallback_used=True)
        return analysis, self._build_provenance(fallback_used=False)

    def _build_provenance(self, *, fallback_used: bool) -> LLMProvenance:
        """Materialize a :class:`LLMProvenance` from primary attributes.

        ``raw_response_hash`` is read from the primary's
        ``_last_raw_response_hash`` stash when present (providers populate
        it on successful ``analyze``); absent / fallback path → ``""``.
        The ``version`` field is provider-SDK-specific and not part of
        the :class:`LLMIntentProvider` Protocol, so we probe it
        optionally and default to ``""``.
        """
        raw_hash: str = ""
        if not fallback_used:
            stashed = getattr(self._primary, "_last_raw_response_hash", None)
            if isinstance(stashed, str):
                raw_hash = stashed
        version: str = ""
        probed_version = getattr(self._primary, "version", None)
        if isinstance(probed_version, str):
            version = probed_version
        return LLMProvenance(
            provider=self._primary.provider_name,
            model=self._primary.model,
            version=version,
            prompt_version=self._primary.prompt_version,
            raw_response_hash=raw_hash,
            fallback_used=fallback_used,
        )


__all__ = ["FallbackIntentAnalyzer", "FallbackMode"]
