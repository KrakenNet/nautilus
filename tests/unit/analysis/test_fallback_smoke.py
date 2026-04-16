"""Smoke coverage for :mod:`nautilus.analysis.fallback` (Task 2.10 bridge).

:class:`FallbackIntentAnalyzer` wraps a primary :class:`LLMIntentProvider`
with a deterministic :class:`IntentAnalyzer` fallback. These smokes pin
the AC-6.2 / AC-6.3 / D-6 contract:

- happy path → ``fallback_used=False`` provenance,
- ``TimeoutError`` / :class:`LLMProviderError` / :class:`pydantic.ValidationError`
  on the primary → fallback delegated,
- ``mode == "llm-only"`` → primary error re-raises (broker fails closed),
- slow primary + ``timeout_s=0.0`` → ``TimeoutError`` path exercised,
- provenance fields (``provider`` / ``model`` / ``prompt_version`` /
  ``raw_response_hash`` / ``version``) populated from the primary's attributes.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from nautilus.analysis.fallback import FallbackIntentAnalyzer
from nautilus.analysis.llm.base import LLMProviderError
from nautilus.core.models import IntentAnalysis


def _make_intent(raw: str = "raw") -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent=raw,
        data_types_needed=["vulnerability"],
        entities=[],
        temporal_scope=None,
        estimated_sensitivity=None,
    )


def _make_validation_error() -> ValidationError:
    """Build a real :class:`pydantic.ValidationError` instance via a failed parse.

    ``pydantic.ValidationError`` cannot be constructed directly; trigger one by
    feeding bad input to :meth:`IntentAnalysis.model_validate`.
    """
    try:
        IntentAnalysis.model_validate({})  # missing required fields
    except ValidationError as exc:
        return exc
    raise AssertionError("model_validate({}) unexpectedly succeeded")  # pragma: no cover


def _make_primary(
    *,
    analyze_side_effect: Any = None,
    analyze_return: Any = None,
    raw_hash: str | None = "sha256:cafebabe",
    version: str | None = "0.95.0",
) -> Any:
    """Build a Mock primary with the LLMIntentProvider Protocol attributes."""
    primary = MagicMock()
    primary.provider_name = "openai"
    primary.model = "gpt-4o-2024-08-06"
    primary.prompt_version = "v1"
    if version is not None:
        primary.version = version
    if raw_hash is not None:
        primary._last_raw_response_hash = raw_hash
    if analyze_side_effect is not None:
        primary.analyze = AsyncMock(side_effect=analyze_side_effect)
    else:
        primary.analyze = AsyncMock(return_value=analyze_return)
    return primary


def _make_fallback(return_value: IntentAnalysis) -> Any:
    fb = MagicMock()
    fb.analyze = MagicMock(return_value=return_value)
    return fb


@pytest.mark.unit
def test_constructor_exposes_mode_and_timeout_properties() -> None:
    """``mode`` / ``timeout_s`` properties forward the constructor kwargs."""
    primary = _make_primary(analyze_return=_make_intent())
    fallback = _make_fallback(_make_intent("fb"))
    analyzer = FallbackIntentAnalyzer(
        primary=primary,
        fallback=fallback,
        timeout_s=1.5,
        mode="llm-only",
    )
    assert analyzer.mode == "llm-only"
    assert analyzer.timeout_s == 1.5


@pytest.mark.unit
def test_constructor_defaults_match_design() -> None:
    """Default ``timeout_s=2.0`` / ``mode="llm-first"`` per design §3.8."""
    primary = _make_primary(analyze_return=_make_intent())
    fallback = _make_fallback(_make_intent("fb"))
    analyzer = FallbackIntentAnalyzer(primary=primary, fallback=fallback)
    assert analyzer.mode == "llm-first"
    assert analyzer.timeout_s == 2.0


@pytest.mark.unit
async def test_happy_path_returns_primary_result_with_fallback_used_false() -> None:
    """Primary succeeds → ``(analysis, provenance)`` with ``fallback_used=False``."""
    primary_intent = _make_intent("primary")
    primary = _make_primary(analyze_return=primary_intent)
    fallback = _make_fallback(_make_intent("fb"))
    analyzer = FallbackIntentAnalyzer(primary=primary, fallback=fallback, timeout_s=2.0)

    analysis, prov = await analyzer.analyze("intent text", {"clearance": "secret"})

    assert analysis is primary_intent
    assert prov.provider == "openai"
    assert prov.model == "gpt-4o-2024-08-06"
    assert prov.prompt_version == "v1"
    assert prov.version == "0.95.0"
    assert prov.raw_response_hash == "sha256:cafebabe"
    assert prov.fallback_used is False
    fallback.analyze.assert_not_called()


@pytest.mark.unit
async def test_primary_timeout_delegates_to_fallback() -> None:
    """Builtin :class:`TimeoutError` from the primary → fallback path."""
    fb_intent = _make_intent("fallback-result")
    primary = _make_primary(analyze_side_effect=TimeoutError("primary timed out"))
    fallback = _make_fallback(fb_intent)
    analyzer = FallbackIntentAnalyzer(primary=primary, fallback=fallback, timeout_s=2.0)

    analysis, prov = await analyzer.analyze("intent", {})

    assert analysis is fb_intent
    assert prov.fallback_used is True
    # raw_response_hash is empty on the fallback path even though primary stashed one.
    assert prov.raw_response_hash == ""
    fallback.analyze.assert_called_once_with("intent", {})


@pytest.mark.unit
async def test_primary_llm_provider_error_delegates_to_fallback() -> None:
    """:class:`LLMProviderError` from the primary → fallback path (AC-6.3)."""
    fb_intent = _make_intent("fallback-result")
    primary = _make_primary(analyze_side_effect=LLMProviderError("upstream 500"))
    fallback = _make_fallback(fb_intent)
    analyzer = FallbackIntentAnalyzer(primary=primary, fallback=fallback, timeout_s=2.0)

    analysis, prov = await analyzer.analyze("intent", {})

    assert analysis is fb_intent
    assert prov.fallback_used is True
    fallback.analyze.assert_called_once()


@pytest.mark.unit
async def test_primary_validation_error_delegates_to_fallback() -> None:
    """:class:`pydantic.ValidationError` from the primary → fallback path."""
    fb_intent = _make_intent("fallback-result")
    primary = _make_primary(analyze_side_effect=_make_validation_error())
    fallback = _make_fallback(fb_intent)
    analyzer = FallbackIntentAnalyzer(primary=primary, fallback=fallback, timeout_s=2.0)

    analysis, prov = await analyzer.analyze("intent", {})

    assert analysis is fb_intent
    assert prov.fallback_used is True


@pytest.mark.unit
async def test_llm_only_mode_reraises_primary_error_without_calling_fallback() -> None:
    """``mode="llm-only"`` → primary failure re-raises, fallback not invoked."""
    primary = _make_primary(analyze_side_effect=LLMProviderError("auth"))
    fallback = _make_fallback(_make_intent("fb"))
    analyzer = FallbackIntentAnalyzer(
        primary=primary,
        fallback=fallback,
        timeout_s=2.0,
        mode="llm-only",
    )
    with pytest.raises(LLMProviderError):
        await analyzer.analyze("intent", {})
    fallback.analyze.assert_not_called()


@pytest.mark.unit
async def test_llm_only_mode_reraises_validation_error() -> None:
    """``mode="llm-only"`` re-raises :class:`ValidationError` too."""
    primary = _make_primary(analyze_side_effect=_make_validation_error())
    fallback = _make_fallback(_make_intent("fb"))
    analyzer = FallbackIntentAnalyzer(
        primary=primary,
        fallback=fallback,
        timeout_s=2.0,
        mode="llm-only",
    )
    with pytest.raises(ValidationError):
        await analyzer.analyze("intent", {})
    fallback.analyze.assert_not_called()


@pytest.mark.unit
async def test_slow_primary_with_zero_timeout_falls_back() -> None:
    """A slow primary + ``timeout_s=0.0`` exercises the :func:`asyncio.timeout`
    branch — :class:`TimeoutError` → fallback delegation."""
    fb_intent = _make_intent("fallback-result")

    async def _slow(intent: str, context: dict[str, Any]) -> IntentAnalysis:
        del intent, context
        await asyncio.sleep(0.5)
        return _make_intent("never-returned")  # pragma: no cover

    primary = MagicMock()
    primary.provider_name = "openai"
    primary.model = "gpt-4o-2024-08-06"
    primary.prompt_version = "v1"
    primary._last_raw_response_hash = None
    primary.analyze = _slow

    fallback = _make_fallback(fb_intent)
    analyzer = FallbackIntentAnalyzer(
        primary=primary, fallback=fallback, timeout_s=0.0, mode="llm-first"
    )
    analysis, prov = await analyzer.analyze("intent", {})
    assert analysis is fb_intent
    assert prov.fallback_used is True


@pytest.mark.unit
async def test_provenance_handles_missing_optional_attributes() -> None:
    """Provider without ``version`` / ``_last_raw_response_hash`` → defaults to ``""``."""
    primary_intent = _make_intent("primary")
    primary = _make_primary(
        analyze_return=primary_intent,
        raw_hash=None,
        version=None,
    )
    # Ensure attributes truly absent (MagicMock auto-creates on access; del them).
    del primary._last_raw_response_hash
    del primary.version

    fallback = _make_fallback(_make_intent("fb"))
    analyzer = FallbackIntentAnalyzer(primary=primary, fallback=fallback, timeout_s=2.0)

    _analysis, prov = await analyzer.analyze("intent", {})
    assert prov.raw_response_hash == ""
    assert prov.version == ""
    assert prov.fallback_used is False
