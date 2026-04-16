"""Phase-3 contract tests for :class:`FallbackIntentAnalyzer` (Task 3.7).

Pins the five authoritative cases the design/ACs enumerate (AC-6.2, AC-6.3,
D-6, FR-14):

- (a) primary success → ``(IntentAnalysis, LLMProvenance(fallback_used=False))``.
- (b) :class:`TimeoutError` on primary → fallback delegated,
  ``fallback_used=True``.
- (c) :class:`LLMProviderError` on primary → fallback delegated.
- (d) :class:`pydantic.ValidationError` on primary → fallback delegated.
- (e) ``mode="llm-only"`` + primary error → re-raised, no fallback.

These are the Phase-3 canonical tests. The Phase-2 smoke file
(:mod:`tests.unit.analysis.test_fallback_smoke`) stays as a bridge so
coverage hits the 80% floor without a phase gap.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from nautilus.analysis.fallback import FallbackIntentAnalyzer
from nautilus.analysis.llm.base import LLMProvenance, LLMProviderError
from nautilus.core.models import IntentAnalysis


def _make_intent(raw: str = "intent-under-test") -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent=raw,
        data_types_needed=["vulnerability"],
        entities=[],
        temporal_scope=None,
        estimated_sensitivity="internal",
    )


def _make_validation_error() -> ValidationError:
    """Obtain a real :class:`pydantic.ValidationError` instance.

    ``ValidationError`` cannot be instantiated directly; trigger one by
    feeding a malformed payload through :meth:`IntentAnalysis.model_validate`
    so the shape the provider would raise is preserved.
    """
    try:
        IntentAnalysis.model_validate({"raw_intent": 42})  # missing required fields, wrong type
    except ValidationError as exc:
        return exc
    raise AssertionError("model_validate unexpectedly succeeded")  # pragma: no cover


def _make_primary(
    *,
    analyze_side_effect: Any = None,
    analyze_return: Any = None,
    raw_hash: str | None = "sha256:deadbeef",
    version: str | None = "2024-10-22",
) -> Any:
    """Build a Mock primary satisfying the :class:`LLMIntentProvider` Protocol."""
    primary = MagicMock()
    primary.provider_name = "anthropic"
    primary.model = "claude-sonnet-4-5"
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
async def test_a_success_returns_intent_and_provenance_fallback_used_false() -> None:
    """(a) Primary succeeds → ``(IntentAnalysis, LLMProvenance(fallback_used=False))``."""
    primary_intent = _make_intent("primary-happy-path")
    primary = _make_primary(analyze_return=primary_intent)
    fallback = _make_fallback(_make_intent("never-used"))
    analyzer = FallbackIntentAnalyzer(primary=primary, fallback=fallback, timeout_s=2.0)

    analysis, prov = await analyzer.analyze("classify me", {"clearance": "internal"})

    assert analysis is primary_intent
    assert isinstance(prov, LLMProvenance)
    assert prov.provider == "anthropic"
    assert prov.model == "claude-sonnet-4-5"
    assert prov.prompt_version == "v1"
    assert prov.version == "2024-10-22"
    assert prov.raw_response_hash == "sha256:deadbeef"
    assert prov.fallback_used is False
    fallback.analyze.assert_not_called()
    primary.analyze.assert_awaited_once_with("classify me", {"clearance": "internal"})


@pytest.mark.unit
async def test_b_timeout_error_triggers_fallback_with_fallback_used_true() -> None:
    """(b) :class:`TimeoutError` → fallback path, ``fallback_used=True``.

    Exercises the :func:`asyncio.timeout` surface by letting the primary's
    coroutine sleep past a near-zero ``timeout_s`` so :class:`TimeoutError`
    is raised by the context manager itself.
    """
    fb_intent = _make_intent("fallback-after-timeout")

    async def _slow(intent: str, context: dict[str, Any]) -> IntentAnalysis:
        del intent, context
        await asyncio.sleep(0.25)
        return _make_intent("never-returned")  # pragma: no cover

    primary = MagicMock()
    primary.provider_name = "anthropic"
    primary.model = "claude-sonnet-4-5"
    primary.prompt_version = "v1"
    primary._last_raw_response_hash = None
    primary.analyze = _slow

    fallback = _make_fallback(fb_intent)
    analyzer = FallbackIntentAnalyzer(
        primary=primary, fallback=fallback, timeout_s=0.0, mode="llm-first"
    )

    analysis, prov = await analyzer.analyze("intent", {"k": "v"})

    assert analysis is fb_intent
    assert prov.fallback_used is True
    # raw_response_hash is cleared on the fallback path even if primary stashed one.
    assert prov.raw_response_hash == ""
    fallback.analyze.assert_called_once_with("intent", {"k": "v"})


@pytest.mark.unit
async def test_c_llm_provider_error_triggers_fallback() -> None:
    """(c) :class:`LLMProviderError` on primary → fallback path (AC-6.3)."""
    fb_intent = _make_intent("fallback-after-provider-error")
    primary = _make_primary(analyze_side_effect=LLMProviderError("upstream 500"))
    fallback = _make_fallback(fb_intent)
    analyzer = FallbackIntentAnalyzer(primary=primary, fallback=fallback, timeout_s=2.0)

    analysis, prov = await analyzer.analyze("intent", {})

    assert analysis is fb_intent
    assert prov.fallback_used is True
    assert prov.provider == "anthropic"  # provenance still stamps primary identity
    fallback.analyze.assert_called_once_with("intent", {})


@pytest.mark.unit
async def test_d_validation_error_on_primary_triggers_fallback() -> None:
    """(d) :class:`pydantic.ValidationError` (non-conforming JSON) → fallback path.

    Simulates schema drift — the primary returned a payload that failed
    :meth:`IntentAnalysis.model_validate`. ``FallbackIntentAnalyzer`` must
    catch that explicitly rather than letting it escape as an unhandled
    pydantic error (design §3.8).
    """
    fb_intent = _make_intent("fallback-after-validation-error")
    primary = _make_primary(analyze_side_effect=_make_validation_error())
    fallback = _make_fallback(fb_intent)
    analyzer = FallbackIntentAnalyzer(primary=primary, fallback=fallback, timeout_s=2.0)

    analysis, prov = await analyzer.analyze("bad-schema-intent", {})

    assert analysis is fb_intent
    assert prov.fallback_used is True
    fallback.analyze.assert_called_once_with("bad-schema-intent", {})


@pytest.mark.unit
async def test_e_llm_only_mode_reraises_and_never_calls_fallback() -> None:
    """(e) ``mode="llm-only"`` + primary error → re-raises, no fallback (AC-6.3).

    The broker uses ``llm-only`` to fail closed with a structured audit
    entry rather than silently degrading to the deterministic path.
    """
    primary = _make_primary(analyze_side_effect=LLMProviderError("auth-failed"))
    fallback = _make_fallback(_make_intent("must-not-be-called"))
    analyzer = FallbackIntentAnalyzer(
        primary=primary,
        fallback=fallback,
        timeout_s=2.0,
        mode="llm-only",
    )

    with pytest.raises(LLMProviderError) as excinfo:
        await analyzer.analyze("intent", {})

    assert "auth-failed" in str(excinfo.value)
    fallback.analyze.assert_not_called()
