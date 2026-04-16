"""Smoke coverage for :mod:`nautilus.analysis.llm.base` (Task 2.5 bridge).

Interim coverage for the Protocol/dataclass module so the Phase-2 `[VERIFY]`
gate clears the 80% branch-coverage floor. The full suite lands in Phase 3
(Task 3.5). These smokes only exercise import, attribute presence, and
dataclass construction / equality / hash — no provider wiring.
"""

from __future__ import annotations

import pytest

from nautilus.analysis.llm.base import (
    LLMIntentProvider,
    LLMProvenance,
    LLMProviderError,
)


@pytest.mark.unit
def test_llm_provider_error_is_exception() -> None:
    """``LLMProviderError`` is a plain ``Exception`` so callers can
    ``except Exception`` without missing it (design §3.8)."""
    assert issubclass(LLMProviderError, Exception)
    exc = LLMProviderError("boom")
    assert str(exc) == "boom"


@pytest.mark.unit
def test_llm_intent_provider_is_runtime_checkable_protocol() -> None:
    """``LLMIntentProvider`` is marked ``@runtime_checkable`` so the broker
    can ``isinstance`` against it at wire-up time."""

    class _Fake:
        model = "m"
        provider_name = "fake"
        prompt_version = "v1"

        async def analyze(self, intent: str, context: dict[str, object]) -> object:
            return None

        def health_check(self) -> None:
            return None

    assert isinstance(_Fake(), LLMIntentProvider)


@pytest.mark.unit
def test_llm_provenance_is_frozen_dataclass_with_all_fields() -> None:
    """``LLMProvenance`` is the per-call audit stamp — AC-6.5."""
    prov = LLMProvenance(
        provider="anthropic",
        model="claude-sonnet-4-5",
        version="0.95.0",
        prompt_version="v1",
        raw_response_hash="sha256:deadbeef",
        fallback_used=False,
    )
    assert prov.provider == "anthropic"
    assert prov.model == "claude-sonnet-4-5"
    assert prov.prompt_version == "v1"
    assert prov.raw_response_hash == "sha256:deadbeef"
    assert prov.fallback_used is False


@pytest.mark.unit
def test_llm_provenance_is_frozen_and_hashable() -> None:
    """Frozen dataclass → immutable + hashable so audit records can sit in
    sets / dict keys without surprise mutation."""
    prov = LLMProvenance(
        provider="anthropic",
        model="m",
        version="v",
        prompt_version="v1",
        raw_response_hash="h",
        fallback_used=True,
    )
    # Frozen dataclass raises ``FrozenInstanceError`` (a ``dataclasses``
    # subclass of ``AttributeError``) on any field assignment.
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        prov.provider = "mutated"  # type: ignore[misc]
    # Hashable → usable as dict key.
    assert {prov: 1}[prov] == 1


@pytest.mark.unit
def test_llm_provenance_equality_by_value() -> None:
    """Dataclass equality is structural so two identical provenances
    compare equal (supports round-trip assertions)."""
    a = LLMProvenance("p", "m", "v", "v1", "h", False)
    b = LLMProvenance("p", "m", "v", "v1", "h", False)
    assert a == b
    assert hash(a) == hash(b)
