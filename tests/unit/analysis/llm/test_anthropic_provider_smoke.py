"""Smoke coverage for :mod:`nautilus.analysis.llm.anthropic_provider` (Task 2.5 bridge).

Interim Phase-2 coverage — full provider tests (including VCR-cassette
determinism harness, NFR-12) land in Phase 3 (Task 3.5). These smokes
exercise only the offline branches:

- Construction populates ``provider_name`` / ``model`` / ``prompt_version``
  and loads the locked prompt template + tool schema.
- ``health_check()`` raises :class:`LLMProviderError` when the configured
  API-key env var is unset or empty (AC-6.6).
- ``health_check()`` passes silently when the env var is populated.

No network calls are made; :class:`anthropic.AsyncAnthropic` is never
instantiated along the paths these tests cover.
"""

from __future__ import annotations

import pytest

pytest.importorskip("anthropic", reason="anthropic SDK not installed (optional extra)")

from nautilus.analysis.llm.anthropic_provider import AnthropicProvider
from nautilus.analysis.llm.base import LLMProviderError


@pytest.mark.unit
def test_provider_attributes_match_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructor populates the attributes the :class:`LLMIntentProvider`
    Protocol requires + the prompt-template / tool-schema slots."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicProvider(
        api_key_env="ANTHROPIC_API_KEY",
        model="claude-sonnet-4-5",
        timeout_s=2.0,
    )
    assert provider.provider_name == "anthropic"
    assert provider.model == "claude-sonnet-4-5"
    assert provider.prompt_version == "v1"
    assert provider.api_key_env == "ANTHROPIC_API_KEY"
    assert provider.timeout_s == 2.0
    # Prompt template + tool schema loaded eagerly at construction time.
    assert provider._tool_schema is not None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert provider._prompt_template is not None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
def test_health_check_raises_when_api_key_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-6.6 — missing env var surfaces as :class:`LLMProviderError`."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicProvider(
        api_key_env="ANTHROPIC_API_KEY",
        model="claude-sonnet-4-5",
        timeout_s=2.0,
    )
    with pytest.raises(LLMProviderError) as excinfo:
        provider.health_check()
    assert "ANTHROPIC_API_KEY" in str(excinfo.value)


@pytest.mark.unit
def test_health_check_raises_when_api_key_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty string is treated as unset (``not key`` branch)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    provider = AnthropicProvider(
        api_key_env="ANTHROPIC_API_KEY",
        model="claude-sonnet-4-5",
        timeout_s=2.0,
    )
    with pytest.raises(LLMProviderError):
        provider.health_check()


@pytest.mark.unit
def test_health_check_passes_when_api_key_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path — populated env var → ``health_check`` returns ``None``."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-real-key")
    provider = AnthropicProvider(
        api_key_env="ANTHROPIC_API_KEY",
        model="claude-sonnet-4-5",
        timeout_s=2.0,
    )
    # No exception; returns None.
    assert provider.health_check() is None


@pytest.mark.unit
def test_provider_loads_default_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default model kwarg matches the design-documented Claude version."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicProvider(api_key_env="ANTHROPIC_API_KEY", timeout_s=2.0)
    assert provider.model == "claude-sonnet-4-5"
