"""Smoke coverage for :mod:`nautilus.analysis.llm.openai_provider` (Task 2.10 bridge).

Interim Phase-2 coverage that exercises the offline branches of the OpenAI
Structured-Outputs provider so the [VERIFY] 2.10 gate clears the 80%
branch-coverage floor. Full provider tests (including VCR-cassette
determinism harness, NFR-12) land in Phase 3.

The :class:`openai.AsyncOpenAI` constructor is monkeypatched at module-level
to capture the kwargs we plumb through (``api_key``, ``timeout``) and to
return a mock ``responses.parse`` so no network call is ever made. The
``analyze()`` happy path asserts the returned :class:`IntentAnalysis`,
the ``temperature=0`` / ``max_output_tokens=512`` / ``text_format`` kwargs,
and the ``_last_raw_response_hash`` stash that
:class:`FallbackIntentAnalyzer` reads to populate ``LLMProvenance``.
"""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.analysis.llm import openai_provider as op_mod
from nautilus.analysis.llm.base import LLMProviderError
from nautilus.analysis.llm.openai_provider import OpenAIProvider
from nautilus.core.models import IntentAnalysis


def _make_intent_analysis() -> IntentAnalysis:
    """Build a deterministic :class:`IntentAnalysis` for parse-return mocks."""
    return IntentAnalysis(
        raw_intent="lookup vuln CVE-2024-0001",
        data_types_needed=["vulnerability"],
        entities=["CVE-2024-0001"],
        temporal_scope=None,
        estimated_sensitivity=None,
    )


def _install_fake_async_openai(
    monkeypatch: pytest.MonkeyPatch,
    parsed: IntentAnalysis | None,
    response_id: str = "resp_abc123",
) -> dict[str, Any]:
    """Patch ``op_mod.AsyncOpenAI`` with a capturing fake.

    Returns a dict the test can inspect post-call:

    - ``"client_init_kwargs"``: kwargs the provider passed to ``AsyncOpenAI(...)``
    - ``"parse_kwargs"``: kwargs passed to ``responses.parse(...)``
    """
    captured: dict[str, Any] = {"client_init_kwargs": None, "parse_kwargs": None}

    response = MagicMock()
    response.output_parsed = parsed
    response.id = response_id

    parse_mock = AsyncMock(return_value=response)

    def _factory(**kwargs: Any) -> Any:
        captured["client_init_kwargs"] = kwargs
        client = MagicMock()
        client.responses = MagicMock()

        async def _parse_capture(**parse_kwargs: Any) -> Any:
            captured["parse_kwargs"] = parse_kwargs
            return await parse_mock(**parse_kwargs)

        client.responses.parse = _parse_capture
        return client

    monkeypatch.setattr(op_mod, "AsyncOpenAI", _factory)
    return captured


@pytest.mark.unit
def test_provider_attributes_match_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructor populates the attributes the :class:`LLMIntentProvider`
    Protocol requires + the prompt-template slot."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIProvider(
        api_key_env="OPENAI_API_KEY",
        model="gpt-4o-2024-08-06",
        timeout_s=2.0,
    )
    assert provider.provider_name == "openai"
    assert provider.model == "gpt-4o-2024-08-06"
    assert provider.prompt_version == "v1"
    assert provider.api_key_env == "OPENAI_API_KEY"
    assert provider.timeout_s == 2.0
    assert provider._prompt_template is not None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert provider._last_raw_response_hash is None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
def test_health_check_raises_when_api_key_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-6.6 — missing env var surfaces as :class:`LLMProviderError`."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIProvider(
        api_key_env="OPENAI_API_KEY",
        model="gpt-4o-2024-08-06",
        timeout_s=2.0,
    )
    with pytest.raises(LLMProviderError) as excinfo:
        provider.health_check()
    assert "OPENAI_API_KEY" in str(excinfo.value)


@pytest.mark.unit
def test_health_check_raises_when_api_key_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty string is treated as unset (``not key`` branch)."""
    monkeypatch.setenv("OPENAI_API_KEY", "")
    provider = OpenAIProvider(
        api_key_env="OPENAI_API_KEY",
        model="gpt-4o-2024-08-06",
        timeout_s=2.0,
    )
    with pytest.raises(LLMProviderError):
        provider.health_check()


@pytest.mark.unit
def test_health_check_passes_when_api_key_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path — populated env var → ``health_check`` returns ``None``."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")
    provider = OpenAIProvider(
        api_key_env="OPENAI_API_KEY",
        model="gpt-4o-2024-08-06",
        timeout_s=2.0,
    )
    assert provider.health_check() is None


@pytest.mark.unit
def test_provider_loads_default_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default ``model`` kwarg matches the design-documented OpenAI version."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIProvider(api_key_env="OPENAI_API_KEY", timeout_s=2.0)
    assert provider.model == "gpt-4o-2024-08-06"


@pytest.mark.unit
async def test_analyze_happy_path_returns_intent_and_stamps_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``analyze`` returns the parsed :class:`IntentAnalysis` and stamps a
    non-empty ``_last_raw_response_hash`` so the fallback can build provenance."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    parsed = _make_intent_analysis()
    captured = _install_fake_async_openai(monkeypatch, parsed)

    provider = OpenAIProvider(
        api_key_env="OPENAI_API_KEY",
        model="gpt-4o-2024-08-06",
        timeout_s=2.0,
    )
    result = await provider.analyze("lookup vuln CVE-2024-0001", {"clearance": "secret"})

    assert result == parsed
    # Hash stash populated; the FallbackIntentAnalyzer reads this to build LLMProvenance.
    raw_hash = provider._last_raw_response_hash  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert isinstance(raw_hash, str)
    assert len(raw_hash) == 64  # sha256 hex digest

    # API call kwargs locked: temperature=0, max_output_tokens=512, text_format=IntentAnalysis.
    parse_kwargs = captured["parse_kwargs"]
    assert parse_kwargs is not None
    assert parse_kwargs["temperature"] == 0
    assert parse_kwargs["max_output_tokens"] == 512
    assert parse_kwargs["text_format"] is IntentAnalysis
    assert parse_kwargs["model"] == "gpt-4o-2024-08-06"
    assert isinstance(parse_kwargs["input"], str)
    assert "lookup vuln CVE-2024-0001" in parse_kwargs["input"]

    # Client init kwargs forward api_key + timeout from constructor.
    client_kwargs = captured["client_init_kwargs"]
    assert client_kwargs is not None
    assert client_kwargs["api_key"] == "sk-test"
    assert client_kwargs["timeout"] == 2.0


@pytest.mark.unit
async def test_analyze_raises_when_parse_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``responses.parse`` returning ``output_parsed=None`` → :class:`LLMProviderError`."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    _install_fake_async_openai(monkeypatch, parsed=None)

    provider = OpenAIProvider(
        api_key_env="OPENAI_API_KEY",
        model="gpt-4o-2024-08-06",
        timeout_s=2.0,
    )
    with pytest.raises(LLMProviderError):
        await provider.analyze("anything", {})


@pytest.mark.unit
async def test_analyze_health_check_first(monkeypatch: pytest.MonkeyPatch) -> None:
    """``analyze`` invokes ``health_check`` before any client work — missing
    env var surfaces as :class:`LLMProviderError` and never builds the client."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def _factory_should_not_be_called(**_kwargs: Any) -> Any:  # pragma: no cover
        raise AssertionError("AsyncOpenAI must not be constructed when health_check fails")

    monkeypatch.setattr(op_mod, "AsyncOpenAI", _factory_should_not_be_called)
    provider = OpenAIProvider(
        api_key_env="OPENAI_API_KEY",
        model="gpt-4o-2024-08-06",
        timeout_s=2.0,
    )
    with pytest.raises(LLMProviderError):
        await provider.analyze("x", {})


@pytest.mark.unit
async def test_analyze_wraps_openai_sdk_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """SDK-level errors in the ``_openai_errors`` tuple surface as
    :class:`LLMProviderError` (AC-6.3).

    We monkey-patch ``op_mod._openai_errors`` to a locally-constructed
    subclass of :class:`Exception` so the ``except _openai_errors`` tuple
    catches our sentinel without needing to instantiate the real
    ``openai.APIError`` (whose constructor signature varies by SDK version).
    """
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    class _FakeAPIError(Exception):
        pass

    monkeypatch.setattr(op_mod, "_openai_errors", (_FakeAPIError,))

    def _factory(**_kwargs: Any) -> Any:
        client = MagicMock()
        client.responses = MagicMock()

        async def _parse_raises(**_pkwargs: Any) -> Any:
            raise _FakeAPIError("boom")

        client.responses.parse = _parse_raises
        return client

    monkeypatch.setattr(op_mod, "AsyncOpenAI", _factory)
    provider = OpenAIProvider(
        api_key_env="OPENAI_API_KEY",
        model="gpt-4o-2024-08-06",
        timeout_s=2.0,
    )
    with pytest.raises(LLMProviderError):
        await provider.analyze("x", {})


@pytest.mark.unit
def test_constructor_raises_when_openai_module_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deferred-import guard — when ``openai`` is unavailable the constructor
    raises :class:`LLMProviderError` instead of ``AttributeError``."""
    # Strip the cached ``op_mod.AsyncOpenAI`` reference; the constructor's
    # ``if AsyncOpenAI is None`` branch then trips.
    monkeypatch.setattr(op_mod, "AsyncOpenAI", None)
    monkeypatch.setattr(op_mod, "_import_error", ImportError("openai not installed"))
    with pytest.raises(LLMProviderError) as excinfo:
        OpenAIProvider(
            api_key_env="OPENAI_API_KEY",
            model="gpt-4o-2024-08-06",
            timeout_s=2.0,
        )
    assert "openai" in str(excinfo.value).lower()


@pytest.mark.unit
def test_module_level_import_guard_handles_missing_openai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The module-level ``try/except ImportError`` keeps the import succeeding
    even when ``openai`` is not installed — exercised by reloading with
    ``sys.modules['openai']`` poisoned."""
    # Save originals so we can restore.
    original_openai = sys.modules.get("openai")
    original_op_mod = sys.modules.get("nautilus.analysis.llm.openai_provider")
    try:
        # Force the import machinery to fail next time openai is requested.
        monkeypatch.setitem(sys.modules, "openai", None)  # raises ImportError on import
        sys.modules.pop("nautilus.analysis.llm.openai_provider", None)

        import importlib

        reloaded = importlib.import_module("nautilus.analysis.llm.openai_provider")
        # Module imported successfully despite missing openai — guard branch hit.
        assert reloaded.AsyncOpenAI is None
        assert reloaded._import_error is not None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    finally:
        # Restore so other tests keep working.
        sys.modules.pop("nautilus.analysis.llm.openai_provider", None)
        if original_openai is not None:
            sys.modules["openai"] = original_openai
        else:
            sys.modules.pop("openai", None)
        if original_op_mod is not None:
            sys.modules["nautilus.analysis.llm.openai_provider"] = original_op_mod
