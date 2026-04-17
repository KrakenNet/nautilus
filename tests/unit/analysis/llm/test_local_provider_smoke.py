"""Smoke coverage for :mod:`nautilus.analysis.llm.local_provider` (Task 2.10 bridge).

:class:`LocalInferenceProvider` is the air-gap-compatible sibling of
:class:`OpenAIProvider`. These smokes exercise:

- inheritance + ``provider_name`` override,
- ``health_check`` no-op semantics (and the optional explicit-env-var path),
- constructor plumbing of ``base_url`` / ``api_key`` defaults into the
  underlying ``AsyncOpenAI`` client factory.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from nautilus.analysis.llm import local_provider as lp_mod
from nautilus.analysis.llm import openai_provider as op_mod
from nautilus.analysis.llm.base import LLMProviderError
from nautilus.analysis.llm.local_provider import LocalInferenceProvider
from nautilus.analysis.llm.openai_provider import OpenAIProvider

# When the openai SDK is not installed, AsyncOpenAI is None and the constructor
# raises LLMProviderError. Patch it to a MagicMock so offline tests can still
# construct providers without the real SDK.
if op_mod.AsyncOpenAI is None:  # pyright: ignore[reportUnnecessaryComparison]
    _sentinel = MagicMock()
    op_mod.AsyncOpenAI = _sentinel  # type: ignore[assignment]
    lp_mod.AsyncOpenAI = _sentinel  # type: ignore[assignment]


def _install_capturing_async_openai(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    """Patch ``AsyncOpenAI`` in both modules with a kwargs-capturing fake.

    :mod:`local_provider` rebinds ``AsyncOpenAI`` at import time
    (``from ... import AsyncOpenAI``), so monkeypatching the source module
    alone is not enough — we patch both bindings.

    Returns the captured-kwargs container the test inspects.
    """
    captured: dict[str, Any] = {"client_init_kwargs": None}

    def _factory(**kwargs: Any) -> Any:
        captured["client_init_kwargs"] = kwargs
        return MagicMock()

    monkeypatch.setattr(op_mod, "AsyncOpenAI", _factory)
    monkeypatch.setattr(lp_mod, "AsyncOpenAI", _factory)
    return captured


@pytest.mark.unit
def test_local_provider_extends_openai_provider() -> None:
    """:class:`LocalInferenceProvider` inherits from :class:`OpenAIProvider`
    so the broker can ``isinstance(p, OpenAIProvider)`` for shared plumbing."""
    assert issubclass(LocalInferenceProvider, OpenAIProvider)


@pytest.mark.unit
def test_provider_attributes_match_protocol() -> None:
    """Constructor populates Protocol attributes + local-specific slots."""
    provider = LocalInferenceProvider(
        base_url="http://localhost:8000/v1",
        model="llama-3-70b-instruct",
        timeout_s=2.5,
    )
    assert provider.provider_name == "local-inference"
    assert provider.model == "llama-3-70b-instruct"
    assert provider.prompt_version == "v1"
    assert provider.timeout_s == 2.5
    assert provider.base_url == "http://localhost:8000/v1"


@pytest.mark.unit
def test_health_check_is_noop_when_api_key_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default path: no ``api_key_env`` → ``health_check`` returns ``None``
    even when nothing is in the environment (local servers have no auth)."""
    monkeypatch.delenv("__NAUTILUS_LOCAL_INFERENCE_UNUSED__", raising=False)
    provider = LocalInferenceProvider(
        base_url="http://localhost:8000/v1",
        model="local-model",
        timeout_s=2.0,
    )
    assert provider.health_check() is None


@pytest.mark.unit
def test_health_check_validates_explicit_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the caller wires an explicit ``api_key_env`` (proxy with auth),
    the env-var presence check fires just like :class:`OpenAIProvider`."""
    monkeypatch.delenv("LOCAL_PROXY_KEY", raising=False)
    provider = LocalInferenceProvider(
        base_url="http://localhost:8000/v1",
        model="local-model",
        timeout_s=2.0,
        api_key_env="LOCAL_PROXY_KEY",
    )
    with pytest.raises(LLMProviderError) as excinfo:
        provider.health_check()
    assert "LOCAL_PROXY_KEY" in str(excinfo.value)


@pytest.mark.unit
def test_health_check_passes_when_explicit_env_var_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit ``api_key_env`` populated → ``health_check`` returns ``None``."""
    monkeypatch.setenv("LOCAL_PROXY_KEY", "secret-value")
    provider = LocalInferenceProvider(
        base_url="http://localhost:8000/v1",
        model="local-model",
        timeout_s=2.0,
        api_key_env="LOCAL_PROXY_KEY",
    )
    assert provider.health_check() is None


@pytest.mark.unit
def test_build_client_plumbs_base_url_and_default_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The internal ``_build_client`` forwards ``base_url`` / ``api_key`` /
    ``timeout`` into :class:`AsyncOpenAI` — defaults to ``"not-needed"``."""
    captured = _install_capturing_async_openai(monkeypatch)
    provider = LocalInferenceProvider(
        base_url="http://localhost:8000/v1",
        model="local-model",
        timeout_s=3.0,
    )
    provider._build_client()  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    kwargs = captured["client_init_kwargs"]
    assert kwargs is not None
    assert kwargs["api_key"] == "not-needed"
    assert kwargs["base_url"] == "http://localhost:8000/v1"
    assert kwargs["timeout"] == 3.0


@pytest.mark.unit
def test_build_client_uses_custom_api_key_literal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Caller-supplied ``api_key`` overrides the ``"not-needed"`` default."""
    captured = _install_capturing_async_openai(monkeypatch)
    provider = LocalInferenceProvider(
        base_url="http://localhost:8000/v1",
        model="local-model",
        timeout_s=2.0,
        api_key="literal-key-value",
    )
    provider._build_client()  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    kwargs = captured["client_init_kwargs"]
    assert kwargs is not None
    assert kwargs["api_key"] == "literal-key-value"


@pytest.mark.unit
def test_build_client_resolves_api_key_env_when_provided(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit ``api_key_env`` set → ``_build_client`` reads ``os.getenv``."""
    monkeypatch.setenv("LOCAL_PROXY_KEY", "env-key-value")
    captured = _install_capturing_async_openai(monkeypatch)
    provider = LocalInferenceProvider(
        base_url="http://localhost:8000/v1",
        model="local-model",
        timeout_s=2.0,
        api_key_env="LOCAL_PROXY_KEY",
    )
    provider._build_client()  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    kwargs = captured["client_init_kwargs"]
    assert kwargs is not None
    assert kwargs["api_key"] == "env-key-value"
    assert kwargs["base_url"] == "http://localhost:8000/v1"


@pytest.mark.unit
def test_build_client_falls_back_to_literal_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit ``api_key_env`` set but env unset → falls back to literal default."""
    monkeypatch.delenv("LOCAL_PROXY_KEY", raising=False)
    captured = _install_capturing_async_openai(monkeypatch)
    provider = LocalInferenceProvider(
        base_url="http://localhost:8000/v1",
        model="local-model",
        timeout_s=2.0,
        api_key="fallback-literal",
        api_key_env="LOCAL_PROXY_KEY",
    )
    provider._build_client()  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    kwargs = captured["client_init_kwargs"]
    assert kwargs is not None
    assert kwargs["api_key"] == "fallback-literal"
