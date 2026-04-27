# pyright: reportPrivateUsage=false
"""Unit tests for LLMAdapter provider dispatch + connect-time validation (Task 37).

Covers AC-5.1, AC-5.2, AC-5.3, AC-5.6 — registry registration, provider × surface
matrix validation, vLLM endpoint requirement, streaming rejection.
"""

from __future__ import annotations

import pytest

from nautilus.adapters import ADAPTER_REGISTRY, LLMAdapter
from nautilus.adapters.llm import ConfigError
from nautilus.config.models import SessionSigningConfig, SourceConfig

pytestmark = pytest.mark.unit


def _base_config(**overrides: object) -> SourceConfig:
    fields: dict[str, object] = {
        "id": "test-llm",
        "type": "llm",
        "description": "test",
        "classification": "internal",
        "data_types": ["llm-output"],
        "connection": "",
        "llm_provider": "openai",
        "llm_model": "gpt-4o-mini",
        "surface": "chat",
        "token_secret_ref": "fake-key",
    }
    fields.update(overrides)
    return SourceConfig(**fields)  # type: ignore[arg-type]


def test_llm_in_adapter_registry() -> None:
    assert "llm" in ADAPTER_REGISTRY
    assert ADAPTER_REGISTRY["llm"] is LLMAdapter


def test_source_type_class_var() -> None:
    assert LLMAdapter.source_type == "llm"


@pytest.mark.asyncio
async def test_connect_rejects_anthropic_embeddings() -> None:
    adapter = LLMAdapter()
    with pytest.raises(ConfigError, match="Anthropic does not offer first-party embeddings"):
        await adapter.connect(
            _base_config(llm_provider="anthropic", surface="embeddings"),
        )


@pytest.mark.asyncio
async def test_connect_rejects_streaming() -> None:
    adapter = LLMAdapter()
    with pytest.raises(ConfigError, match="streaming deferred to v2"):
        await adapter.connect(_base_config(stream=True))


@pytest.mark.asyncio
async def test_connect_requires_vllm_endpoint() -> None:
    adapter = LLMAdapter()
    with pytest.raises(ConfigError, match="vLLM source requires"):
        await adapter.connect(_base_config(llm_provider="vllm", endpoint=None))


@pytest.mark.asyncio
async def test_connect_requires_provider_model_surface() -> None:
    adapter = LLMAdapter()
    bad = SourceConfig(
        id="x",
        type="llm",
        description="x",
        classification="internal",
        data_types=["llm-output"],
        connection="",
        llm_provider=None,
        llm_model=None,
        surface=None,
    )
    with pytest.raises(ConfigError, match="llm_provider, llm_model"):
        await adapter.connect(bad)


@pytest.mark.asyncio
async def test_connect_signing_requires_keyref() -> None:
    adapter = LLMAdapter()
    cfg = _base_config(
        session_signing=SessionSigningConfig(enabled=True, key_ref=""),
    )
    with pytest.raises(ConfigError, match="key_ref is empty"):
        await adapter.connect(cfg)


@pytest.mark.asyncio
async def test_connect_unknown_signing_scheme() -> None:
    adapter = LLMAdapter()
    cfg = _base_config(
        session_signing=SessionSigningConfig(enabled=True, key_ref="aws-kms://foo"),
    )
    with pytest.raises(ConfigError, match="unsupported session_signing.key_ref scheme"):
        await adapter.connect(cfg)


@pytest.mark.asyncio
async def test_connect_env_signing_keyref(monkeypatch: pytest.MonkeyPatch) -> None:
    seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    monkeypatch.setenv("NAUTILUS_TEST_SIGNING_SEED", seed)
    adapter = LLMAdapter()
    cfg = _base_config(
        session_signing=SessionSigningConfig(
            enabled=True,
            key_ref="env://NAUTILUS_TEST_SIGNING_SEED",
        ),
    )
    await adapter.connect(cfg)
    assert adapter._signer is not None
    assert adapter._signer.keyid.startswith("test-llm:")
    await adapter.close()
