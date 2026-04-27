"""Integration tests for the LLM adapter embeddings surface (Task 40, AC-5.18).

Anthropic is rejected at ``connect()`` per AC-5.2; only OpenAI and vLLM are
exercised here.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from nautilus.adapters.llm import ConfigError, LLMAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis

pytestmark = pytest.mark.integration


def _config(provider: str, **overrides: object) -> SourceConfig:
    fields: dict[str, object] = {
        "id": f"emb-{provider}",
        "type": "llm",
        "description": "test",
        "classification": "internal",
        "data_types": ["llm-output"],
        "connection": "",
        "llm_provider": provider,
        "llm_model": "text-embedding-3-small",
        "surface": "embeddings",
        "token_secret_ref": "sk-test",
    }
    if provider == "vllm":
        fields["endpoint"] = "http://127.0.0.1:8080"
        fields["llm_model"] = "BAAI/bge-base-en-v1.5"
    fields.update(overrides)
    return SourceConfig(**fields)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_openai_embeddings_round_trip() -> None:
    adapter = LLMAdapter()
    await adapter.connect(_config("openai"))
    body = {
        "object": "list",
        "data": [
            {"object": "embedding", "embedding": [0.1, 0.2, 0.3], "index": 0},
            {"object": "embedding", "embedding": [0.4, 0.5, 0.6], "index": 1},
        ],
        "model": "text-embedding-3-small",
        "usage": {"prompt_tokens": 4, "total_tokens": 4},
    }
    with respx.mock(base_url="https://api.openai.com/v1") as router:
        router.post("/embeddings").mock(return_value=httpx.Response(200, json=body))
        result = await adapter.execute(
            IntentAnalysis(raw_intent="hello", data_types_needed=[], entities=[]),
            [],
            {"inputs": ["a", "b"]},
        )
    await adapter.close()

    assert result.error is None
    assert len(result.rows) == 2
    assert result.rows[0]["embedding"] == [0.1, 0.2, 0.3]
    assert result.rows[1]["index"] == 1


@pytest.mark.asyncio
async def test_anthropic_embeddings_rejected_at_connect() -> None:
    adapter = LLMAdapter()
    with pytest.raises(ConfigError, match="Anthropic does not offer first-party embeddings"):
        await adapter.connect(_config("anthropic", llm_model="claude-3-5-sonnet-20241022"))


@pytest.mark.asyncio
async def test_vllm_embeddings_round_trip() -> None:
    adapter = LLMAdapter()
    await adapter.connect(_config("vllm"))
    body = {
        "object": "list",
        "data": [{"object": "embedding", "embedding": [0.7, 0.8], "index": 0}],
        "model": "BAAI/bge-base-en-v1.5",
        "usage": {"prompt_tokens": 2, "total_tokens": 2},
    }
    with respx.mock(base_url="http://127.0.0.1:8080") as router:
        router.post("/embeddings").mock(return_value=httpx.Response(200, json=body))
        result = await adapter.execute(
            IntentAnalysis(raw_intent="hi", data_types_needed=[], entities=[]),
            [],
            {},
        )
    await adapter.close()
    assert result.rows[0]["embedding"] == [0.7, 0.8]
