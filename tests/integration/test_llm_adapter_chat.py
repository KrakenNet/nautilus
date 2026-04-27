"""Integration tests for the LLM adapter chat surface (Task 40, AC-5.18).

Provider mocks are hand-authored at the HTTP layer via respx so the tests
remain hermetic. Cassette files at ``tests/fixtures/llm/{openai,anthropic,
local}_cassette.yaml`` document the exact JSON shapes these mocks produce;
production cassette refresh runs against the live providers under their
respective recording marks.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from nautilus.adapters.llm import LLMAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis

pytestmark = pytest.mark.integration


def _config(provider: str, **overrides: object) -> SourceConfig:
    fields: dict[str, object] = {
        "id": f"chat-{provider}",
        "type": "llm",
        "description": "test",
        "classification": "internal",
        "data_types": ["llm-output"],
        "connection": "",
        "llm_provider": provider,
        "llm_model": "gpt-4o-mini" if provider != "anthropic" else "claude-3-5-sonnet-20241022",
        "surface": "chat",
        "token_secret_ref": "test-key",
    }
    if provider == "vllm":
        fields["endpoint"] = "http://127.0.0.1:8080"
        fields["llm_model"] = "meta-llama/Meta-Llama-3-8B-Instruct"
    fields.update(overrides)
    return SourceConfig(**fields)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_openai_chat_round_trip() -> None:
    adapter = LLMAdapter()
    await adapter.connect(_config("openai"))
    body = {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1714000000,
        "model": "gpt-4o-mini",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "hello back"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
    }
    with respx.mock(base_url="https://api.openai.com/v1") as router:
        router.post("/chat/completions").mock(return_value=httpx.Response(200, json=body))
        result = await adapter.execute(
            IntentAnalysis(raw_intent="hello", data_types_needed=[], entities=[]),
            [],
            {"temperature": 0.5},
        )
    await adapter.close()

    assert result.error is None
    assert result.rows[0]["content"] == "hello back"
    assert result.meta is not None
    assert result.meta["input_tokens"] == 4
    assert result.meta["output_tokens"] == 2
    assert result.meta["total_tokens"] == 6


@pytest.mark.asyncio
async def test_anthropic_chat_round_trip() -> None:
    adapter = LLMAdapter()
    await adapter.connect(_config("anthropic"))
    body = {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "claude says hi"}],
        "model": "claude-3-5-sonnet-20241022",
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 5,
            "output_tokens": 3,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        },
    }
    with respx.mock(base_url="https://api.anthropic.com") as router:
        router.post("/v1/messages").mock(return_value=httpx.Response(200, json=body))
        result = await adapter.execute(
            IntentAnalysis(raw_intent="hi", data_types_needed=[], entities=[]),
            [],
            {"max_tokens": 256},
        )
    await adapter.close()

    assert result.error is None
    assert result.rows[0]["content"] == "claude says hi"
    assert result.meta is not None
    assert result.meta["input_tokens"] == 5
    assert result.meta["output_tokens"] == 3


@pytest.mark.asyncio
async def test_vllm_chat_uses_endpoint_override() -> None:
    adapter = LLMAdapter()
    await adapter.connect(_config("vllm"))
    body = {
        "id": "chatcmpl-vllm",
        "object": "chat.completion",
        "created": 1714000000,
        "model": "meta-llama/Meta-Llama-3-8B-Instruct",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "local response"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
    }
    with respx.mock(base_url="http://127.0.0.1:8080") as router:
        route = router.post("/chat/completions").mock(return_value=httpx.Response(200, json=body))
        result = await adapter.execute(
            IntentAnalysis(raw_intent="local", data_types_needed=[], entities=[]),
            [],
            {},
        )
    await adapter.close()

    assert result.rows[0]["content"] == "local response"
    assert route.called
