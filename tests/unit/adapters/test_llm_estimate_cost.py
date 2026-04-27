"""Unit tests for LLMAdapter.estimate_cost() preflight token counts (Task 38, AC-5.7).

OpenAI/vLLM path uses ``tiktoken``; Anthropic path uses
``POST /v1/messages/count_tokens`` (mocked via respx).
"""

from __future__ import annotations

import httpx
import pytest
import respx

from nautilus.adapters.llm import LLMAdapter, PreflightEstimate
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis

pytestmark = pytest.mark.unit


def _intent(text: str) -> IntentAnalysis:
    return IntentAnalysis(raw_intent=text, data_types_needed=[], entities=[])


def _config(**overrides: object) -> SourceConfig:
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
        "token_secret_ref": "sk-test",
    }
    fields.update(overrides)
    return SourceConfig(**fields)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_estimate_cost_openai_uses_tiktoken() -> None:
    adapter = LLMAdapter()
    await adapter.connect(_config())
    estimate = await adapter.estimate_cost(_intent("hello world"), {})
    assert isinstance(estimate, PreflightEstimate)
    # tiktoken on "hello world" + per-message overhead is well under 100.
    assert 1 < estimate.input_tokens < 100
    await adapter.close()


@pytest.mark.asyncio
async def test_estimate_cost_unknown_model_falls_back_to_cl100k() -> None:
    adapter = LLMAdapter()
    await adapter.connect(_config(llm_model="some-model-tiktoken-does-not-know"))
    estimate = await adapter.estimate_cost(_intent("hello"), {})
    assert estimate.input_tokens > 0
    await adapter.close()


@pytest.mark.asyncio
async def test_estimate_cost_anthropic_calls_count_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = LLMAdapter()
    await adapter.connect(
        _config(llm_provider="anthropic", llm_model="claude-3-5-sonnet-20241022"),
    )
    with respx.mock(base_url="https://api.anthropic.com") as router:
        router.post("/v1/messages/count_tokens").mock(
            return_value=httpx.Response(200, json={"input_tokens": 42})
        )
        estimate = await adapter.estimate_cost(_intent("hello"), {})
    assert estimate.input_tokens == 42
    await adapter.close()
