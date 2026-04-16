"""Phase-3 cassette-driven tests for :class:`AnthropicProvider` (Task 3.7).

Replays the three canonical prompts from
``tests/fixtures/llm/anthropic_cassette.yaml`` against a mocked
``anthropic.AsyncAnthropic`` client and asserts the returned
:class:`IntentAnalysis` matches the cassette's ``tool_use.input`` block
(AC-6.6, NFR-12). Each cassette entry exercises a different sensitivity
bucket (public / internal / confidential) so the determinism harness
surface is covered end-to-end at the provider layer without a live API
call.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from nautilus.analysis.llm import anthropic_provider as ap_mod
from nautilus.analysis.llm.anthropic_provider import AnthropicProvider
from nautilus.core.models import IntentAnalysis

_CASSETTE_PATH: Path = (
    Path(__file__).resolve().parents[4] / "tests" / "fixtures" / "llm" / "anthropic_cassette.yaml"
)


def _load_cassette() -> list[dict[str, Any]]:
    with _CASSETTE_PATH.open("r", encoding="utf-8") as f:
        doc = cast(dict[str, Any], yaml.safe_load(f))
    return cast(list[dict[str, Any]], doc["interactions"])


def _intent_from_user_message(content: str) -> str:
    """Strip the cassette's ``CANONICAL_PROMPT_N:`` preamble + context_json tail.

    The cassette's ``messages[0].content`` concatenates the canonical prompt
    with an optional ``context_json: ...`` trailer that the fixture authors
    baked in for replay determinism. The provider's ``analyze()`` only
    consumes the bare intent string, so strip both.
    """
    first_line = content.splitlines()[0]
    return re.sub(r"^CANONICAL_PROMPT_\d+:\s*", "", first_line).strip()


def _build_params() -> list[Any]:
    params: list[Any] = []
    for idx, interaction in enumerate(_load_cassette(), start=1):
        user_msg = interaction["request"]["body"]["messages"][0]["content"]
        intent = _intent_from_user_message(user_msg)
        response_json = json.loads(interaction["response"]["body"]["string"])
        tool_input = response_json["content"][0]["input"]
        expected = IntentAnalysis.model_validate(tool_input)
        response_id = response_json["id"]
        params.append(
            pytest.param(
                intent,
                tool_input,
                expected,
                response_id,
                id=f"cassette-prompt-{idx}",
            )
        )
    return params


def _install_fake_anthropic(
    monkeypatch: pytest.MonkeyPatch,
    tool_input: dict[str, Any],
    response_id: str,
) -> None:
    """Patch ``ap_mod.AsyncAnthropic`` with a fake returning a tool_use block.

    Constructs a stand-in response whose ``content[0]`` is a
    ``SimpleNamespace``-like object matching ``_extract_tool_use_input``'s
    duck-typed expectations (``.type == "tool_use"``, ``.input`` dict).
    """
    block = MagicMock()
    block.type = "tool_use"
    block.input = tool_input

    response = MagicMock()
    response.content = [block]
    response.id = response_id

    async def _create(**_kwargs: Any) -> Any:
        return response

    def _factory(**_init_kwargs: Any) -> Any:
        client = MagicMock()
        client.messages = MagicMock()
        client.messages.create = AsyncMock(side_effect=_create)
        return client

    monkeypatch.setattr(ap_mod, "AsyncAnthropic", _factory)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("intent", "tool_input", "expected", "response_id"),
    _build_params(),
)
async def test_anthropic_cassette_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
    intent: str,
    tool_input: dict[str, Any],
    expected: IntentAnalysis,
    response_id: str,
) -> None:
    """Provider binds the mocked tool_use block into an :class:`IntentAnalysis`.

    Asserts every field the cassette fixes — raw_intent, data_types_needed,
    entities, temporal_scope, estimated_sensitivity — plus the
    ``_last_raw_response_hash`` stash so ``FallbackIntentAnalyzer`` can
    populate :class:`LLMProvenance` for the audit entry (AC-6.5, AC-6.6).
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-cassette")
    _install_fake_anthropic(monkeypatch, tool_input, response_id)

    provider = AnthropicProvider(
        api_key_env="ANTHROPIC_API_KEY",
        model="claude-sonnet-4-5",
        timeout_s=2.0,
    )
    result = await provider.analyze(intent, {})

    assert isinstance(result, IntentAnalysis)
    assert result.raw_intent == expected.raw_intent
    assert result.data_types_needed == expected.data_types_needed
    assert result.entities == expected.entities
    assert result.temporal_scope == expected.temporal_scope
    assert result.estimated_sensitivity == expected.estimated_sensitivity

    # Provenance-hash stash populated (64-hex sha256) per AC-6.5.
    raw_hash = provider._last_raw_response_hash  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert isinstance(raw_hash, str)
    assert len(raw_hash) == 64
