"""Phase-3 cassette-driven tests for :class:`OpenAIProvider` (Task 3.7).

Replays the three canonical prompts from
``tests/fixtures/llm/openai_cassette.yaml`` against a mocked
``openai.AsyncOpenAI`` client and asserts the returned
:class:`IntentAnalysis` matches the cassette's
``choices[0].message.content`` JSON payload (AC-6.6, NFR-12).

The provider uses ``responses.parse(text_format=IntentAnalysis)`` —
that SDK path binds the response directly to the Pydantic schema and
hands back a populated ``response.output_parsed``. We emulate that by
decoding the cassette's JSON-string content and handing the parsed
:class:`IntentAnalysis` back on the fake ``responses.parse`` mock.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from nautilus.analysis.llm import openai_provider as op_mod
from nautilus.analysis.llm.openai_provider import OpenAIProvider
from nautilus.core.models import IntentAnalysis

_CASSETTE_PATH: Path = (
    Path(__file__).resolve().parents[4] / "tests" / "fixtures" / "llm" / "openai_cassette.yaml"
)


def _load_cassette() -> list[dict[str, Any]]:
    with _CASSETTE_PATH.open("r", encoding="utf-8") as f:
        doc = cast(dict[str, Any], yaml.safe_load(f))
    return cast(list[dict[str, Any]], doc["interactions"])


def _intent_from_user_message(content: str) -> str:
    """Strip the cassette's ``CANONICAL_PROMPT_N:`` preamble."""
    first_line = content.splitlines()[0]
    return re.sub(r"^CANONICAL_PROMPT_\d+:\s*", "", first_line).strip()


def _build_params() -> list[Any]:
    params: list[Any] = []
    for idx, interaction in enumerate(_load_cassette(), start=1):
        user_msg = interaction["request"]["body"]["messages"][0]["content"]
        intent = _intent_from_user_message(user_msg)
        response_json = json.loads(interaction["response"]["body"]["string"])
        content_str = response_json["choices"][0]["message"]["content"]
        expected_payload = json.loads(content_str)
        expected = IntentAnalysis.model_validate(expected_payload)
        response_id = response_json["id"]
        params.append(
            pytest.param(
                intent,
                expected,
                response_id,
                id=f"cassette-prompt-{idx}",
            )
        )
    return params


def _install_fake_openai(
    monkeypatch: pytest.MonkeyPatch,
    parsed: IntentAnalysis,
    response_id: str,
) -> None:
    """Patch ``op_mod.AsyncOpenAI`` to return a fake exposing ``output_parsed``."""
    response = MagicMock()
    response.output_parsed = parsed
    response.id = response_id

    async def _parse(**_kwargs: Any) -> Any:
        return response

    def _factory(**_init_kwargs: Any) -> Any:
        client = MagicMock()
        client.responses = MagicMock()
        client.responses.parse = AsyncMock(side_effect=_parse)
        return client

    monkeypatch.setattr(op_mod, "AsyncOpenAI", _factory)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("intent", "expected", "response_id"),
    _build_params(),
)
async def test_openai_cassette_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
    intent: str,
    expected: IntentAnalysis,
    response_id: str,
) -> None:
    """Provider passes the parsed :class:`IntentAnalysis` through unchanged.

    Asserts every field the cassette fixes plus the non-empty
    ``_last_raw_response_hash`` stash used by
    :class:`FallbackIntentAnalyzer` for audit provenance (AC-6.5, AC-6.6).
    """
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-cassette")
    _install_fake_openai(monkeypatch, expected, response_id)

    provider = OpenAIProvider(
        api_key_env="OPENAI_API_KEY",
        model="gpt-4o-2024-08-06",
        timeout_s=2.0,
    )
    result = await provider.analyze(intent, {})

    assert isinstance(result, IntentAnalysis)
    assert result.raw_intent == expected.raw_intent
    assert result.data_types_needed == expected.data_types_needed
    assert result.entities == expected.entities
    assert result.temporal_scope == expected.temporal_scope
    assert result.estimated_sensitivity == expected.estimated_sensitivity

    raw_hash = provider._last_raw_response_hash  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert isinstance(raw_hash, str)
    assert len(raw_hash) == 64
