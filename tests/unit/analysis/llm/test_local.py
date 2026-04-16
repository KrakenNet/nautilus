"""Phase-3 cassette-driven tests for :class:`LocalInferenceProvider` (Task 3.7).

Replays the three canonical prompts from
``tests/fixtures/llm/local_cassette.yaml`` against a mocked
OpenAI-compatible client and asserts the returned :class:`IntentAnalysis`
matches the cassette's ``choices[0].message.content`` JSON payload
(AC-6.6, NFR-12). The local cassette points at ``http://127.0.0.1:8080/v1``
— the fixture convention for an air-gapped vLLM / llama.cpp instance — so
the same prompt set exercises the local branch of the determinism harness
without a live server.

:class:`LocalInferenceProvider` inherits :meth:`OpenAIProvider.analyze`;
we patch ``AsyncOpenAI`` on BOTH modules because ``local_provider`` rebinds
the import at module-load time (``from ... import AsyncOpenAI``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from nautilus.analysis.llm import local_provider as lp_mod
from nautilus.analysis.llm import openai_provider as op_mod
from nautilus.analysis.llm.local_provider import LocalInferenceProvider
from nautilus.core.models import IntentAnalysis

_CASSETTE_PATH: Path = (
    Path(__file__).resolve().parents[4] / "tests" / "fixtures" / "llm" / "local_cassette.yaml"
)


def _load_cassette() -> list[dict[str, Any]]:
    with _CASSETTE_PATH.open("r", encoding="utf-8") as f:
        doc = cast(dict[str, Any], yaml.safe_load(f))
    return cast(list[dict[str, Any]], doc["interactions"])


def _intent_from_user_message(content: str) -> str:
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
) -> dict[str, Any]:
    """Patch ``AsyncOpenAI`` on both modules with a capturing fake.

    Returns a container the test inspects post-call to verify the
    ``base_url`` plumbing survived the ``LocalInferenceProvider._build_client``
    override.
    """
    captured: dict[str, Any] = {"client_init_kwargs": None}

    response = MagicMock()
    response.output_parsed = parsed
    response.id = response_id

    async def _parse(**_kwargs: Any) -> Any:
        return response

    def _factory(**init_kwargs: Any) -> Any:
        captured["client_init_kwargs"] = init_kwargs
        client = MagicMock()
        client.responses = MagicMock()
        client.responses.parse = AsyncMock(side_effect=_parse)
        return client

    monkeypatch.setattr(op_mod, "AsyncOpenAI", _factory)
    monkeypatch.setattr(lp_mod, "AsyncOpenAI", _factory)
    return captured


@pytest.mark.unit
@pytest.mark.parametrize(
    ("intent", "expected", "response_id"),
    _build_params(),
)
async def test_local_cassette_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
    intent: str,
    expected: IntentAnalysis,
    response_id: str,
) -> None:
    """Provider returns the cassette's parsed :class:`IntentAnalysis` unchanged,
    routes through ``base_url`` with the default ``"not-needed"`` api_key."""
    captured = _install_fake_openai(monkeypatch, expected, response_id)

    provider = LocalInferenceProvider(
        base_url="http://127.0.0.1:8080/v1",
        model="nautilus-local-intent-v1",
        timeout_s=2.0,
    )
    result = await provider.analyze(intent, {})

    assert isinstance(result, IntentAnalysis)
    assert result.raw_intent == expected.raw_intent
    assert result.data_types_needed == expected.data_types_needed
    assert result.entities == expected.entities
    assert result.temporal_scope == expected.temporal_scope
    assert result.estimated_sensitivity == expected.estimated_sensitivity

    # base_url survives the _build_client override — distinguishes the local
    # provider from the cloud OpenAI provider (design §3.8 FR-13).
    client_kwargs = captured["client_init_kwargs"]
    assert client_kwargs is not None
    assert client_kwargs["base_url"] == "http://127.0.0.1:8080/v1"
    assert client_kwargs["api_key"] == "not-needed"

    raw_hash = provider._last_raw_response_hash  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert isinstance(raw_hash, str)
    assert len(raw_hash) == 64
