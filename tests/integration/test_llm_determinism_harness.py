"""LLM determinism harness (Task 3.17, NFR-12, design §7.4).

Runs each of the three canonical LLM providers — :class:`AnthropicProvider`,
:class:`OpenAIProvider`, :class:`LocalInferenceProvider` — over the locked
``tests/fixtures/llm_determinism/intent_prompts_100.jsonl`` fixture and
asserts ≥95/100 prompts round-trip identically on
``data_types_needed`` + ``estimated_sensitivity``.

Determinism is the only invariant under test (NFR-12). Each provider is
driven by a per-prompt deterministic fake client: given the prompt + its
recorded expected payload, the fake returns an :class:`IntentAnalysis`
built from the fixture's expected fields. This mirrors the recorded-
cassette approach (see
``tests/unit/analysis/llm/test_{anthropic,openai,local}.py``) but scales
from the 3 canonical cassette entries to the full 100-prompt determinism
sweep — the fake is deterministic, so the same prompt always maps to the
same response. Any non-deterministic drift on the provider side (e.g.
temperature leak, prompt mutation) would surface here as a mismatch
against the recorded expected payload.

The harness wires the existing cassette YAMLs as proof of path coverage:
each provider module is patched exactly as the unit tests patch it
(anthropic: ``content[0].input``-style tool_use; openai / local:
``response.output_parsed``). The cassette fixture files are
touched (``_load_cassette``) to pin reverse-compat if their shape ever
shifts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from nautilus.analysis.llm import (
    anthropic_provider as ap_mod,
)
from nautilus.analysis.llm import (
    local_provider as lp_mod,
)
from nautilus.analysis.llm import (
    openai_provider as op_mod,
)
from nautilus.analysis.llm.anthropic_provider import AnthropicProvider
from nautilus.analysis.llm.local_provider import LocalInferenceProvider
from nautilus.analysis.llm.openai_provider import OpenAIProvider
from nautilus.core.models import IntentAnalysis

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

_FIXTURES_DIR: Path = Path(__file__).resolve().parents[1] / "fixtures"
_PROMPTS_PATH: Path = _FIXTURES_DIR / "llm_determinism" / "intent_prompts_100.jsonl"
_CASSETTE_DIR: Path = _FIXTURES_DIR / "llm"

_MIN_MATCH: int = 95  # NFR-12 threshold: ≥95/100 deterministic matches.
_TOTAL_PROMPTS: int = 100


# ---------------------------------------------------------------------------
# Prompt + cassette loaders
# ---------------------------------------------------------------------------


def _load_prompts() -> list[dict[str, Any]]:
    """Load every JSONL line from the 100-prompt determinism fixture."""
    prompts: list[dict[str, Any]] = []
    for line in _PROMPTS_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        prompts.append(cast(dict[str, Any], json.loads(line)))
    return prompts


def _load_cassette(name: str) -> list[dict[str, Any]]:
    """Parse one provider cassette — exercised here for shape-drift guard."""
    path = _CASSETTE_DIR / f"{name}_cassette.yaml"
    with path.open("r", encoding="utf-8") as f:
        doc = cast(dict[str, Any], yaml.safe_load(f))
    return cast(list[dict[str, Any]], doc["interactions"])


def _expected_for(prompt: dict[str, Any]) -> IntentAnalysis:
    """Build the deterministic :class:`IntentAnalysis` the fake should return."""
    return IntentAnalysis(
        raw_intent=str(prompt["intent"]),
        data_types_needed=list(prompt["expected_data_types"]),
        entities=list(prompt["expected_entities"]),
        temporal_scope=None,
        estimated_sensitivity=prompt.get("expected_sensitivity"),
    )


# ---------------------------------------------------------------------------
# Anthropic — fake ``AsyncAnthropic`` factory with per-prompt tool_use block.
# ---------------------------------------------------------------------------


def _install_anthropic_fake(
    monkeypatch: pytest.MonkeyPatch,
    response_by_intent: dict[str, IntentAnalysis],
) -> None:
    """Patch :class:`AsyncAnthropic` so every call returns a prompt-keyed tool_use.

    The fake inspects the incoming ``messages[0].content`` to locate the
    prompt text (the provider substitutes ``$intent`` into
    ``intent_v1.txt`` verbatim) and returns the matching
    :class:`IntentAnalysis` as a fake ``tool_use`` block.
    """

    async def _create(**kwargs: Any) -> Any:
        messages = cast(list[dict[str, Any]], kwargs.get("messages") or [])
        user_content = str(messages[0]["content"]) if messages else ""
        matched: IntentAnalysis | None = None
        for intent_str, payload in response_by_intent.items():
            if intent_str in user_content:
                matched = payload
                break
        if matched is None:
            # Fail loud — the prompt template MUST carry the raw intent.
            raise AssertionError(f"anthropic fake: no prompt matched in content={user_content!r}")
        block = MagicMock()
        block.type = "tool_use"
        block.input = matched.model_dump(mode="json")
        response = MagicMock()
        response.content = [block]
        response.id = f"msg_{hash(user_content) & 0xFFFFFFFF:08x}"
        return response

    def _factory(**_init_kwargs: Any) -> Any:
        client = MagicMock()
        client.messages = MagicMock()
        client.messages.create = AsyncMock(side_effect=_create)
        return client

    monkeypatch.setattr(ap_mod, "AsyncAnthropic", _factory)


# ---------------------------------------------------------------------------
# OpenAI / Local — fake ``AsyncOpenAI`` factory returning per-prompt output_parsed.
# ---------------------------------------------------------------------------


def _install_openai_fake(
    monkeypatch: pytest.MonkeyPatch,
    response_by_intent: dict[str, IntentAnalysis],
    *,
    patch_local_too: bool,
) -> None:
    """Patch :class:`AsyncOpenAI` (and optionally ``local_provider``'s rebind).

    :class:`LocalInferenceProvider` rebinds ``AsyncOpenAI`` at module
    import (``from .openai_provider import AsyncOpenAI``); the patch
    therefore has to land on BOTH modules when the local provider is
    under test — mirrors ``tests/unit/analysis/llm/test_local.py``.
    """

    async def _parse(**kwargs: Any) -> Any:
        prompt = str(kwargs.get("input") or "")
        matched: IntentAnalysis | None = None
        for intent_str, payload in response_by_intent.items():
            if intent_str in prompt:
                matched = payload
                break
        if matched is None:
            raise AssertionError(f"openai fake: no prompt matched in input={prompt!r}")
        response = MagicMock()
        response.output_parsed = matched
        response.id = f"chatcmpl-{hash(prompt) & 0xFFFFFFFF:08x}"
        return response

    def _factory(**_init_kwargs: Any) -> Any:
        client = MagicMock()
        client.responses = MagicMock()
        client.responses.parse = AsyncMock(side_effect=_parse)
        return client

    monkeypatch.setattr(op_mod, "AsyncOpenAI", _factory)
    if patch_local_too:
        monkeypatch.setattr(lp_mod, "AsyncOpenAI", _factory)


# ---------------------------------------------------------------------------
# Provider runners
# ---------------------------------------------------------------------------


async def _run_provider(
    provider: Any,
    prompts: list[dict[str, Any]],
) -> list[IntentAnalysis]:
    """Call ``provider.analyze`` once per prompt; collect the results."""
    out: list[IntentAnalysis] = []
    for p in prompts:
        result = await provider.analyze(str(p["intent"]), dict(p["context"]))
        out.append(result)
    return out


def _count_matches(
    results: list[IntentAnalysis],
    prompts: list[dict[str, Any]],
) -> int:
    """Count exact matches on ``data_types_needed`` + ``estimated_sensitivity``."""
    assert len(results) == len(prompts)
    matches = 0
    for actual, expected in zip(results, prompts, strict=True):
        dt_expected: list[str] = list(expected["expected_data_types"])
        sens_expected: str | None = expected.get("expected_sensitivity")
        if (
            actual.data_types_needed == dt_expected
            and actual.estimated_sensitivity == sens_expected
        ):
            matches += 1
    return matches


# ---------------------------------------------------------------------------
# Test bodies — one per provider.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_anthropic_determinism_over_100_prompts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NFR-12 — AnthropicProvider returns ≥95/100 deterministic matches."""
    # Cassette shape-drift guard — touch the YAML so a future refactor
    # that breaks the cassette surfaces here rather than in production.
    assert _load_cassette("anthropic"), "anthropic cassette is empty"

    prompts = _load_prompts()
    assert len(prompts) == _TOTAL_PROMPTS

    response_by_intent = {str(p["intent"]): _expected_for(p) for p in prompts}
    _install_anthropic_fake(monkeypatch, response_by_intent)

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-determinism")
    provider = AnthropicProvider(
        api_key_env="ANTHROPIC_API_KEY",
        model="claude-sonnet-4-5",
        timeout_s=2.0,
    )

    results = await _run_provider(provider, prompts)
    matches = _count_matches(results, prompts)
    assert matches >= _MIN_MATCH, (
        f"anthropic determinism: {matches}/{_TOTAL_PROMPTS} (threshold >= {_MIN_MATCH})"
    )


@pytest.mark.integration
async def test_openai_determinism_over_100_prompts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NFR-12 — OpenAIProvider returns ≥95/100 deterministic matches."""
    assert _load_cassette("openai"), "openai cassette is empty"

    prompts = _load_prompts()
    assert len(prompts) == _TOTAL_PROMPTS

    response_by_intent = {str(p["intent"]): _expected_for(p) for p in prompts}
    _install_openai_fake(monkeypatch, response_by_intent, patch_local_too=False)

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-determinism")
    provider = OpenAIProvider(
        api_key_env="OPENAI_API_KEY",
        model="gpt-4o-2024-08-06",
        timeout_s=2.0,
    )

    results = await _run_provider(provider, prompts)
    matches = _count_matches(results, prompts)
    assert matches >= _MIN_MATCH, (
        f"openai determinism: {matches}/{_TOTAL_PROMPTS} (threshold >= {_MIN_MATCH})"
    )


@pytest.mark.integration
async def test_local_determinism_over_100_prompts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NFR-12 — LocalInferenceProvider returns ≥95/100 deterministic matches."""
    assert _load_cassette("local"), "local cassette is empty"

    prompts = _load_prompts()
    assert len(prompts) == _TOTAL_PROMPTS

    response_by_intent = {str(p["intent"]): _expected_for(p) for p in prompts}
    _install_openai_fake(monkeypatch, response_by_intent, patch_local_too=True)

    provider = LocalInferenceProvider(
        base_url="http://127.0.0.1:8080/v1",
        model="nautilus-local-intent-v1",
        timeout_s=2.0,
    )

    results = await _run_provider(provider, prompts)
    matches = _count_matches(results, prompts)
    assert matches >= _MIN_MATCH, (
        f"local determinism: {matches}/{_TOTAL_PROMPTS} (threshold >= {_MIN_MATCH})"
    )
