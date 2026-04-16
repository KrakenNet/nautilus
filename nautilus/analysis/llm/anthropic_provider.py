"""Anthropic-backed :class:`LLMIntentProvider` — design §3.8, FR-13.

Wraps :class:`anthropic.AsyncAnthropic` with tool-use binding to the
:class:`IntentAnalysis` JSON schema so responses are constrained to the
Pydantic model without ad-hoc parsing (AC-6.1). All SDK / network / auth
failures surface as :class:`LLMProviderError`; schema drift surfaces as
:class:`pydantic.ValidationError` and bubbles to
:class:`FallbackIntentAnalyzer` (AC-6.3).

The prompt template is locked at ``prompts/intent_v1.txt`` and stamped
into :class:`LLMProvenance.prompt_version` as ``"v1"`` so any edit to the
template forces a visible version bump in the audit stream (NFR-12,
AC-6.6).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from string import Template
from typing import Any, cast

from nautilus.analysis.llm.base import LLMProviderError
from nautilus.core.models import IntentAnalysis

try:
    from anthropic import (
        APIConnectionError,
        APIError,
        APITimeoutError,
        AsyncAnthropic,
    )

    _anthropic_errors: tuple[type[BaseException], ...] = (
        APIError,
        APIConnectionError,
        APITimeoutError,
    )
    _import_error: ImportError | None = None
except ImportError as exc:  # pragma: no cover - guarded in __init__
    AsyncAnthropic = None  # type: ignore[assignment,misc]
    _anthropic_errors = ()
    _import_error = exc


_PROMPT_PATH = Path(__file__).parent / "prompts" / "intent_v1.txt"
_PROMPT_VERSION = "v1"
_TOOL_NAME = "emit_intent_analysis"


class AnthropicProvider:
    """Anthropic Claude-backed intent analyzer.

    Uses the Messages API with tool-use to pin the response to
    :meth:`IntentAnalysis.model_json_schema`; ``temperature=0`` and
    ``max_tokens=512`` keep the path deterministic enough for the
    100-prompt determinism harness (NFR-12).

    Constructor does NOT touch the network; :meth:`health_check` only
    asserts that ``api_key_env`` is populated so :meth:`Broker.setup`
    can fail fast on misconfiguration (AC-6.6).
    """

    provider_name: str = "anthropic"

    def __init__(
        self,
        *,
        api_key_env: str,
        model: str = "claude-sonnet-4-5",
        timeout_s: float,
    ) -> None:
        if AsyncAnthropic is None:
            raise LLMProviderError(
                "anthropic extra not installed; install nautilus[llm-anthropic]"
            ) from _import_error
        self.api_key_env = api_key_env
        self.model = model
        self.timeout_s = timeout_s
        self.prompt_version = _PROMPT_VERSION
        self._prompt_template = Template(_PROMPT_PATH.read_text(encoding="utf-8"))
        self._tool_schema: dict[str, Any] = IntentAnalysis.model_json_schema()
        self._last_raw_response_hash: str | None = None

    def health_check(self) -> None:
        """Presence-check the API-key env var. No network I/O."""
        key = os.getenv(self.api_key_env)
        if not key:
            raise LLMProviderError(
                f"AnthropicProvider: env var {self.api_key_env!r} is unset or empty"
            )

    async def analyze(self, intent: str, context: dict[str, Any]) -> IntentAnalysis:
        """Classify ``intent`` via Claude tool-use."""
        self.health_check()
        prompt = self._prompt_template.safe_substitute(
            intent=intent,
            context_json=json.dumps(context, sort_keys=True, default=str),
        )
        tool_def: dict[str, Any] = {
            "name": _TOOL_NAME,
            "description": "Emit the structured IntentAnalysis classification.",
            "input_schema": self._tool_schema,
        }
        assert AsyncAnthropic is not None  # narrowed by __init__ guard
        client = AsyncAnthropic(
            api_key=os.getenv(self.api_key_env),
            timeout=self.timeout_s,
        )
        try:
            response = await client.messages.create(
                model=self.model,
                max_tokens=512,
                temperature=0,
                messages=[{"role": "user", "content": prompt}],
                tools=[cast(Any, tool_def)],
                tool_choice={"type": "tool", "name": _TOOL_NAME},
            )
        except _anthropic_errors as exc:
            raise LLMProviderError(f"anthropic SDK call failed: {exc}") from exc

        tool_input = _extract_tool_use_input(response)
        # Stash the deterministic response hash for the broker's provenance stamp.
        response_id = cast(str, getattr(response, "id", ""))
        self._last_raw_response_hash = hashlib.sha256(
            (response_id + json.dumps(tool_input, sort_keys=True, default=str)).encode("utf-8")
        ).hexdigest()
        return IntentAnalysis.model_validate(tool_input)


def _extract_tool_use_input(response: Any) -> dict[str, Any]:
    """Pull the first ``tool_use`` block's ``input`` from a Messages response.

    Raises :class:`LLMProviderError` if no tool_use block is present;
    schema drift inside the block is caught downstream by
    :meth:`IntentAnalysis.model_validate`.
    """
    content = cast(list[Any], getattr(response, "content", []) or [])
    for block in content:
        if getattr(block, "type", None) == "tool_use":
            payload = getattr(block, "input", None)
            if isinstance(payload, dict):
                return cast(dict[str, Any], payload)
            raise LLMProviderError(
                f"anthropic tool_use block carried non-dict input: {type(payload)!r}"
            )
    raise LLMProviderError("anthropic response contained no tool_use block")
