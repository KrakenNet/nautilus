"""OpenAI-backed :class:`LLMIntentProvider` — design §3.8, FR-13.

Wraps :class:`openai.AsyncOpenAI` with the Structured Outputs API
(:meth:`responses.parse`) bound to :class:`IntentAnalysis` so responses
are constrained to the Pydantic model without ad-hoc parsing (AC-6.1).
All SDK / network / auth failures surface as :class:`LLMProviderError`;
schema drift surfaces as :class:`pydantic.ValidationError` and bubbles
to :class:`FallbackIntentAnalyzer` (AC-6.3).

The prompt template is locked at ``prompts/intent_v1.txt`` and stamped
into :class:`LLMProvenance.prompt_version` as ``"v1"`` so any edit to
the template forces a visible version bump in the audit stream
(NFR-12, AC-6.6).
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
    from openai import (
        APIConnectionError,
        APIError,
        APITimeoutError,
        AsyncOpenAI,
    )

    _openai_errors: tuple[type[BaseException], ...] = (
        APIError,
        APIConnectionError,
        APITimeoutError,
    )
    _import_error: ImportError | None = None
except ImportError as exc:  # pragma: no cover - guarded in __init__
    AsyncOpenAI = None  # type: ignore[assignment,misc]
    _openai_errors = ()
    _import_error = exc


_PROMPT_PATH = Path(__file__).parent / "prompts" / "intent_v1.txt"
_PROMPT_VERSION = "v1"


class OpenAIProvider:
    """OpenAI GPT-backed intent analyzer.

    Uses the Responses API with :meth:`responses.parse` and
    ``text_format=IntentAnalysis`` to pin the response to the Pydantic
    schema; ``temperature=0`` and ``max_output_tokens=512`` keep the
    path deterministic enough for the 100-prompt determinism harness
    (NFR-12).

    Constructor does NOT touch the network; :meth:`health_check` only
    asserts that ``api_key_env`` is populated so :meth:`Broker.setup`
    can fail fast on misconfiguration (AC-6.6).
    """

    provider_name: str = "openai"

    def __init__(
        self,
        *,
        api_key_env: str,
        model: str = "gpt-4o-2024-08-06",
        timeout_s: float,
    ) -> None:
        if AsyncOpenAI is None:
            raise LLMProviderError(
                "openai extra not installed; install nautilus[llm-openai]"
            ) from _import_error
        self.api_key_env = api_key_env
        self.model = model
        self.timeout_s = timeout_s
        self.prompt_version = _PROMPT_VERSION
        self._prompt_template = Template(_PROMPT_PATH.read_text(encoding="utf-8"))
        self._last_raw_response_hash: str | None = None

    def health_check(self) -> None:
        """Presence-check the API-key env var. No network I/O."""
        key = os.getenv(self.api_key_env)
        if not key:
            raise LLMProviderError(
                f"OpenAIProvider: env var {self.api_key_env!r} is unset or empty"
            )

    def _build_client(self) -> Any:
        """Construct the :class:`AsyncOpenAI` client for one call.

        Overridden by :class:`LocalInferenceProvider` to inject
        ``base_url`` / ``api_key='not-needed'`` for OpenAI-compatible
        local inference servers (vLLM / llama.cpp).
        """
        assert AsyncOpenAI is not None  # narrowed by __init__ guard
        return AsyncOpenAI(
            api_key=os.getenv(self.api_key_env),
            timeout=self.timeout_s,
        )

    async def analyze(self, intent: str, context: dict[str, Any]) -> IntentAnalysis:
        """Classify ``intent`` via OpenAI Structured Outputs."""
        self.health_check()
        prompt = self._prompt_template.safe_substitute(
            intent=intent,
            context_json=json.dumps(context, sort_keys=True, default=str),
        )
        client = self._build_client()
        try:
            response = await client.responses.parse(
                model=self.model,
                input=prompt,
                text_format=IntentAnalysis,
                temperature=0,
                max_output_tokens=512,
            )
        except _openai_errors as exc:
            raise LLMProviderError(f"openai SDK call failed: {exc}") from exc

        parsed = cast(IntentAnalysis | None, getattr(response, "output_parsed", None))
        if parsed is None:
            raise LLMProviderError("openai responses.parse returned no output_parsed payload")
        response_id = cast(str, getattr(response, "id", ""))
        self._last_raw_response_hash = hashlib.sha256(
            (
                response_id
                + json.dumps(parsed.model_dump(mode="json"), sort_keys=True, default=str)
            ).encode("utf-8")
        ).hexdigest()
        return parsed
