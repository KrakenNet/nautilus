"""Local-inference :class:`LLMIntentProvider` — design §3.8, FR-13.

Air-gap-compatible sibling of :class:`OpenAIProvider` that points at an
OpenAI-compatible local inference server (vLLM, llama.cpp, LM Studio,
etc.) via a configurable ``base_url``. Accepts any ``model`` string
verbatim so operators can swap fine-tuned local checkpoints without
code changes (D-5).

The constructor does NOT touch the network — a live local server is
not required until :meth:`analyze` is invoked — so misconfigured
base URLs surface at request time rather than at :meth:`Broker.setup`.
:meth:`health_check` is a no-op by design: local servers typically
have no auth and no reliable presence-probe semantics, so we let the
first real call fail with :class:`LLMProviderError` instead of
smuggling network I/O into startup (AC-6.6).
"""

from __future__ import annotations

import os
from typing import Any

from nautilus.analysis.llm.base import LLMProviderError
from nautilus.analysis.llm.openai_provider import AsyncOpenAI, OpenAIProvider


class LocalInferenceProvider(OpenAIProvider):
    """OpenAI-compatible local-inference intent analyzer.

    Inherits the :meth:`analyze` / :meth:`responses.parse` plumbing
    from :class:`OpenAIProvider` and overrides only the client factory
    and health-check semantics. The API key defaults to
    ``"not-needed"`` because most local servers ignore the header.
    """

    provider_name: str = "local-inference"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        timeout_s: float,
        api_key: str = "not-needed",
        api_key_env: str | None = None,
    ) -> None:
        # Parent's ``__init__`` guards the ``openai`` import and raises
        # :class:`LLMProviderError` if the extra is missing; we simply
        # forward and then stamp the local-inference specifics.
        super().__init__(
            api_key_env=api_key_env or "__NAUTILUS_LOCAL_INFERENCE_UNUSED__",
            model=model,
            timeout_s=timeout_s,
        )
        self.base_url = base_url
        self._api_key_literal = api_key
        self._api_key_env_is_optional = api_key_env is None

    def health_check(self) -> None:
        """No-op. Local servers fail at :meth:`analyze` time, not here.

        If the caller wired an explicit ``api_key_env`` (e.g. for a
        local proxy that does require auth), enforce the same
        presence-check as :class:`OpenAIProvider`.
        """
        if self._api_key_env_is_optional:
            return
        if not os.getenv(self.api_key_env):
            raise LLMProviderError(
                f"LocalInferenceProvider: env var {self.api_key_env!r} is unset or empty"
            )

    def _build_client(self) -> Any:
        """Construct an :class:`AsyncOpenAI` client pointed at ``base_url``."""
        assert AsyncOpenAI is not None  # narrowed by __init__ guard
        if self._api_key_env_is_optional:
            api_key = self._api_key_literal
        else:
            api_key = os.getenv(self.api_key_env) or self._api_key_literal
        return AsyncOpenAI(
            api_key=api_key,
            base_url=self.base_url,
            timeout=self.timeout_s,
        )
