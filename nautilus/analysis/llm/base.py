"""LLM intent-provider Protocol + provenance record — design §3.8.

Defines the shared surface every LLM-backed intent analyzer
(:class:`AnthropicProvider`, :class:`OpenAIProvider`,
:class:`LocalInferenceProvider`) must satisfy so the broker can swap
providers via config without code changes (FR-13, D-5).

:class:`LLMProvenance` captures the per-call audit trail the broker
stamps onto :class:`nautilus.core.models.AuditEntry` (AC-6.5): which
provider answered, which prompt template was used, a deterministic hash
of the raw response (so operators can detect non-determinism), and
whether the deterministic pattern-matching fallback was invoked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from nautilus.core.models import IntentAnalysis


class LLMProviderError(Exception):
    """Raised by an :class:`LLMIntentProvider` when the underlying SDK,
    network, auth, rate limit, or schema binding fails.

    The broker's :class:`FallbackIntentAnalyzer` catches this alongside
    :class:`asyncio.TimeoutError` and :class:`pydantic.ValidationError`
    to decide whether to fall through to the deterministic pattern
    matcher (design §3.8, AC-6.3).
    """


@runtime_checkable
class LLMIntentProvider(Protocol):
    """Async LLM-backed intent analyzer — design §3.8, FR-13.

    Attributes mirror fields copied into :class:`LLMProvenance` and the
    audit entry so the broker can introspect a provider without calling
    it. ``prompt_version`` is derived from the locked prompt-template
    filename suffix (e.g. ``"v1"`` for ``intent_v1.txt``) so changes to
    the template force a visible version bump in the audit stream
    (NFR-12, AC-6.6).
    """

    model: str
    provider_name: str
    prompt_version: str

    async def analyze(self, intent: str, context: dict[str, Any]) -> IntentAnalysis:
        """Classify ``intent`` via the backing LLM.

        Implementations MUST:

        * bind the response to :class:`IntentAnalysis` via native
          structured-output / tool-use (no ad-hoc JSON parsing);
        * raise :class:`LLMProviderError` on any SDK / network / auth /
          rate-limit failure;
        * let :class:`pydantic.ValidationError` escape when the LLM
          returns a response that does not match the schema.

        Args:
            intent: Raw natural-language request from the agent.
            context: Per-request context (clearance, purpose, session
                id, optional embedding override, etc.).

        Returns:
            A populated :class:`IntentAnalysis` consumed by the router.
        """
        ...

    def health_check(self) -> None:
        """Fast liveness probe — raises :class:`LLMProviderError` if the
        provider is obviously misconfigured (e.g. missing API-key env
        var). Must NOT make network calls; wired into
        :meth:`Broker.setup` (AC-6.6).
        """
        ...


@dataclass(frozen=True)
class LLMProvenance:
    """Per-call audit trail stamped onto :class:`AuditEntry` — AC-6.5.

    Populated once per :meth:`FallbackIntentAnalyzer.analyze` call
    regardless of which path fired (primary vs fallback). The
    ``fallback_used`` flag lets operators grep the audit stream for
    degraded runs; ``raw_response_hash`` lets the 100-prompt
    determinism harness (NFR-12) detect non-determinism without storing
    the full response text.
    """

    provider: str
    model: str
    version: str
    prompt_version: str
    raw_response_hash: str
    fallback_used: bool
