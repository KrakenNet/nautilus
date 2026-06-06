"""LLM-backed source adapter — LLMs as a brokered data source (#43).

Treats an OpenAI-compatible chat-completions endpoint (vLLM, llama.cpp,
LM Studio, OpenAI, or any proxy speaking the same dialect) as a queryable
data source. This is data-plane, not control-plane: the LLM's responses
are *data* routed and policed by CLIPS — no LLM reasoning enters the
routing path.

Key properties:

- ``capabilities = {"non_deterministic"}`` — the broker skips response
  hashing and signs a ``hash_skipped=True`` attestation claim instead
  (AC-19.g, DQ2 LOCKED).
- **Scope-limited prompt assembly**: the prompt is built exclusively from
  the router-issued :class:`IntentAnalysis` and :class:`ScopeConstraint`
  list — :func:`_assemble_prompt`'s signature does not accept the request
  ``context``, so session tokens / clearance / embeddings can never leak
  into a prompt by construction. Note ``raw_intent``/``entities`` are
  agent-supplied and reach the prompt *by design* (they ARE the request);
  the mitigation for adversarial intent text is data-plane treatment —
  the LLM's output is provenance-marked data policed by CLIPS, never
  routing input.
- **Provenance marking**: every returned row carries
  ``provenance="llm_generated"`` so escalation/denial rules can
  distinguish generated content from records of fact.
- Loopback/private endpoints are ALLOWED (local inference is the
  air-gap-compatible deployment); link-local/metadata and multicast
  literals are rejected. Under ``serve --air-gapped`` non-loopback LLM
  sources are dropped entirely (see ``nautilus.cli.serve``).
"""

from __future__ import annotations

import ipaddress
import time
from typing import Any, ClassVar

import httpx

from nautilus.adapters.base import (
    AdapterError,
    ScopeEnforcementError,
    validate_field,
    validate_operator,
)
from nautilus.adapters.rest import _auth_for_config  # pyright: ignore[reportPrivateUsage]
from nautilus.adapters.schema import AdapterSchema
from nautilus.config.models import MtlsAuth, SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

_DEFAULT_TIMEOUT_S = 30.0

_SYSTEM_PROMPT = (
    "You are a data source behind the Nautilus data broker. Answer the "
    "request using only information consistent with the hard constraints "
    "listed. If the constraints exclude the requested information, say so "
    "instead of speculating."
)


def _reject_unroutable_literal(base_url: str) -> None:
    """Reject link-local/metadata, multicast, and unspecified IP literals.

    Unlike :class:`~nautilus.adapters.rest.RestAdapter` (which also blocks
    loopback/private as SSRF defense), loopback and RFC1918 literals are
    *allowed* here: a local inference server is the primary —and the only
    air-gap-compatible— deployment for an LLM source. Cloud metadata
    endpoints (169.254.x.x) stay blocked.
    """
    host = httpx.URL(base_url).host
    if not host:
        raise ScopeEnforcementError(
            f"LLMAdapter requires a non-empty host in base_url '{base_url}'"
        )
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # hostname literal; resolution is out of scope
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise ScopeEnforcementError(
            f"LLMAdapter refuses link-local/multicast/unspecified base URL host: {host}"
        )


def _assemble_prompt(intent: IntentAnalysis, scope: list[ScopeConstraint]) -> str:
    """Build the user prompt from intent + scope ONLY.

    Security invariant (#43 acceptance): scope violation in prompt assembly
    is impossible by construction — this function's signature does not
    accept the request ``context`` dict, so clearance, session tokens, and
    other per-request secrets cannot enter the prompt. Every constraint is
    validated against the operator/field allowlists before rendering.
    """
    for constraint in scope:
        validate_operator(constraint.operator)
        validate_field(constraint.field)

    data_types = ", ".join(intent.data_types_needed) if intent.data_types_needed else "(none)"
    entities = ", ".join(intent.entities) if intent.entities else "(none)"
    lines = [
        f"Request: {intent.raw_intent}",
        f"Data types in scope: {data_types}",
        f"Entities of interest: {entities}",
    ]
    if intent.temporal_scope:
        lines.append(f"Temporal scope: {intent.temporal_scope}")
    if scope:
        lines.append("Hard constraints — only consider information satisfying ALL of:")
        for constraint in scope:
            if constraint.operator == "IS NULL":
                lines.append(f"- {constraint.field} IS NULL")
            else:
                lines.append(f"- {constraint.field} {constraint.operator} {constraint.value!r}")
    else:
        lines.append("Hard constraints: none declared for this source.")
    return "\n".join(lines)


class LLMAdapter:
    """Adapter Protocol impl treating an LLM endpoint as a data source.

    ``config.connection`` is the OpenAI-compatible base URL (e.g.
    ``http://localhost:8000/v1``); ``config.model`` selects the model.
    ``config.auth`` (bearer/basic) attaches the same way as for
    :class:`~nautilus.adapters.rest.RestAdapter`.
    """

    source_type: ClassVar[str] = "llm"
    # AC-19.g — broker skips response hashing and signs hash_skipped=True.
    capabilities: ClassVar[frozenset[str]] = frozenset({"non_deterministic"})

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        # ``client`` is injectable so unit tests can pass an
        # ``httpx.MockTransport``-backed client (mirrors RestAdapter).
        self._client: httpx.AsyncClient | None = client
        self._config: SourceConfig | None = None
        self._model: str | None = None
        self._closed = False

    async def connect(self, config: SourceConfig) -> None:
        """Validate the endpoint + model and build the HTTP client."""
        _reject_unroutable_literal(config.connection)
        if not config.model:
            raise AdapterError(
                f"LLMAdapter source '{config.id}' requires a 'model' field in its source block"
            )
        if isinstance(config.auth, MtlsAuth):
            # Fail closed rather than silently dropping the credential:
            # _auth_for_config returns None for mTLS (RestAdapter wires it
            # via client cert kwargs, which this adapter doesn't support).
            raise AdapterError(
                f"LLMAdapter source '{config.id}' does not support mTLS auth; "
                "use bearer/basic or front the endpoint with a TLS-terminating proxy"
            )
        self._config = config
        self._model = config.model
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=config.connection,
                timeout=_DEFAULT_TIMEOUT_S,
                auth=_auth_for_config(config),
                # Never follow redirects (RestAdapter precedent, NFR-17):
                # a 3xx pointing at e.g. a metadata endpoint is parsed as a
                # non-OpenAI response shape and surfaces as AdapterError.
                follow_redirects=False,
            )

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """POST a scoped completion request and return the response as data.

        ``context`` is deliberately unused: it may carry session tokens and
        clearance markers that must never reach an external model. Prompt
        text comes from :func:`_assemble_prompt` (intent + scope only).
        """
        del context  # by-construction exclusion — see docstring
        if self._client is None or self._config is None or self._model is None:
            raise AdapterError("LLMAdapter.execute() called before connect()")

        prompt = _assemble_prompt(intent, scope)  # raises ScopeEnforcementError pre-network
        started = time.perf_counter()
        try:
            response = await self._client.post(
                "chat/completions",
                json={
                    "model": self._model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0,
                },
            )
            response.raise_for_status()
            body: Any = response.json()
            content = body["choices"][0]["message"]["content"]
        except httpx.HTTPError as exc:
            raise AdapterError(f"LLMAdapter call failed: {exc}") from exc
        except (KeyError, IndexError, TypeError) as exc:
            raise AdapterError(
                f"LLMAdapter received a non-OpenAI-compatible response shape: {exc}"
            ) from exc

        duration_ms = int((time.perf_counter() - started) * 1000)
        return AdapterResult(
            source_id=self._config.id,
            rows=[
                {
                    # Provenance marking (#43 scope item 2): rules can
                    # distinguish generated content from records of fact.
                    "content": str(content),
                    "provenance": "llm_generated",
                    "model": self._model,
                }
            ],
            duration_ms=duration_ms,
        )

    async def close(self) -> None:
        """Release the HTTP client. Idempotent (FR-17, AC-8.6)."""
        if self._closed:
            return
        self._closed = True
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_schema(self) -> AdapterSchema:
        """Static capability-only schema (RestAdapter precedent, AC-21/OQ3)."""
        if self._config is None:
            return AdapterSchema.unknown("llm", self.source_type)
        return AdapterSchema.unknown(self._config.id, self.source_type)


__all__ = ["LLMAdapter"]
