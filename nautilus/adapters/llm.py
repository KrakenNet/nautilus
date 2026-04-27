# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false, reportPrivateUsage=false, reportArgumentType=false
"""First-party LLM adapter (Tasks 37-39).

Routes chat-completion and embeddings calls across OpenAI, Anthropic, and
vLLM with unified usage normalisation, pre-flight token counts (the
``estimate_cost()`` hook used by :func:`Broker._enforce_cost_caps`), and
adapter-boundary DSSE session signing (AC-5.9 / AC-5.10 / AC-5.14).

Provider × surface matrix (AC-5.2):
    +----------+------+------------+
    | provider | chat | embeddings |
    +----------+------+------------+
    | openai   |  yes |    yes     |
    | anthropic|  yes |    no (*)  |
    | vllm     |  yes |    yes     |
    +----------+------+------------+
    (*) ``{anthropic, embeddings}`` is rejected at ``connect()`` per AC-5.2.

Streaming is deferred to v2 (AC-5.6); ``stream=true`` raises
:class:`ConfigError` at ``connect()``.

Output-hash policy (AC-5.10, TD-15):
    chat       → SHA-256 of JCS canonical bytes of the response ``content``
    embeddings → SHA-256 of big-endian IEEE-754 float32 raw bytes
                 (re-packed even when OpenAI returned the vector as a JSON
                 array, so the hash is provider-independent).

Fail-closed semantics (AC-5.12, NFR-SEC-SIGN):
    Signer raises → execute() raises ``AdapterError`` → broker surfaces 503.
    No retry. No unsigned response.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import struct
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar

import httpx
import rfc8785

from nautilus.adapters.base import Adapter, AdapterError
from nautilus.config.models import SessionSigningConfig, SourceConfig
from nautilus.config.secrets import resolve as resolve_secret
from nautilus.config.secrets.vault_transit import build_transit_signer_ref
from nautilus.core.circuit_breaker import CircuitBreaker
from nautilus.core.models import AdapterResult, ErrorRecord, IntentAnalysis, ScopeConstraint
from nautilus.core.signer import (
    InProcessEd25519Signer,
    Signer,
    VaultTransitSignerAdapter,
    _build_dsse_envelope,
)

if TYPE_CHECKING:  # pragma: no cover - import-only for type hints
    from anthropic import AsyncAnthropic
    from openai import AsyncOpenAI

logger = logging.getLogger(__name__)


class ConfigError(AdapterError):
    """Raised when an LLM source's config rejects validation at connect()."""


class PreflightEstimate:
    """Pre-flight token-count estimate produced by :meth:`LLMAdapter.estimate_cost`."""

    def __init__(self, *, input_tokens: int) -> None:
        self.input_tokens = input_tokens

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"PreflightEstimate(input_tokens={self.input_tokens})"


_OPENAI_DEFAULT_BASE = "https://api.openai.com/v1"
_ANTHROPIC_DEFAULT_BASE = "https://api.anthropic.com"


def _now_rfc3339_ms() -> str:
    """RFC 3339 UTC timestamp with millisecond precision (AC-5.10)."""
    now = datetime.now(UTC)
    # millisecond precision; trim microseconds to milliseconds and add Z.
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _hash_jcs(payload: object) -> str:
    """SHA-256 of the RFC 8785 canonical bytes of ``payload``."""
    return hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def _hash_embedding_output(vector: list[float]) -> str:
    """SHA-256 of big-endian IEEE-754 float32 raw bytes (TD-15, AC-5.10b).

    Re-packs the vector regardless of how the provider returned it so the
    hash is provider-independent; OpenAI returns a JSON-array of floats by
    default, vLLM may return base64, and Voyage may return doubles. All
    funnel through the same float32-big-endian pipe before SHA-256.
    """
    packed = struct.pack(">" + "f" * len(vector), *vector)
    return hashlib.sha256(packed).hexdigest()


class LLMAdapter:
    """Adapter for chat / embeddings across OpenAI / Anthropic / vLLM."""

    source_type: ClassVar[str] = "llm"

    def __init__(self) -> None:
        self._source_id: str = ""
        self._provider: str = ""
        self._surface: str = ""
        self._model: str = ""
        self._endpoint: str | None = None
        self._openai: AsyncOpenAI | None = None
        self._anthropic: AsyncAnthropic | None = None
        self._http: httpx.AsyncClient | None = None
        self._signer: Signer | None = None
        self._signing_cfg: SessionSigningConfig | None = None
        self._params: dict[str, Any] = {}

    # ------------------------------------------------------------------ connect

    async def connect(self, config: SourceConfig) -> None:
        if config.type != "llm":
            raise ConfigError(f"LLMAdapter received non-llm source type {config.type!r}")
        if config.llm_provider is None or config.llm_model is None or config.surface is None:
            raise ConfigError("LLM source requires llm_provider, llm_model, and surface to be set")
        if config.stream:
            raise ConfigError("streaming deferred to v2")
        if config.llm_provider == "anthropic" and config.surface == "embeddings":
            raise ConfigError(
                "Anthropic does not offer first-party embeddings; use a different provider"
            )

        self._source_id = config.id
        self._provider = config.llm_provider
        self._surface = config.surface
        self._model = config.llm_model
        self._endpoint = config.endpoint
        self._params = {}

        # Lazy import the provider SDK so users that never use the LLM adapter
        # do not pay the import cost at startup.
        if self._provider in ("openai", "vllm"):
            from openai import AsyncOpenAI

            base_url = self._endpoint or (
                _OPENAI_DEFAULT_BASE if self._provider == "openai" else None
            )
            if self._provider == "vllm" and base_url is None:
                raise ConfigError("vLLM source requires an explicit 'endpoint' base URL")
            api_key = await self._resolve_api_key(config)
            self._openai = AsyncOpenAI(base_url=base_url, api_key=api_key)
        elif self._provider == "anthropic":
            from anthropic import AsyncAnthropic

            api_key = await self._resolve_api_key(config)
            base_url = self._endpoint or _ANTHROPIC_DEFAULT_BASE
            self._anthropic = AsyncAnthropic(api_key=api_key, base_url=base_url)
            # Anthropic count_tokens uses raw HTTP — keep our own client.
            self._http = httpx.AsyncClient(
                base_url=base_url,
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                timeout=30.0,
            )
        else:  # pragma: no cover - guarded by Literal
            raise ConfigError(f"unknown llm_provider: {self._provider!r}")

        await self._build_signer(config.session_signing)

    async def _resolve_api_key(self, config: SourceConfig) -> str:
        """Resolve the provider API key.

        ``token_secret_ref`` carries the URI; bare strings are treated as
        env-interpolated literals (already resolved by ``loader.py``).
        """
        ref = config.token_secret_ref
        if not ref:
            return ""  # vLLM self-hosted may not need auth
        if "://" in ref:
            return await resolve_secret(ref)
        return ref

    async def _build_signer(self, cfg: SessionSigningConfig | None) -> None:
        """Construct the appropriate :class:`Signer` based on ``cfg.key_ref`` scheme."""
        self._signer = None
        self._signing_cfg = cfg
        if cfg is None or not cfg.enabled:
            return
        if not cfg.key_ref:
            raise ConfigError("session_signing.enabled but key_ref is empty")
        scheme, _, _ = cfg.key_ref.partition("://")
        if scheme == "env":
            seed = await resolve_secret(cfg.key_ref)
            self._signer = InProcessEd25519Signer(
                seed_hex=seed.strip(),
                keyid=f"{self._source_id}:{scheme}",
            )
        elif scheme == "vault":
            seed = await resolve_secret(cfg.key_ref)
            self._signer = InProcessEd25519Signer(
                seed_hex=seed.strip(),
                keyid=f"{self._source_id}:vault",
            )
        elif scheme == "vault-transit":
            import os

            transit = build_transit_signer_ref(cfg.key_ref)
            vault_addr = os.environ.get("VAULT_ADDR")
            vault_token = os.environ.get("VAULT_TOKEN")
            if not vault_addr or not vault_token:
                raise ConfigError(
                    "vault-transit:// signing requires VAULT_ADDR + VAULT_TOKEN env vars"
                )
            breaker = CircuitBreaker(name=f"signer:{self._source_id}")
            self._signer = VaultTransitSignerAdapter(
                key_name=transit.key_name,
                vault_addr=vault_addr,
                vault_token=vault_token,
                breaker=breaker,
                keyid=f"{self._source_id}:{transit.key_name}",
            )
        else:
            raise ConfigError(f"unsupported session_signing.key_ref scheme {scheme!r}")

    # ---------------------------------------------------------------- estimate

    async def estimate_cost(
        self, intent: IntentAnalysis, context: dict[str, Any]
    ) -> PreflightEstimate:
        """Pre-flight token count for cost-cap enforcement (AC-5.7, FR-12)."""
        messages = self._build_messages(intent, context)
        if self._provider in ("openai", "vllm"):
            import tiktoken

            try:
                enc = tiktoken.encoding_for_model(self._model)
            except KeyError:
                # Unknown model — use the latest OpenAI cl100k_base default.
                enc = tiktoken.get_encoding("cl100k_base")
            # Approximate per-message overhead per OpenAI cookbook.
            tokens = 0
            for msg in messages:
                tokens += 4
                for value in msg.values():
                    tokens += len(enc.encode(value))
            tokens += 2
            return PreflightEstimate(input_tokens=tokens)

        if self._provider == "anthropic":
            assert self._http is not None
            response = await self._http.post(
                "/v1/messages/count_tokens",
                json={"model": self._model, "messages": messages},
            )
            response.raise_for_status()
            return PreflightEstimate(input_tokens=int(response.json()["input_tokens"]))

        raise ConfigError(f"unknown provider {self._provider!r}")  # pragma: no cover

    def _build_messages(
        self, intent: IntentAnalysis, context: dict[str, Any]
    ) -> list[dict[str, str]]:
        """Build a provider-shaped messages list from ``intent`` + ``context``.

        For chat: callers MAY provide ``context["messages"]`` to override the
        default ``[{"role": "user", "content": intent.raw_intent}]``.
        For embeddings the same input strings are used; ``context["inputs"]``
        is the override.
        """
        if self._surface == "embeddings":
            inputs = context.get("inputs") or [intent.raw_intent]
            if not isinstance(inputs, list):
                inputs = [inputs]
            return [{"role": "input", "content": str(s)} for s in inputs]
        msgs = context.get("messages")
        if isinstance(msgs, list) and msgs:
            return [
                {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
                for m in msgs
            ]
        return [{"role": "user", "content": intent.raw_intent}]

    # ----------------------------------------------------------------- execute

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del scope  # LLM adapter does not enforce scope constraints in v1
        start = time.monotonic()
        try:
            if self._surface == "chat":
                rows, usage = await self._execute_chat(intent, context)
            elif self._surface == "embeddings":
                rows, usage = await self._execute_embeddings(intent, context)
            else:  # pragma: no cover
                raise ConfigError(f"unknown surface {self._surface!r}")
        except AdapterError:
            raise
        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            return AdapterResult(
                source_id=self._source_id,
                rows=[],
                duration_ms=duration_ms,
                error=ErrorRecord(
                    source_id=self._source_id,
                    error_type=type(exc).__name__,
                    message=str(exc),
                    trace_id="",
                ),
            )

        duration_ms = int((time.monotonic() - start) * 1000)
        usage["duration_ms"] = duration_ms

        signature: dict[str, Any] | None = None
        if self._signer is not None:
            signature = await self._sign_response(intent, context, rows)

        return AdapterResult(
            source_id=self._source_id,
            rows=rows,
            duration_ms=duration_ms,
            meta=usage,
            signature=signature,
        )

    async def _execute_chat(
        self, intent: IntentAnalysis, context: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        messages = self._build_messages(intent, context)
        params = self._extract_params(context, axis="chat")
        self._params = params  # snapshot for params_hash
        if self._provider in ("openai", "vllm"):
            assert self._openai is not None
            response = await self._openai.chat.completions.create(
                model=self._model,
                messages=messages,  # type: ignore[arg-type]
                **{k: v for k, v in params.items() if v is not None},
            )
            content = response.choices[0].message.content or ""
            tool_calls = response.choices[0].message.tool_calls or []
            usage_raw = response.usage
            usage = {
                "input_tokens": getattr(usage_raw, "prompt_tokens", 0),
                "output_tokens": getattr(usage_raw, "completion_tokens", 0),
                "cached_tokens": 0,
                "total_tokens": getattr(usage_raw, "total_tokens", 0),
                "tool_call_count": len(tool_calls),
            }
            return ([{"content": content, "tool_calls": _serialize_tool_calls(tool_calls)}], usage)

        # anthropic chat
        assert self._anthropic is not None
        response = await self._anthropic.messages.create(
            model=self._model,
            messages=messages,  # type: ignore[arg-type]
            max_tokens=int(params.get("max_tokens") or 1024),
            **{k: v for k, v in params.items() if k != "max_tokens" and v is not None},
        )
        content_blocks = response.content or []
        text = "".join(getattr(b, "text", "") for b in content_blocks if hasattr(b, "text"))
        tool_calls = [b for b in content_blocks if getattr(b, "type", "") == "tool_use"]
        usage_raw = response.usage
        cache_read = getattr(usage_raw, "cache_read_input_tokens", 0) or 0
        cache_create = getattr(usage_raw, "cache_creation_input_tokens", 0) or 0
        usage = {
            "input_tokens": getattr(usage_raw, "input_tokens", 0),
            "output_tokens": getattr(usage_raw, "output_tokens", 0),
            "cached_tokens": cache_read,
            "total_tokens": (
                getattr(usage_raw, "input_tokens", 0)
                + getattr(usage_raw, "output_tokens", 0)
                + cache_read
                + cache_create
            ),
            "tool_call_count": len(tool_calls),
        }
        return ([{"content": text, "tool_calls": _serialize_tool_calls(tool_calls)}], usage)

    async def _execute_embeddings(
        self, intent: IntentAnalysis, context: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        inputs_msgs = self._build_messages(intent, context)
        inputs = [m["content"] for m in inputs_msgs]
        params = self._extract_params(context, axis="embeddings")
        self._params = params
        assert self._openai is not None  # only OpenAI/vLLM reach this branch
        response = await self._openai.embeddings.create(
            model=self._model,
            input=inputs,
            **{k: v for k, v in params.items() if v is not None},
        )
        rows = [{"embedding": list(item.embedding), "index": item.index} for item in response.data]
        usage_raw = response.usage
        usage = {
            "input_tokens": getattr(usage_raw, "prompt_tokens", 0),
            "output_tokens": 0,
            "cached_tokens": 0,
            "total_tokens": getattr(usage_raw, "total_tokens", 0),
            "tool_call_count": 0,
        }
        return (rows, usage)

    def _extract_params(self, context: dict[str, Any], *, axis: str) -> dict[str, Any]:
        keys = (
            ("temperature", "top_p", "max_tokens")
            if axis == "chat"
            else ("dimensions", "encoding_format")
        )
        return {k: context.get(k) for k in keys}

    # ---------------------------------------------------------------- signing

    async def _sign_response(
        self,
        intent: IntentAnalysis,
        context: dict[str, Any],
        rows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build the 5-field canonical payload and produce a DSSE envelope.

        Fail-closed: any signer exception propagates to ``execute()``, which
        re-raises as :class:`AdapterError`. The broker maps that to HTTP 503.
        Never return an unsigned response (NFR-SEC-SIGN, AC-5.12).
        """
        assert self._signer is not None
        if self._surface == "chat":
            output_hash = _hash_jcs(rows[0].get("content", ""))
        else:
            # Embeddings: hash the (concatenation of) all returned vectors so
            # multi-input requests still produce a single output_hash. TD-15
            # mandates re-packing to big-endian float32 regardless of provider.
            all_floats: list[float] = []
            for r in rows:
                all_floats.extend(r["embedding"])
            output_hash = _hash_embedding_output(all_floats)

        if self._surface == "chat":
            messages = self._build_messages(intent, context)
            prompt_payload: object = messages
        else:
            prompt_payload = [m["content"] for m in self._build_messages(intent, context)]

        canonical_payload = {
            "model_id": self._model,
            "output_hash": output_hash,
            "params_hash": _hash_jcs(
                {
                    "model_id": self._model,
                    **{k: v for k, v in self._params.items() if v is not None},
                }
            ),
            "prompt_hash": _hash_jcs(prompt_payload),
            "timestamp": _now_rfc3339_ms(),
        }
        try:
            return await _build_dsse_envelope(canonical_payload, self._signer)
        except Exception as exc:
            raise AdapterError(f"session signing failed: {exc}") from exc

    # ------------------------------------------------------------------- close

    async def close(self) -> None:
        # Idempotent — close swallows double-close errors per AC-1.3 / FR-17.
        tasks = []
        if self._openai is not None:
            tasks.append(self._openai.close())
        if self._anthropic is not None:
            tasks.append(self._anthropic.close())
        if self._http is not None:
            tasks.append(self._http.aclose())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._openai = None
        self._anthropic = None
        self._http = None


def _serialize_tool_calls(tool_calls: object) -> list[dict[str, Any]]:
    """Best-effort serialise provider tool-call objects to plain dicts."""
    out: list[dict[str, Any]] = []
    for tc in tool_calls or []:  # type: ignore[union-attr]
        if hasattr(tc, "model_dump"):
            out.append(tc.model_dump())
        elif isinstance(tc, dict):
            out.append(tc)
        else:
            out.append({"repr": repr(tc)})
    return out


__all__ = [
    "ConfigError",
    "LLMAdapter",
    "PreflightEstimate",
]


# Conformance check: LLMAdapter implements the Adapter Protocol.
_: type[Adapter] = LLMAdapter
