# LLM Adapter

## Description

The first-party LLM adapter routes chat-completion and embedding calls
across **OpenAI**, **Anthropic**, and **vLLM** (OpenAI-compatible
self-hosted) with unified usage normalisation, pre-flight token counts
that feed the cost-cap enforcer, and **adapter-boundary DSSE session
signing**. Signatures are Ed25519 over the JCS-canonical payload
`{model_id, output_hash, params_hash, prompt_hash, timestamp}`; the
private key may live in a 32-byte env-var seed (dev) or in Vault transit
(prod).

> **TODO(verifier-v2)**: producer-only in v1. The downstream verifier
> and JWKS distribution endpoint ship in a follow-up spec. Comments in
> `nautilus/adapters/llm.py` mark every hook point a verifier will
> attach to.

## Use cases

* End-to-end provenance — prove that a specific model produced a
  specific output for a specific prompt at a specific timestamp.
* Cost governance — pre-flight token counts power the broker's hard
  cost-cap enforcement (US-2 / AC-2.5).
* Multi-provider portability — one config shape; switch providers per
  source without rewriting agent code.

## Provider × surface matrix

|           | chat | embeddings |
|-----------|:----:|:----------:|
| openai    | ✅   | ✅         |
| anthropic | ✅   | ❌ (rejected at connect — AC-5.2) |
| vllm      | ✅   | ✅         |

Anthropic does not offer first-party embeddings; the broker rejects
`{anthropic, embeddings}` at `connect()` with `ConfigError`. Streaming
is deferred to v2 (AC-5.6); `stream: true` is rejected at `connect()`.

## Config schema

```yaml
sources:
  - id: llm-prod
    type: llm
    description: Production chat completion through self-hosted vLLM
    classification: internal
    data_types: [llm-output]
    llm_provider: vllm                  # openai | anthropic | vllm
    llm_model: meta-llama/Meta-Llama-3-70B-Instruct
    surface: chat                       # chat | embeddings
    endpoint: ${VLLM_URL}               # required for vllm; optional for openai/anthropic
    token_secret_ref: vault://secret/data/llm#api_key
    session_signing:
      enabled: true
      key_ref: vault-transit://nautilus-session-prod
      algorithm: ed25519
      ttl: 24h                          # Vault transit auto-rotation window
```

## Endpoint / capability coverage matrix

| Capability | Support | Notes |
|---|---|---|
| Chat completion | ✅ | All three providers. |
| Embeddings | ✅ | OpenAI + vLLM only. |
| Tool / function calls | ⚠️ Captured | Tool-call objects are serialised into `rows[0].tool_calls`. v1 does not orchestrate the tool loop. |
| Streaming | ❌ | Rejected at `connect()` with `streaming deferred to v2`. |
| Pre-flight token count | ✅ | `tiktoken` for OpenAI/vLLM; Anthropic `POST /v1/messages/count_tokens`. |
| Usage normalisation | ✅ | `{input_tokens, output_tokens, cached_tokens, total_tokens, tool_call_count, duration_ms}` regardless of provider. |
| Anthropic prompt-cache fields | ✅ | `cache_read_input_tokens` → `cached_tokens`; `cache_creation` rolled into `total_tokens`. |
| DSSE session signing | ✅ | Adapter-boundary; in-process Ed25519 or Vault transit. |
| Verification helper | ❌ (v1) | Producer-only; verifier ships in v2. |

## Query language

Callers supply a free-form `intent.raw_intent` plus an optional
`context["messages"]` override (chat) or `context["inputs"]` list
(embeddings). Per-call parameters (`temperature`, `top_p`, `max_tokens`,
`dimensions`, `encoding_format`) flow through `context` into the
provider request and into `params_hash` — they are NOT defaults on the
source.

## Auth

| Mode | Behavior |
|---|---|
| `token_secret_ref: env://VAR` | env-var literal API key. |
| `token_secret_ref: vault://secret/data/<path>#<field>` | Vault KV resolution at `connect()`. |
| Inline `${VAR}` | Already-interpolated literal. |

API keys are never logged. Secret-provider failures raise typed
`ConfigError` without leaking the path or response body.

## Key Custody

DSSE session signing supports three key-reference schemes; pick based on
your environment.

### Dev / test — `env://NAUTILUS_SIGNING_KEY_HEX`

A 32-byte hex seed is loaded from the env var and turned into an
in-process `Ed25519PrivateKey`. Failures (missing var, wrong length,
non-hex) raise `ConfigError` at `connect()` so the adapter never
becomes ready. Rotate the seed by redeploying with a new var; emit the
old + new public keys side-by-side during a 2×TTL rollover (see below).

```yaml
session_signing:
  enabled: true
  key_ref: env://NAUTILUS_SIGNING_KEY_HEX
  algorithm: ed25519
  ttl: 24h
```

### Prod — `vault-transit://nautilus-session-<env>`

The private key never leaves Vault. The adapter sends the SHA-512
pre-hash of the canonical payload to `POST /v1/transit/sign/<key>` and
decodes the `vault:v1:<base64>` response into a 64-byte Ed25519
signature. The Vault transit engine handles rotation: configure
`auto_rotate_period=24h` so the key rotates daily and old keys remain
verifiable through Vault until `min_decryption_version` advances.

Recommended Vault policy (writeable to `vault policy write nautilus-signer …`):

```hcl
path "transit/sign/nautilus-session-+" {
  capabilities = ["update"]
}

path "transit/keys/nautilus-session-+" {
  capabilities = ["read"]
}
```

The matching key configuration:

```bash
vault write transit/keys/nautilus-session-prod \
  type=ed25519 \
  auto_rotate_period=24h \
  exportable=false \
  allow_plaintext_backup=false
```

Naming convention: `nautilus-session-<env>` (e.g. `nautilus-session-prod`,
`nautilus-session-staging`). One key per environment keeps blast radius
on a key compromise scoped to that environment.

### Verifier grace period (2×TTL)

Verifiers in v2 must accept BOTH the current and the previous public key
during a `2 × ttl = 48h` rollover window so that signatures produced
just before rotation are still verifiable just after rotation. Operators
should publish both keys in the future JWKS endpoint until the grace
period elapses.

## Fail-closed semantics

The adapter **never returns an unsigned response** when
`session_signing.enabled=true`:

* In-process signer raises (corrupt seed, invalid key bytes) →
  `connect()` fails; the adapter never reaches readiness.
* Vault transit returns 5xx or times out → `CircuitBreaker` failure
  counter increments; after 3 consecutive failures the breaker opens for
  60 seconds and subsequent requests fail fast with
  `CircuitOpenError`. The adapter raises `AdapterError`; the broker
  returns HTTP 503 to the caller.
* Vault transit returns HTTP 404 (`key not found`) → fatal config
  error, **not** counted toward the breaker (so a
  misconfiguration cannot eventually open the breaker on the wrong
  metric).
* Signer success but signature is the wrong length → adapter raises
  `RuntimeError`; never returns a wire envelope.

## DSSE envelope structure

The session signature appears on `AdapterResult.signature` and on the
broker response under `source_session_signatures[<source_id>]`:

```json
{
  "payloadType": "application/vnd.nautilus.signed-session+json",
  "payload": "<base64url(JCS_bytes)>",
  "signatures": [
    {
      "keyid": "llm-prod:nautilus-session-prod",
      "sig": "<base64url(64_byte_ed25519_sig)>"
    }
  ]
}
```

The decoded `payload` is the RFC 8785 (JCS) canonical bytes of:

```json
{
  "model_id": "<model>",
  "output_hash": "<sha256_hex>",
  "params_hash": "<sha256_hex>",
  "prompt_hash": "<sha256_hex>",
  "timestamp": "2026-04-27T10:00:00.000Z"
}
```

Verifiers re-encode the canonical bytes and verify the signature against
the published public key — no re-canonicalisation drift, no rebuild
required at verify time (TD-6).

> **TODO(verifier-v2)** — `nautilus.verify_llm_response(envelope, pubkey)`
> ships with the v2 spec.

### Worked verification example (v2 feature)

```python
# v2 — not shipped yet; included here so v1 producers can plan ahead.
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

envelope = response["source_session_signatures"]["llm-prod"]
payload = base64.urlsafe_b64decode(envelope["payload"] + "==")
sig = base64.urlsafe_b64decode(envelope["signatures"][0]["sig"] + "==")
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUBKEY_HEX))
pub.verify(sig, payload)
```

## Output-hash policy (TD-15)

* **chat** — SHA-256 of the JCS-canonical bytes of the response
  `content` string.
* **embeddings** — SHA-256 of the **big-endian IEEE-754 float32** raw
  bytes of the embedding vector. The adapter re-packs vectors regardless
  of how the provider returned them (OpenAI's JSON-array, base64, etc.)
  so the hash is provider-independent.

## Error mapping

| Provider response | Adapter outcome |
|---|---|
| 2xx with content | `rows` populated; signed if enabled |
| 401 / 403 | `error_type="<provider error class>"`, e.g. `AuthenticationError` |
| 429 (rate limit) | `error_type="RateLimitError"` |
| 5xx | propagated as `error_type="APIError"` |
| Anthropic embeddings request | `ConfigError` at `connect()` |
| `stream: true` | `ConfigError` at `connect()` |
| Signer unreachable | `AdapterError` → broker HTTP 503 |
| Circuit open | `AdapterError` → broker HTTP 503; provider not called |

## Example YAML

```yaml
sources:
  - id: openai-chat
    type: llm
    description: OpenAI gpt-4o-mini chat with in-process signing
    classification: internal
    data_types: [llm-output]
    llm_provider: openai
    llm_model: gpt-4o-mini
    surface: chat
    token_secret_ref: env://OPENAI_API_KEY
    session_signing:
      enabled: true
      key_ref: env://NAUTILUS_SIGNING_KEY_HEX

  - id: anthropic-chat
    type: llm
    description: Anthropic claude-3-5 chat through Vault transit signing
    classification: internal
    data_types: [llm-output]
    llm_provider: anthropic
    llm_model: claude-3-5-sonnet-20241022
    surface: chat
    token_secret_ref: vault://secret/data/llm#anthropic_key
    session_signing:
      enabled: true
      key_ref: vault-transit://nautilus-session-prod
      ttl: 24h

  - id: vllm-embeddings
    type: llm
    description: Self-hosted vLLM bge-base embeddings, unsigned (lab use)
    classification: internal
    data_types: [embeddings]
    llm_provider: vllm
    llm_model: BAAI/bge-base-en-v1.5
    surface: embeddings
    endpoint: http://vllm.internal:8080
```

## Testing

* Unit: `tests/unit/adapters/test_llm_dispatch.py`,
  `tests/unit/adapters/test_llm_estimate_cost.py`,
  `tests/unit/adapters/test_llm_signing.py`,
  `tests/unit/core/test_signer.py` (including the RFC 8032 test vector 1
  KAT and the DSSE golden envelope).
* Integration: `tests/integration/test_llm_adapter_chat.py`,
  `tests/integration/test_llm_adapter_embeddings.py`,
  `tests/integration/test_llm_session_signing.py` — three providers via
  respx mocks against the canonical chat / embedding payloads.
* Benchmark: `benchmarks/bench_session_signing.py` confirms NFR-PERF-SIGN
  (`< 10ms p95` for in-process, `< 50ms p95` for Vault transit).

## Out of scope (v1)

* Streaming responses + streaming-usage aggregation.
* Voyage AI provider for Anthropic embeddings.
* Gemini / Bedrock providers (no LiteLLM abstraction layer in v1).
* Adapter-level prompt templates — callers supply prompts per request.
* Verifier `nautilus.verify_llm_response()` helper — v2 feature.
