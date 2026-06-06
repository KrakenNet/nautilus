# Add an LLM Source

Treat an OpenAI-compatible chat-completions endpoint (vLLM, llama.cpp,
LM Studio, OpenAI, or any proxy speaking the same dialect) as a brokered
data source. The LLM's responses are **data** — routed, scoped, denied,
and attested like any other source. No LLM reasoning enters the routing
path.

## Declare the source

```yaml
sources:
  - id: local_llm
    type: llm
    description: "Local vLLM inference server"
    classification: unclassified
    data_types: [vulnerability, threat-summary]
    allowed_purposes: [threat-analysis]
    connection: http://127.0.0.1:8000/v1     # OpenAI-compatible base URL
    model: qwen2.5-7b-instruct
    auth:                                     # optional — bearer/basic
      type: bearer
      token: ${LLM_API_KEY}
```

`model` is required. mTLS auth is not supported (the adapter refuses it
rather than silently skipping the credential) — front the endpoint with
a TLS-terminating proxy if you need it.

## What the LLM sees — and doesn't

The prompt is assembled **only** from the router-issued intent analysis
and scope constraints. The request `context` (clearance, session tokens,
embeddings) is excluded by construction — the prompt-assembly function
does not even accept it. Scope constraints are rendered as hard
constraints in the prompt, and every constraint is validated against the
operator/field allowlists *before* any network call.

Each returned row is provenance-marked:

```json
{"content": "...", "provenance": "llm_generated", "model": "qwen2.5-7b-instruct"}
```

so downstream rules and consumers can always distinguish generated
content from records of fact.

## Attestation: `hash_skipped`

LLM output is non-deterministic, so a response hash would be
unverifiable theater. The adapter declares the `non_deterministic`
capability and the broker signs `hash_skipped: true` instead of a
`response_hash` claim — see
[the attestation chain](../concepts/attestation-chain.md).

## Endpoint rules

Unlike the REST adapter (which blocks loopback/private addresses as SSRF
defense), the LLM adapter **allows** loopback and RFC1918 endpoints —
a local inference server is the primary deployment. Link-local/metadata
(`169.254.x.x`), multicast, and unspecified literals stay blocked, and
redirects are never followed.

Under `nautilus serve --air-gapped`, any `type: llm` source whose
`connection` host is not loopback is dropped with a WARN — only local
inference is air-gap compatible.

## Denials apply before any call

If routing denies the LLM source (clearance, purpose, or your own
rules), no HTTP request is made at all — the denial is recorded in
`sources_denied` and the audit entry like any other source.
