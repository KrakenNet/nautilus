# The Attestation Chain

How Nautilus produces a verifiable, tamper-evident record that a given
response was produced by a given routing decision.

## Per-request: the attestation token

After synthesis, the broker signs an Ed25519 JWS over the routing
decision. The payload binds together:

- `request_id` — the join key to the audit entry,
- the routing outcome (sources queried, denied, scoped),
- `response_hash` — a hash of the response data, **or**
- `hash_skipped: true` when any queried source declares the
  `non_deterministic` capability (LLM sources do). A hash over
  non-reproducible output would be unverifiable theater; the token
  states honestly that re-execution cannot re-verify this response.

The token returns to the caller on `response.attestation_token` and can
be verified offline with nothing but the public key — see
[Verify a token](../how-to/verify-a-token.md).

## Per-deployment: the sink

Independent of what is returned to agents, every signed payload can be
emitted to a sink (`attestation.sink`): a JSONL file, or HTTP POST to an
external collector. With `chained: true` the file sink upgrades to a
hash-chained log — each line carries `prev_sha256` linkage plus its own
EdDSA signature, so deletion, reordering, or edits anywhere in the
history are detectable offline (`nautilus attestation verify`), and
signed checkpoints anchor against tail truncation.

The result is three mutually reinforcing records per request:

| Record | Holder | Proves |
|--------|--------|--------|
| Attestation token | the agent/caller | this response came from this decision |
| Sink entry | the operator (or external collector) | the broker really made this decision |
| Audit entry | the operator | full lifecycle: intent, rule trace, denials, errors, timing |

A caller cannot forge a token (no private key); an operator cannot
quietly rewrite history (chain linkage); and disagreements between the
three records are themselves evidence.

## Session tokens and key rotation

Session tokens (cumulative-exposure tracking, handoff authorization) are
signed by a separate rotating `KeyRing`, published at
`GET /v1/keys/jwks.json`. Rotation keeps a grace window: the old key
verifies but no longer signs, and presented tokens are lazily re-signed
under the new primary *with their original expiry* — rotation can never
extend a session. Revocation ends grace immediately. Every rotation and
revocation is itself an audit event, signed into the same trail it
protects.
