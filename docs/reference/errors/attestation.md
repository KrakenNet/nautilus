# Attestation, keys and the chained log

Signing keys, the JWKS the broker publishes, and the hash-chained audit and attestation logs.
The chained log fails closed: if it cannot prove integrity, the broker stops rather than append
to something it cannot vouch for.

## Key management over HTTP

Both routes need the `keys` capability. `curl` examples assume the
[scratch broker](index.md#a-scratch-broker) on `127.0.0.1:8001` and
`export NAUTILUS=http://127.0.0.1:8001`.

| Message | Status | Line | Meaning |
| --- | --- | --- | --- |
| `reviewer is required (no control characters)` | 400 | `fastapi_app.py:946` | `POST /v1/keys/rotate` needs `reviewer` in the body. Control characters are stripped, so a value made only of them reads as absent. |
| `reviewer and reason are required (no control characters)` | 400 | `fastapi_app.py:992` | `POST /v1/keys/{kid}/revoke` needs both. |
| `kid must be a UUID` | 400 | `fastapi_app.py:985` | The `{kid}` path segment is not a UUID. Take it from `/v1/keys/jwks.json`. |
| `kid {kid!r} not found` | 404 | `fastapi_app.py:1012` | No key with that id in the ring. |

```bash
curl -s -X POST "$NAUTILUS/v1/keys/rotate" \
  -H 'X-API-Key: govern-key' -H 'Content-Type: application/json' -d '{}'
curl -s -X POST "$NAUTILUS/v1/keys/not-a-uuid/revoke" \
  -H 'X-API-Key: govern-key' -H 'Content-Type: application/json' \
  -d '{"reviewer":"ops","reason":"test"}'
```

Rotation and revocation are also refused with **HTTP 409** carrying the underlying `ValueError`
text (`fastapi_app.py:999-1007`) — most often:

### `kid {kid!r} is the current primary; rotate first, then revoke`

`nautilus/core/broker.py:1509`. Revoking the primary would leave nothing to sign with. Call
`POST /v1/keys/rotate` first, then revoke the now-superseded kid.

Both routes answer **503 `Key ring not ready`** (`fastapi_app.py:872`) when
`app.state.key_ring` is unset, and raise
`session tokens are disabled (session_tokens.enabled: false)` when tokens are off — see
[session-tokens.md](session-tokens.md).

## The key ring

### `Key {entry.kid!r} has no private key (revoked)`

**`ValueError`**, `nautilus/attestation/key_ring.py:259-262`. Something asked a revoked key to
sign. Private material is dropped on revocation, deliberately; only verification survives.

### `Expected Ed25519PrivateKey` / `Expected Ed25519PublicKey`

**`TypeError`**, `nautilus/attestation/key_ring.py:264` and `:273`. A PEM file at
`attestation.private_key_path` loaded successfully but is not Ed25519 — an RSA or EC key, or a
public key where a private one was expected. Nautilus signs with Ed25519 only.

### `attestation is disabled`

**`RuntimeError`**, `nautilus/core/broker.py:3140`. An attestation API was called while
`attestation.enabled` is false. Enable it, or stop calling that API.

## Chained log configuration

All raised at startup while building sinks.

### `attestation.sink.chained requires attestation.enabled with a signing key`

**`ValueError`**, `nautilus/core/broker.py:1074-1077`. A chained sink signs every line, so it
needs `attestation.enabled: true`.

### `audit.chained requires attestation.enabled with a signing key: each chained line carries a JWS, and there is nothing to sign with`

**`ValueError`**, `nautilus/core/broker.py:1120-1125`. Same for the audit log.

### `audit.chained cannot append to the existing chain at {audit_path} with an auto-generated signing key: attestation.private_key_path is unset, so this process signs with a key the lines already on disk were not signed by, and every request would fail closed on a log that reads as corrupt. Set attestation.private_key_path to the key that wrote them, or start a new chain at a new audit.path.`

**`ValueError`**, `nautilus/core/broker.py:1127-1135`. The most common chained-log failure on a
second boot: the first run generated an ephemeral key, so the lines on disk cannot be extended.

**Fix.** Set `attestation.private_key_path` to a persistent key — before the first chained boot,
ideally — or point `audit.path` at a new file.

The warning that precedes it by one run (`nautilus/core/broker.py:1137-1141`):

```text
audit.chained is on with an auto-generated attestation key: this chain is signed by this
process only and the next boot will refuse to append to it. Set attestation.private_key_path
to keep it.
```

## Single-writer enforcement

### `{subject} is already open for writing by {holder}. A hash chain admits exactly one writer: a second one interleaves into corruption that verify_chain cannot distinguish from tampering. {remedy}`

**`SinkAlreadyLockedError`** (`nautilus/core/attestation_sink.py:82`), raised at `:101-105`.

**Interpolates.** `{subject}` — the chained file. `{holder}` — the process already holding it.
`{remedy}` — what to do, supplied by the caller.

**Means.** Two brokers were pointed at one chained log. Two interleaved writers produce a chain
that fails verification identically to a tampered one, so the second writer is refused.

**Fix.** Give each replica its own `audit.path` / `attestation.sink.path`, or run one writer.
If the previous process died, remove its stale lock before restarting.

### `emit on closed ChainedFileAttestationSink`

**`ValueError`**, `nautilus/core/attestation_sink.py:244`. A record was emitted after `close()`.
When embedding Nautilus, this means the broker was closed while work was still in flight — see
[library.md](library.md).

## Forensics offsets

`OffsetsCorruptError` (`nautilus/forensics/offsets.py:24`) — the resume file for the handoff
worker did not read back as it was written.

| Message | Line |
| --- | --- |
| `unreadable offsets file {path}: {exc}` | `:75` |
| `offsets payload must be a JSON object, got {type(payload).__name__}` | `:78` |
| `last_byte_offset must be int, got {type(offset_raw).__name__}` | `:85` |
| `last_byte_offset must be non-negative, got {offset_raw}` | `:89` |
| `seen_line_sha256 must be list, got {type(seen_raw).__name__}` | `:93` |
| `seen_line_sha256 entries must be str, got {type(item).__name__}` | `:99` |
| `refusing non-monotonic save: current={self.last_byte_offset} < persisted={existing.last_byte_offset}` | `:120` |

The first six mean the file was hand-edited or truncated: delete it to restart the scan from the
beginning. The last is different — the worker tried to save an offset *behind* the one on disk,
which would re-emit already-processed handoffs. It is refused; the persisted value stands.

## Audit records

### `AuditRecord has no {NAUTILUS_METADATA_KEY!r} metadata`

**`KeyError`**, `nautilus/audit/logger.py:328`. A record was read that carries no Nautilus
metadata block. It came from a different writer, or the log mixes sources. Check that
`audit.path` is not shared with another tool.

## Offline verification

`nautilus attestation verify` checks a chained log without a running broker: link hashes,
per-line JWS signatures, and optionally an out-of-band head hash and checkpoint token.

```bash
nautilus attestation verify --help | head -20
```

Failures are reported by the command's own output rather than as exceptions; `--json` gives a
machine-readable verdict. `--expected-head` fails when the mirrored line hash is absent, which is
how tail truncation is caught — a chain that has had lines removed from the end is internally
consistent and only an external witness can detect it.
