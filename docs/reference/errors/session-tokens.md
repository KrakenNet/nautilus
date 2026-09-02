# Session tokens

A session token is a signed JWT that pins one session to one agent on one broker instance.
Verification failures raise `SessionTokenError` (`nautilus/attestation/session_token.py:26-35`),
which carries a machine-readable `reason_code` **and** a human message. The transport shows you
the code; the message is what the library shows.

`curl` examples assume the [scratch broker](index.md#a-scratch-broker) on
`127.0.0.1:8001` and `export NAUTILUS=http://127.0.0.1:8001`.

## Reading `Invalid session token: …`

Two wrappers exist, and which one you see tells you where the token was carried.

### `Invalid session token: {exc.reason_code}`

**HTTP 401.** `nautilus/transport/auth.py:388-391` and `:401-404`, from the
`verify_session_token` dependency. The token was in the **`X-Nautilus-Session-Token` header**.
Only the code is shown. Rendered example:

```text
Invalid session token: bad_signature
```

### `Invalid session token ({exc.reason_code}): {exc}`

**HTTP 401**, with `WWW-Authenticate: Bearer`. `nautilus/transport/fastapi_app.py:723-727`. The
token was in the **request body**, at `context.session_token`. Both the code and the message are
shown. Rendered example:

```text
Invalid session token (expired): Token has expired
```

```bash
curl -s -X POST "$NAUTILUS/v1/request" \
  -H 'X-API-Key: query-key' -H 'X-Nautilus-Session-Token: garbage' \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"analyst","intent":"list notes"}'
```

## The reason codes

`missing`, `bad_signature`, `unknown_kid`, `expired`, `broker_instance_mismatch` and
`agent_mismatch`. Each is paired below with every message that carries it.

### `missing`

#### `No token provided`

`nautilus/attestation/session_token.py:116`. `SessionTokenService.verify` was called with an
empty string. Over HTTP this is unreachable — an absent header is not an error — so seeing it
means library code passed `""`.

#### `session_token must be a string`

`nautilus/core/broker.py:3413-3414`. `context["session_token"]` was present but not a `str`
(commonly `None`, or a dict left over from a JSON round-trip). Send the compact JWT string.

### `bad_signature`

#### `Cannot decode token header`

`nautilus/attestation/session_token.py:120-123`. The value is not a JWT at all: its header
segment is not base64url-encoded JSON. Usually a truncated copy-paste, a `Bearer ` prefix left
in the value, or the session *id* sent where the token belongs.

#### `Invalid signature`

`nautilus/attestation/session_token.py:145-148`. Structure and `kid` are fine; the Ed25519
signature does not verify. The token was minted by a different key ring, or the payload was
edited after signing.

#### `Token decode failed`

`nautilus/attestation/session_token.py:149`. `PyJWT` rejected the token for a reason other than
the signature — malformed claims, bad segment count, unsupported `alg`.

### `unknown_kid`

#### `Token header missing kid`

`nautilus/attestation/session_token.py:124-127`. The JWT has no `kid` header, so no key can be
selected. Nautilus always sets one when minting; a token without it came from elsewhere.

#### `Unknown kid: {kid!r}`

`nautilus/attestation/session_token.py:128-131`. The `kid` names a key this broker's `KeyRing`
does not hold. Rendered example:

```text
Unknown kid: '9f2c1a5e-...'
```

Happens after `POST /v1/keys/rotate` on a *different* broker, or when replicas were given
separate key material. Check the live set at `/v1/keys/jwks.json`.

#### `Key {kid!r} has been revoked`

`nautilus/attestation/session_token.py:132-136`. The key is present but marked revoked by
`POST /v1/keys/{kid}/revoke`. Revocation is retroactive by design: tokens already minted under
that key stop verifying. Mint a new token.

```bash
curl -s "$NAUTILUS/v1/keys/jwks.json" | head -c 200; echo
```

### `expired`

#### `Token has expired`

`nautilus/attestation/session_token.py:151-155`. `exp` is in the past. Lifetime comes from
`session_tokens.ttl_seconds`. If tokens expire far sooner than the TTL suggests, check clock
skew between the minting and verifying hosts — `exp` is absolute.

### `broker_instance_mismatch`

#### `Token issued for {broker_instance_id!r}, not {self._broker_instance_id!r}`

`nautilus/attestation/session_token.py:156-161`. Rendered example:

```text
Token issued for 'broker-A', not 'broker-B'
```

The token names a different broker instance. Two brokers behind one load balancer, each with its
own instance id, produce this on roughly half of all requests. Either route a session to the
instance that minted its token, or give the replicas a shared identity and key ring.

```bash
python - <<'PY'
from nautilus.attestation.key_ring import KeyRing
from nautilus.attestation.session_token import SessionTokenError, SessionTokenService
ring = KeyRing()
token = SessionTokenService(key_ring=ring, broker_instance_id="broker-A").issue(
    session_id="s1", agent_id="analyst", purpose="research", clearance="unclassified"
)
try:
    SessionTokenService(key_ring=ring, broker_instance_id="broker-B").verify(token)
except SessionTokenError as exc:
    print(exc.reason_code, "|", exc)
PY
```

### `agent_mismatch`

#### `session token was minted for agent {claims.agent_id!r}, presented by {agent_id!r}`

`nautilus/core/broker.py:3421-3426`. The token is valid, but the request's `agent_id` is not the
one it was minted for. This is the property the token exists to enforce: presenting another
agent's token would inherit that session's cumulative-exposure ledger.

**Fix.** Call with the `agent_id` in the token, or mint a token for the caller. To move work
between agents, declare a handoff instead — see `Broker.declare_handoff` and the
`session_not_yours` entry in [sessions.md](sessions.md).

## Adjacent failures

### `session tokens are disabled (session_tokens.enabled: false)`

**`RuntimeError`** from `Broker.issue_session_token`, `.verify_session_token`, `.rotate_signing_key` and
`.revoke_signing_key` (`nautilus/core/broker.py:1730`, `:1768`, `:1809`, `:1843`).

**Fix.** Set `session_tokens.enabled: true`. Note the key-management routes fail the same way,
so `/v1/keys/rotate` on a broker with tokens off surfaces this text.

### `purpose {purpose!r} is not one of the purposes agent {agent_id!r} may claim ({sorted(record.allowed_purposes)})`

**`PurposeNotPermittedError`** (`nautilus/core/__init__.py:23`), raised while minting at
`nautilus/core/broker.py:1736-1739`. The requested `purpose` is not in that agent's
`allowed_purposes`. Add it to the agent's registry entry, or mint with a purpose it holds.

### `Unknown agent id='{agent_id}'`

**`UnknownAgentError`** (`nautilus/config/agent_registry.py:19,43`). The `agent_id` has no entry
under `agents:` in the config. Add one, or correct the id.

### Denial reasons that name a token

These appear inside `BrokerResponse.denial_records` rather than as an exception:

- `handoff requires the originating agent's session token` — `nautilus/core/broker.py:2314-2318`.
- `session token rejected: {exc.reason_code}` — `nautilus/core/broker.py:2337-2341`, using the same
  reason codes listed above.
