# Verify a Token

Nautilus issues two kinds of EdDSA (Ed25519) JWS tokens. Both verify
offline with nothing but the public key.

## Attestation tokens

`response.attestation_token` is signed by the broker's attestation key
(`attestation.private_key_path`, or per-process if unset). Verify with
the corresponding public key:

```python
import base64, json
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

header_b64, payload_b64, sig_b64 = token.split(".")
public_key = load_pem_public_key(open("attestation.pub.pem", "rb").read())
public_key.verify(b64url(sig_b64), f"{header_b64}.{payload_b64}".encode())  # raises on tamper
claims = json.loads(b64url(payload_b64))
```

Claims worth checking:

- `request_id` — joins the token to its audit entry
  (`GET /v1/audit/{request_id}`).
- `response_hash` — hash of the response data; recompute to prove the
  data you hold is the data that was attested.
- `hash_skipped: true` — present instead of `response_hash` when a
  non-deterministic source (e.g. an LLM) was queried; such responses
  cannot be re-verified by re-execution, and the token says so honestly.

## Session tokens

Session tokens are signed by the broker's rotating `KeyRing`. The JWS
header carries a `kid`; resolve it against the live JWKS endpoint:

```bash
curl -s http://127.0.0.1:8000/v1/keys/jwks.json
```

```python
import base64, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

header = json.loads(b64url(token.split(".")[0]))
jwk = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
public_key = Ed25519PublicKey.from_public_bytes(b64url(jwk["x"]))
public_key.verify(b64url(sig_b64), f"{header_b64}.{payload_b64}".encode())
```

A `kid` absent from the JWKS means the key was revoked (or never
existed) — treat the token as invalid. During a rotation grace window
the old `kid` remains published until explicitly revoked, and the broker
lazily re-signs presented tokens under the new primary.

## Chained attestation logs

To verify an entire `chained: true` sink log (chain integrity + every
line's signature) rather than a single token:

```bash
nautilus attestation verify attestations.jsonl --pubkey attestation.pub.pem
```

`--expected-head` guards against tail truncation with an out-of-band
mirrored line hash; `--anchor-token` checks a signed checkpoint appears
in the log. See [Configure attestation](configure-attestation.md).
