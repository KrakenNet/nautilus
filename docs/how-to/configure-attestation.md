# Configure Attestation

Every brokered response can carry a signed attestation token binding the
routing decision to the request. This recipe covers key persistence and
sink configuration. For what's inside a token, see
[the attestation chain](../concepts/attestation-chain.md).

## Persist the signing key

```yaml
attestation:
  enabled: true
  private_key_path: /etc/nautilus/attestation.pem
```

Without `private_key_path` the broker auto-generates an Ed25519 keypair
**per process** — fine for dev, but tokens from a previous run can no
longer be verified against the current public key after a restart.
Generate a key once and protect it like any private key. Nautilus reads a
standard PKCS#8 Ed25519 PEM, so `openssl` is all it takes. Run this **on the
host**, before the broker starts — there is no `openssl`, no `chmod` and no
shell in the container image, and on the container path the key is mounted
read-only from a Secret (`deploy/README.md` §5):

```console
$ openssl genpkey -algorithm ed25519 -out /var/lib/nautilus/attestation.pem && chmod 600 /var/lib/nautilus/attestation.pem
$ ls -l /var/lib/nautilus/attestation.pem | awk '{print $1, $NF}'
-rw------- /var/lib/nautilus/attestation.pem
```

Back it up with the log it signs — see
[Back up and restore](operator-guide.md#9-back-up-and-restore). A chained log
pins this key's fingerprint in its genesis record: with a different key the
broker refuses to append to it at all.

Set `enabled: false` to disable attestation entirely —
`response.attestation_token` is `None` in that case.

## Choose a sink

The sink receives every signed attestation payload, independent of the
response returned to the agent:

```yaml
attestation:
  enabled: true
  private_key_path: /etc/nautilus/attestation.pem
  sink:
    type: file                     # null | file | http
    path: /var/lib/nautilus/attestations.jsonl
    chained: true                  # hash-chained, JWS-signed log
    checkpoint_interval: 100       # signed checkpoint every N emissions
```

- `null` (default) — sign tokens but persist nothing.
- `file` — append one JSONL envelope per request:
  `{"token": "<jws>", "nautilus_payload": {...claims...}, "emitted_at": ...}`.
  With `chained: true`, each line additionally carries `prev_sha256`
  linkage plus an EdDSA signature, so deletion, reordering, or edits are
  detectable offline:

    ```bash
    nautilus attestation verify /var/lib/nautilus/attestations.jsonl \
      --expected-head <mirrored-line-hash>
    ```

    A chained log admits exactly one writer. The first attestation a broker
    emits takes an exclusive lock on `<path>.lock`; a second process writing
    the same path is refused rather than allowed to fork the chain. Read-only
    tooling that builds a broker without emitting anything (`nautilus adapters
    list`, `schema`, `schema-fingerprint`, `schema-diff`) does not take the
    lock and works while a server runs. Nor does `schema-ack`, which emits no
    attestation — but it does write an *audit* line, and `audit.chained: true`
    puts the same single-writer lock on `audit.path`, so beside a running
    server it refuses with exit `2` rather than acknowledging drift it cannot
    record. Stop the server and re-run it, or leave `audit.chained` off, where
    there is no lock.

- `http` — POST each envelope to an external collector, with a retry
  policy and optional `dead_letter_path`.

## Non-deterministic sources

Responses are normally bound by a `response_hash` claim. Sources that
declare the `non_deterministic` capability (the LLM adapter does) cannot
be re-verified by re-execution, so the broker omits the hash and signs
`hash_skipped: true` instead — auditors can distinguish "hash matches"
from "hash was never claimable".

## Verify it works

```bash
curl -s -X POST http://127.0.0.1:8000/v1/request -H "Content-Type: application/json" \
  -d '{"agent_id": "agent-alpha", "intent": "recent CVEs", "context": {"clearance": "unclassified", "purpose": "threat-analysis", "session_id": "s1"}}' \
  | python -c "import json,sys; print(json.load(sys.stdin)['attestation_token'])"
```

Then check the sink file grew by one line, and verify the token against
the public key — see [Verify a token](verify-a-token.md).
