# Hardening Nautilus

`nautilus init` writes a config that runs. It does not write a config that is
safe to expose. This guide turns the first into the second: every control the
broker actually has, what each one defends against, the command that turns it
on, and what it costs you.

Read [Security Policy](https://github.com/KrakenNet/nautilus/blob/main/SECURITY.md)
for how to report a vulnerability. This page is about configuration.

## What Nautilus is trusted with

The broker is the only process that holds source credentials. An agent sends an
intent and gets rows; it never sees a DSN
(see [The Trust Boundary](../concepts/trust-boundary.md)). Three things follow,
and they set the whole priority order below:

1. **The API key is a data-exfiltration credential.** It is not a rate-limit
   token. Whoever holds one queries every source the agent it maps to may reach.
2. **The signing keys are the audit trail.** `attestation.private_key_path` signs
   decisions; the `session_tokens` key ring signs session provenance. Either one
   leaking makes the receipts forgeable.
3. **The audit log is evidence.** `audit.path` accumulates every intent, every
   decision and every denial, in plaintext JSONL, on a volume you choose.

## Read this first: Nautilus does not terminate TLS

`nautilus serve` builds its uvicorn server with host, port and log level only —
there is no `--tls-cert`, no `--ssl-keyfile`, no `api.tls` config key. Run it as
shipped and **every `X-API-Key` header crosses the network in cleartext**. The
Kubernetes manifests under `deploy/` are plaintext HTTP too: `service.yaml`
exposes `port: 8000` named `http`, and nothing in `deploy/` mentions TLS.

You have two supported ways to get TLS, both in [§3](#3-terminate-tls). Neither
is "turn on a flag", because there is no flag.

## 1. Generate credentials

Do not reuse the key `nautilus init` printed to your terminal. It was written
with `secrets.token_hex(16)` (128 bits, fine) but it has been in your shell
history, your scrollback and the file since the first minute.

### 1.1 API keys

```bash
# 256-bit API key. Repeat once per calling agent — one key per caller is what
# makes revocation possible without an outage for everyone else.
openssl rand -hex 32
```

Never pass a key as a command-line argument on a shared host: `nautilus key
rotate --api-key ...` puts it in `ps` output and in `~/.bash_history`. Read it
from the environment instead:

```bash
read -rs NAUTILUS_API_KEY && export NAUTILUS_API_KEY
nautilus key list --url https://nautilus.internal --api-key "$NAUTILUS_API_KEY"
```

### 1.2 The attestation signing key

Unset, `attestation.private_key_path` makes the broker mint a fresh Ed25519
keypair on every start. Every attestation signed before the restart then
verifies against a public key nobody has. Generate one and keep it:

```bash
openssl genpkey -algorithm ed25519 -out attestation.pem
chmod 600 attestation.pem
```

The broker reads that file with `AttestationService.from_private_key_bytes`,
which is `load_pem_private_key(..., password=None)` — an **unencrypted PKCS#8
PEM**. There is no passphrase option. The file's permissions and the volume it
sits on are the whole control.

> `deploy/secret.yaml` tells you to generate this with `nautilus key generate
> --out attestation.pem`. That subcommand does not exist — `nautilus key` has
> `list`, `rotate` and `revoke` only. Use the `openssl` line above.

### 1.3 The session-token key ring

`session_tokens.enabled: true` makes the broker mint an EdDSA JWS per session.
The ring lives in memory unless you set `session_tokens.key_ring_path`, and an
in-memory ring is wrong for any deployment with more than one replica: replicas
that do not share key material reject each other's tokens with `unknown_kid`,
which behind a load balancer is roughly every second request.

<!-- not-executed: fragment of nautilus.yaml; §7 has the complete file -->
```yaml
session_tokens:
  enabled: true
  ttl_seconds: 900
  key_ring_path: /var/lib/nautilus/keyring.json
  broker_instance_id: nautilus-prod
```

`KeyRing` writes that file with `os.open(..., 0o600)` and an `fcntl` lock, so
the ring itself is created correctly; the **directory** is yours to protect.
`broker_instance_id` must be identical across the replicas of one deployment and
different between deployments — it is what stops a token minted by staging from
verifying against production when both mount the same ring.

**Cost:** `session_tokens.enabled: true` changes the audit JSONL — new
`session_token_issued` and `session_token_verification_failed` events appear. If
you have byte-comparison tooling over `audit.path`, it will notice.

### 1.4 Keep every secret out of the YAML

The config loader interpolates `${VAR}` from the process environment in any
string field, and raises `ConfigError: Missing env var 'X' referenced by source
id='...'` when one is absent — so a missing secret is a startup failure, not a
silent anonymous connection.

<!-- not-executed: fragment of nautilus.yaml; §7 has the complete file -->
```yaml
sources:
  - id: orders
    type: postgres
    connection: ${ORDERS_DSN}
api:
  keys:
    - key: ${NAUTILUS_API_KEY}
      agent_id: support-bot
      capabilities: [query]
```

Config-validation errors are rendered by `_redacted_errors`, which prints the
field location and the message but never pydantic's `input_value=` — so a
malformed `auth:` block does not paste your resolved password into the ticket.

Environment variables the broker reads directly, all of which carry secrets or
change trust:

| Variable | Read by | Notes |
| --- | --- | --- |
| `NAUTILUS_REVIEWER` | `nautilus key rotate`/`revoke`, `nautilus rkm`, `nautilus rule` | Reviewer identity written into audit events. Required; the CLI exits 1 without it. |
| `${...}` names in `nautilus.yaml` | `EnvInterpolator` | Where DSNs and API keys belong. |
| `api_key_env` target (e.g. `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) | `analysis.provider` | Named indirectly: the config holds the variable *name*, the environment holds the key. |
| `INFLUXDB_V2_TOKEN`, `INFLUXDB_V2_ORG` | InfluxDB adapter | Fallback when the source declares no token. |
| `TEST_PG_DSN` | `session_store` when `dsn` is unset | A test-fixture fallback. Do not set it in production: it silently supplies a session store the config never declared. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `nautilus.observability` | Spans are exported only when this is set. Traces carry request metadata; point it somewhere you trust. |
| `OTEL_SDK_DISABLED=true` | `nautilus.observability` | Skips OTel setup entirely — and takes the `nautilus_*` Prometheus series with it. |

## 2. Bind and scope the credential

### 2.1 A bare-string key is root

`api.keys` accepts two forms, and the difference is the single largest
authorization decision in the product:

<!-- not-executed: fragment of nautilus.yaml; §7 has the complete file -->
```yaml
api:
  keys:
    # ROOT. Bound to no agent, holds every capability. This is what
    # `nautilus init` writes and what every short example uses.
    - 4f3c2b1a9e8d7c6b5a4938271605f4e3

    # Scoped. Speaks only as `support-bot`, may only run queries.
    - key: ${SUPPORT_BOT_KEY}
      agent_id: support-bot
      capabilities: [query]
```

A bare string resolves to `ALL_CAPABILITIES` and to `agent_id: None`, which means
*the caller names its own agent in the request body* and the registry hands that
name its clearance. A holder of a bare key can therefore ask as your
highest-clearance agent, read the audit log, rotate the signing key and approve
its own rule proposals. The broker logs this at startup:

```text
api.keys[0] is a bare string: bound to no agent_id, so it can ask as any agent
and call every governance route. Use the {key, agent_id, capabilities} form to scope it.
```

### 2.2 The four capabilities

`CAPABILITIES = ("query", "audit_read", "govern", "keys")`. Omit
`capabilities:` on a structured entry and you get `["query"]`.

| Capability | Unlocks | Give it to |
| --- | --- | --- |
| `query` | `POST /v1/request`, `POST /v1/query`, `GET /v1/sources`, `POST /v1/sessions`, the MCP `nautilus_request` / `nautilus_sources` tools, `/admin/playground` | Every calling agent. |
| `audit_read` | `GET /v1/audit`, `GET /v1/audit/{request_id}`, `/admin/decisions`, `/admin/audit`, `/admin/attestation` | Your compliance reader, nothing else. |
| `govern` | `POST /v1/rkm/queue`, the approve/reject routes, `POST /v1/rules/{rule_name}/retract`, `POST /v1/rules/{rule_name}/rollback` | A human operator's key. Never an agent's. |
| `keys` | `POST /v1/keys/rotate`, `POST /v1/keys/{kid}/revoke` | A break-glass key, stored separately. |

The check is `capability_refusal`, called from one shared `caller_identity`
across REST, MCP and the admin console — so a credential refused on `/v1/audit`
cannot get the same data by switching to the MCP port. That was not always true;
it is the reason the resolution is shared rather than per-transport.

**Cost:** scoping is opt-in and one-way. The moment you replace a bare key with
a structured one, any request whose body names a different `agent_id` starts
returning 403 instead of running. Roll one caller at a time.

### 2.3 What does *not* authenticate anybody

- **`agent_id` in the request body.** Under a bare key it is taken verbatim.
  Binding a key with `agent_id:` is the only thing that constrains it.
- **`X-Nautilus-Reviewer` / `X-Reviewer`.** These name a reviewer for the audit
  record on governance routes. They are not credentials; the route is gated by
  `govern` on top of them.
- **`X-Forwarded-User`,** unless you are in `proxy_trust` mode *and* the socket
  peer is inside `api.auth.trusted_proxies`. In `api_key` mode the header is
  ignored entirely.

## 3. Terminate TLS

### 3.1 Option A — run uvicorn yourself, with certificates

`nautilus serve` calls `uvicorn.Config(app, host=..., port=..., log_level=...)`
and exposes none of uvicorn's TLS parameters. `create_app` is a plain factory,
so point uvicorn at it directly and you get every uvicorn flag back, TLS
included. Two files:

```bash
# 1. A certificate. Use your CA in production; this is the local-test shape.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /etc/nautilus/tls.key -out /etc/nautilus/tls.crt \
  -subj "/CN=nautilus.internal" -addext "subjectAltName=DNS:nautilus.internal"
chmod 600 /etc/nautilus/tls.key
```

```bash
# 2. An app module uvicorn can import.
cat > /etc/nautilus/serve_tls.py <<'PY'
from nautilus.transport.fastapi_app import create_app

app = create_app("/etc/nautilus/nautilus.yaml")
PY
```

```bash
# 3. Start it. --ssl-keyfile / --ssl-certfile are uvicorn's, not Nautilus's.
PYTHONPATH=/etc/nautilus uvicorn serve_tls:app \
  --host 0.0.0.0 --port 8443 \
  --ssl-keyfile /etc/nautilus/tls.key \
  --ssl-certfile /etc/nautilus/tls.crt \
  --ssl-ca-certs /etc/nautilus/clients-ca.crt \
  --ssl-cert-reqs 2          # 2 = ssl.CERT_REQUIRED — demand a client cert
```

Drop the last two lines if you are not doing client-certificate auth; keep them
and Nautilus will only ever see connections your CA signed, which is the
strongest transport-level gate available here.

Verify from a second shell:

```bash
curl --cacert /etc/nautilus/tls.crt \
     --cert client.crt --key client.key \
     -H "X-API-Key: $NAUTILUS_API_KEY" \
     https://nautilus.internal:8443/v1/sources
```

**Cost:** you lose `nautilus serve`'s `--transport`, `--mcp-mode`,
`--air-gapped` and `--log-format` flags — this path runs the REST app only.
`--air-gapped` is recoverable in config (`analysis.mode: pattern`, no
`analysis.provider`); MCP is not, so a deployment that needs both transports
takes Option B.

### 3.2 Option B — terminate in front, and tell Nautilus who did it

The alternative is an ingress or sidecar that terminates TLS and forwards the
authenticated identity. This is the mode the product is designed around, and it
is the only one that gives you mTLS/SPIFFE/OIDC identities rather than shared
secrets. Two halves — get either one wrong and it is worse than no auth at all.

**Half one: Nautilus must not be reachable except through the proxy.**
`api.host` defaults to `127.0.0.1`; leave it there when the proxy is on the same
host. `deploy/configmap.yaml` sets `host: 0.0.0.0`, which is correct for a pod
whose `Service` is `ClusterIP` and wrong the moment anything else can route to
the pod IP — pair it with a `NetworkPolicy` that admits only the ingress.

**Half two: `X-Forwarded-User` is the credential, so nobody but the proxy may
set it.** That is what `api.auth.trusted_proxies` is; the config refuses to
start `proxy_trust` without it.

<!-- not-executed: fragment of nautilus.yaml; §7 has the complete file -->
```yaml
api:
  host: 127.0.0.1
  port: 8000
  auth:
    mode: proxy_trust
    trusted_proxies: ["10.4.0.0/16"]

agents:
  support-bot:
    id: support-bot
    clearance: confidential
    allowed_purposes: [support]
    # The string the proxy forwards. SPIFFE id, OIDC sub, certificate CN.
    subject: spiffe://prod/ns/agents/sa/support-bot
```

The matching nginx front end — note that it *strips* any client-supplied
`X-Forwarded-User` before setting its own, and that `/metrics` and `/admin` are
refused outright (see [§4](#4-keep-the-private-surface-off-the-public-listener)):

```nginx
server {
    listen 443 ssl;
    server_name nautilus.internal;

    ssl_certificate     /etc/nginx/tls.crt;
    ssl_certificate_key /etc/nginx/tls.key;
    ssl_protocols       TLSv1.3;

    ssl_client_certificate /etc/nginx/clients-ca.crt;
    ssl_verify_client      on;

    location /metrics { deny all; }
    location /admin   { deny all; }

    location / {
        proxy_set_header X-Forwarded-User $ssl_client_s_dn_cn;
        proxy_pass http://127.0.0.1:8000;
    }
}
```

An unmapped subject is *not* refused — `caller_identity` leaves it unbound, and
an unbound caller names its own agent and holds every capability, exactly like a
bare key. Declare `subject:` on every agent that will call, and treat a missing
mapping as a misconfiguration to alert on.

**Cost:** `trusted_proxies` is an IP check on `request.client.host`. If anything
between the proxy and Nautilus rewrites the source address — a second hop, a
NAT, a service mesh in a mode you did not choose — the check compares the wrong
address and your identity boundary is gone. Verify it by sending a forged
`X-Forwarded-User` from a host outside the CIDR and confirming the 401 in
[§9](#9-when-a-control-rejects-a-request).

### 3.3 TLS on the way *out*, to your sources

Inbound TLS says nothing about the connections the broker makes to your data.
Per source, `sources[].auth` takes a discriminated union — `bearer`, `basic`,
`mtls`, `none`:

<!-- not-executed: fragment of nautilus.yaml; §7 has the complete file -->
```yaml
sources:
  - id: cases
    type: elasticsearch
    auth:
      type: mtls
      cert_path: /etc/nautilus/client.crt
      key_path: /etc/nautilus/client.key
      ca_path: /etc/nautilus/source-ca.crt
```

`mtls` builds `ssl.create_default_context(cafile=ca_path)` and calls
`load_cert_chain`; a cert or key that cannot be loaded raises `AdapterError`
naming both paths, rather than connecting anonymously. For `postgres` and
`pgvector`, TLS is part of the DSN — put `?sslmode=verify-full` in the
`${ORDERS_DSN}` value, not in `nautilus.yaml`.

## 4. Keep the private surface off the public listener

The listener serves one port. What is on it:

| Route | Auth as shipped | Exposure |
| --- | --- | --- |
| `GET /healthz` | **none, by design** | Safe. Returns `{"status":"ok"}` and touches no broker state. |
| `GET /readyz` | **none, by design** | Safe. Probes the session store; leaks only up/down. Never gate it — probes must work during unauthenticated rolling restarts. |
| `GET /metrics` | **none** | **Must not be public.** See below. |
| `GET /v1/keys/jwks.json` | none, by design | Safe — public keys, and token verifiers need them. |
| `GET /` | none | 302 redirect to `/admin`. |
| `/admin/**` | cookie `nautilus_key` + capability | **Must not be public.** Off unless `ui.enabled: true`. |
| `POST /v1/request`, `/v1/query`, `GET /v1/sources`, `POST /v1/sessions`, `GET /v1/adapters/{name}/schema` | key + `query` | Your actual API. |
| `GET /v1/audit`, `GET /v1/audit/{request_id}` | key + `audit_read` | Every intent and decision ever made. |
| `POST /v1/rkm/queue`, `.../approve`, `.../reject`, `POST /v1/rules/{rule_name}/retract`, `.../rollback` | key + `govern` | Changes what the broker will allow. |
| `POST /v1/keys/rotate`, `POST /v1/keys/{kid}/revoke` | key + `keys` | Changes what the broker's signatures mean. |

### 4.1 `/metrics` is unauthenticated

`GET /metrics` carries no auth dependency and is in `_UNGATED_PATHS`, so it also
bypasses the concurrency limit. Anyone who can reach the port can scrape
`nautilus_ruleset_info` (which names the exact ruleset hash the replica loaded),
`nautilus_rkm_queue_depth`, `nautilus_rkm_queue_oldest_age_seconds` and every
`python_*` process metric. Three ways to keep it internal, in order of
preference:

1. **Deny it at the proxy** — the `location /metrics { deny all; }` block in
   §3.2, with Prometheus scraping `127.0.0.1:8000/metrics` behind it.
2. **Keep the listener on loopback** (`api.host: 127.0.0.1`) and scrape over the
   node-local interface.
3. **In Kubernetes**, a `NetworkPolicy` admitting port 8000 only from the
   ingress and the monitoring namespace. `deploy/` ships no `NetworkPolicy`; you
   write it.

There is no config key that gates `/metrics`. Do not look for one.

### 4.2 The admin console is a second front door

`ui.enabled` defaults to `false`, and when it is off the routes are never
registered — `/admin/login` is a 404, not a login prompt. Turn it on only if an
operator will use it, because:

- `POST /admin/login` sets the `nautilus_key` cookie to **the API key itself**,
  with `httponly=True`, `samesite="lax"`, `max_age=86400` — and **no `secure`
  flag**. Over plaintext HTTP that cookie is an API key on the wire in every
  request. Serving `/admin` without TLS ([§3](#3-terminate-tls)) is not a
  hardening gap, it is credential disclosure.
- `caller_identity` reads `X-API-Key` *or* the `nautilus_key` cookie, so the
  console gets exactly the capabilities of the key that logged in — a bare key
  in the login box is a root browser session for 24 hours.
- `/admin/playground` runs real queries against real sources.

### 4.3 MCP

`nautilus serve --transport mcp --mcp-mode stdio` has no network listener and no
auth: the pipe is the boundary. `--mcp-mode http` is wrapped by
`wrap_http_with_api_key`, which runs the same `verify_api_key` and fails closed
with `{"detail":"Invalid API key"}` when `api.keys` is empty. Under
`--transport both` the MCP server binds `port + 1` — so `--bind 0.0.0.0:8000`
also opens **8001**. Both ports need the same treatment.

`mcp.expose_declare_handoff` defaults to `false`; leave it off unless you use
the `nautilus_declare_handoff` tool.

## 5. Rotate and revoke

### 5.1 The signing key

Rotation is a broker operation, not a file operation — the running broker holds
its ring in memory, so editing `keyring.json` would leave it signing with a key
it no longer has and emit no audit event. `nautilus key` requires `--url` for
exactly this reason.

```bash
export NAUTILUS_REVIEWER="alice@example.com"   # written into the audit event
nautilus key rotate --yes \
  --url https://nautilus.internal --api-key "$NAUTILUS_BREAKGLASS_KEY"
```

The old primary moves to `rotating-out`: in-flight session tokens keep verifying
and are lazily re-signed on their next request, and the old public key stays in
`GET /v1/keys/jwks.json` so external verifiers do not break mid-flight. The
server emits `signing_key_rotated`. Close the window when your longest
`session_tokens.ttl_seconds` has elapsed:

```bash
nautilus key list --url https://nautilus.internal --api-key "$NAUTILUS_BREAKGLASS_KEY"
nautilus key revoke <kid-from-the-list> --yes \
  --reason "scheduled 90-day rotation" \
  --url https://nautilus.internal --api-key "$NAUTILUS_BREAKGLASS_KEY"
```

Revoking drops the private key but keeps the public key in the JWKS exposure
window, and emits `signing_key_revoked`. The current primary cannot be revoked —
rotate first, or you get a 409.

**Cost:** revoking before the grace window closes invalidates every session
token signed by that `kid`; callers see
`{"detail":"Invalid session token: unknown_kid"}` and must start a new session.

### 5.2 The API keys

There is no rotate command for `api.keys` — it is a config list. Roll it in
three steps, no downtime:

```bash
NEW=$(openssl rand -hex 32)          # 1. add the new key alongside the old
# edit nautilus.yaml / the Secret so api.keys holds BOTH entries, then restart
# 2. move callers to $NEW
# 3. remove the old entry and restart again
```

Two restarts is the price of not having a live key registry. In Kubernetes,
`deploy/deployment.yaml` reads the key via `envFrom` on the Secret, so both
steps are `kubectl rollout restart`.

### 5.3 The attestation key

`attestation.private_key_path` is read once at startup and has no rotation
endpoint. Changing it changes the public key every future attestation verifies
against; attestations already written stay verifiable only against the old
public key, so archive it before you swap. If `audit.chained: true`, the broker
**refuses to start** against an existing chain with a rotated or auto-generated
key rather than appending lines the chain cannot verify.

## 6. Audit, logs and the evidence path

<!-- not-executed: fragment of nautilus.yaml; §7 has the complete file -->
```yaml
audit:
  path: /var/log/nautilus/audit.jsonl
  chained: true
  checkpoint_interval: 1000
```

- `chained: true` hash-chains every line and signs it, so a deleted or edited
  entry is detectable offline. It requires `attestation.enabled: true` **and**
  `attestation.private_key_path` set, and — like every chain — a single writer.
  **Cost: it is incompatible with multiple replicas writing one file.** Give each
  replica its own `audit.path`, or leave `chained: false` and rely on your log
  pipeline's integrity.
- Verify a chain offline, on a host that never held the private key. Export the
  public half of `attestation.private_key_path` once and ship only that:

  ```bash
  openssl pkey -in attestation.pem -pubout -out audit.jsonl.pub.pem
  # --pubkey defaults to <log>.pub.pem beside the log, so the name above is
  # what makes the next line work with no flag.
  nautilus attestation verify /var/log/nautilus/audit.jsonl \
    --pubkey /var/log/nautilus/audit.jsonl.pub.pem \
    --expected-head "$MIRRORED_HEAD_HASH"
  ```

  `--expected-head` is the part that catches tail truncation: without an
  out-of-band copy of the last line hash, a chain with its final entries
  deleted still verifies as internally consistent.

- The audit volume is a **fail-closed dependency**: `/readyz` returns 503 when
  the audit sink complains, so a full disk drains every replica rather than
  degrading one. Alert on free space there, not just on the database.
- `nautilus serve --log-format json` emits structured lines on stdout for SIEM
  ingestion. Use it in production; `text` is the local-dev default.
- Application logs never contain a rejected config value
  (`_redacted_errors`), but the audit entries *do* contain the caller's intent
  text verbatim. If intents can carry regulated data, the audit volume inherits
  that classification.

## 7. A hardened configuration, end to end

Everything above, in one file. Trade-offs are named inline, because each one
costs you something real.

<!-- not-executed: needs ORDERS_DSN / SESSION_DSN / NAUTILUS_API_KEY in the environment; §7.1 validates it without touching a database -->
```yaml
# /etc/nautilus/nautilus.yaml — hardened.
sources:
  - id: orders
    type: postgres
    description: Order records
    classification: confidential
    data_types: [orders]
    allowed_purposes: [support]
    # sslmode belongs in the DSN; Nautilus does not add it for you.
    connection: ${ORDERS_DSN}
    table: public.orders
    # Trade-off: a source legitimately slower than 8s starts timing out. The
    # default is 15; without any deadline one hung source holds the request,
    # its session write and its audit entry open forever.
    timeout_s: 8.0

agents:
  support-bot:
    id: support-bot
    clearance: confidential
    compartments: []
    allowed_purposes: [support]
    subject: spiffe://prod/ns/agents/sa/support-bot

api:
  # Trade-off: loopback means the reverse proxy must be on this host or in this
  # pod. In Kubernetes use 0.0.0.0 plus a NetworkPolicy instead.
  host: 127.0.0.1
  port: 8000
  auth:
    # Trade-off: proxy_trust means the ingress owns authentication. Get
    # trusted_proxies wrong and X-Forwarded-User becomes forgeable. Use
    # mode: api_key if you do not control the network path.
    mode: proxy_trust
    trusted_proxies: ["127.0.0.1/32"]
  keys:
    # Kept for break-glass and for the monitoring reader while proxy_trust is
    # on. Structured, so it is not root.
    - key: ${NAUTILUS_API_KEY}
      agent_id: support-bot
      capabilities: [query]
  # Trade-off: 256 KiB rejects large batch intents with 413. The audit entry
  # stores the intent three times, so an unbounded body is an audit-volume
  # amplifier.
  max_request_bytes: 262144
  # Trade-off: past 32 in flight, callers get 503 + Retry-After instead of a
  # slow 200. That is the point — a saturated broker must be distinguishable
  # from a healthy one, or your load balancer retries into the same queue.
  max_concurrent_requests: 32

# Trade-off: the console is a second front door with a cookie that has no
# `secure` flag. Off unless a human needs it, and never without TLS.
ui:
  enabled: false

session_store:
  # Trade-off: postgres is the only backend shared across replicas. memory
  # gives each replica a partial view of cumulative exposure, so caps under-
  # count; sqlite is durable but single-node.
  backend: postgres
  dsn: ${SESSION_DSN}
  # Trade-off: fail_closed refuses requests when the store is unreachable.
  # fallback_memory keeps answering with an exposure ledger that has forgotten
  # everything, which is the failure mode escalation rules exist to prevent.
  on_failure: fail_closed
  ttl_seconds: 3600
  purpose_ttl_seconds: 1800
  # Trade-off: every request from one caller takes the same ledger lock. 15s
  # bounds the queue; a caller past it gets an error instead of a 32-second 200.
  lock_timeout_s: 15.0

session_tokens:
  enabled: true
  ttl_seconds: 900
  key_ring_path: /var/lib/nautilus/keyring.json
  broker_instance_id: nautilus-prod

attestation:
  enabled: true
  private_key_path: /etc/nautilus/attestation.pem

audit:
  path: /var/log/nautilus/audit.jsonl
  # Trade-off: single writer only. One replica per audit.path.
  chained: true
  checkpoint_interval: 1000

mcp:
  expose_declare_handoff: false
  max_response_bytes: 262144

rules:
  consistency_checks: true

state_dir: /var/lib/nautilus
```

### 7.1 Validate it before you ship it

This loads and validates the file without connecting to anything:

```bash
ORDERS_DSN='postgresql://nautilus@db:5432/orders?sslmode=verify-full' \
SESSION_DSN='postgresql://nautilus@db:5432/sessions?sslmode=verify-full' \
NAUTILUS_API_KEY="$(openssl rand -hex 32)" \
python -c "from nautilus.config.loader import load_config; \
load_config('/etc/nautilus/nautilus.yaml'); print('config ok')"
```

### 7.2 Start it

<!-- not-executed: systemd unit file, not a shell command -->
```ini
# /etc/systemd/system/nautilus.service
[Service]
User=nautilus
Group=nautilus
# Secrets arrive by file, not by command line: EnvironmentFile is 0600 and
# never appears in `ps`.
EnvironmentFile=/etc/nautilus/secrets.env
ExecStart=/usr/local/bin/nautilus serve \
  --config /etc/nautilus/nautilus.yaml \
  --bind 127.0.0.1:8000 \
  --log-format json
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/nautilus /var/log/nautilus
```

```bash
install -o nautilus -g nautilus -m 700 -d /var/lib/nautilus /var/log/nautilus
chmod 600 /etc/nautilus/attestation.pem /etc/nautilus/secrets.env
systemctl daemon-reload && systemctl enable --now nautilus
nautilus health --url https://nautilus.internal/readyz
```

The container image runs as a non-root user already: `deploy/deployment.yaml`
sets `runAsNonRoot: true`, `runAsUser: 65532`, `allowPrivilegeEscalation:
false`, `readOnlyRootFilesystem: true` and drops all capabilities. If you build
your own unit or Compose file, match that.

### 7.3 Confirm the gate is closed

```bash
# No credential — expect 401.
curl -s -o /dev/null -w '%{http_code}\n' https://nautilus.internal/v1/sources
# Wrong credential — expect 401.
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'X-API-Key: not-the-key' https://nautilus.internal/v1/sources
# /metrics from outside the proxy allow-list — expect 403 from nginx.
curl -s -o /dev/null -w '%{http_code}\n' https://nautilus.internal/metrics
# The console, with ui.enabled false — expect 404.
curl -s -o /dev/null -w '%{http_code}\n' https://nautilus.internal/admin/login
```

## 8. Limits that keep one caller from taking the broker down

| Key | Default | Rejects with | Cost of tightening |
| --- | --- | --- | --- |
| `api.max_request_bytes` | `1048576` | 413, before a byte of body is read when `Content-Length` is present | Large legitimate intents fail. `null` removes the limit and the audit-volume protection with it. |
| `api.max_concurrent_requests` | `64` | 503 + `Retry-After: 1` | Bursts are refused rather than queued. Probes and `/metrics` are exempt, so saturation does not restart the pod. |
| `sources[].timeout_s` | `15.0` | Source error for that source only | A slow source starts failing. `null` waits forever. |
| `session_store.lock_timeout_s` | `30.0` | Error rather than an unbounded wait | Contended callers fail faster. Applies to every backend — the in-process lock is where the queue forms. |
| `mcp.max_response_bytes` | `262144` | Rows dropped whole, with every affected source named in `truncated_sources` | Truncated results. The SDK sends the payload twice, so wire cost is roughly 2.1x this number. |

None of these is a per-key rate limit — Nautilus has none. If you need one, it
belongs in the proxy from §3.2.

## 9. When a control rejects a request

Exact response bodies, so you can match on them. The
[error reference](../reference/errors/index.md) is the full catalogue, keyed on the exact
emitted string.

| You see | Meaning | Do this |
| --- | --- | --- |
| `401 {"detail":"Not authenticated"}` | No `X-API-Key` header at all. | Send the header. Under `proxy_trust`, this is the proxy failing to forward. |
| `401 {"detail":"Invalid API key"}` | Header present, matches no entry in `api.keys`. | Compare against the running config — a key rotated out is the usual cause. |
| `401 {"detail":"API key required"}` | `api.keys` is **empty**. Fail-closed: an empty allow-list means nobody, not everybody. | Add a key. The startup log says `api.keys is empty, so every data and governance route will answer 401`. |
| `401 {"detail":"Forwarded identity rejected: peer is not a trusted proxy"}` | `proxy_trust` mode, and `request.client.host` is outside `api.auth.trusted_proxies`. | Either a genuine bypass attempt, or a hop between proxy and broker rewriting the source address. Check the peer address before widening the CIDR. |
| `401 {"detail":"Missing X-Forwarded-User"}` | Peer is trusted but forwarded no identity. | Fix `proxy_set_header X-Forwarded-User` on the proxy. |
| `403 {"detail":"This credential does not hold the 'audit_read' capability (it holds ['query'])"}` | Capability check. Same shape for `govern` and `keys`. | Add the capability to that key's entry, or use the key that has it. |
| `403 {"detail":"This credential is bound to agent_id='support-bot', so it cannot mint a session token for 'other-bot'"}` | A key with `agent_id:` tried to act as a different agent. | Use that agent's own key. This is the binding working. |
| `401 {"detail":"Invalid session token: bad_signature"}` | The token was not signed by any key this broker's ring knows. | Usually a token from a different deployment — check `broker_instance_id`. |
| `401 {"detail":"Invalid session token: unknown_kid"}` | Signed by a `kid` this ring does not have, or one that was revoked. | Replicas with unshared rings: set `session_tokens.key_ring_path` to a shared path. Otherwise the key was revoked; start a new session. |
| `401 {"detail":"Invalid session token: expired"}` | Past `session_tokens.ttl_seconds`. | Start a new session. Raise the TTL only with the replay window in mind. |
| `413 {"detail":"Request body is 2000000 bytes; this broker accepts at most 1048576 (api.max_request_bytes)."}` | Body limit. | Split the request or raise `api.max_request_bytes`. |
| `503 {"detail":"Broker busy: 32 requests are already in flight (api.max_concurrent_requests). Retry."}` with `Retry-After: 1` | Concurrency limit. Deliberately not 429 — you did nothing wrong. | Honour `Retry-After`. If it is constant, add replicas; throughput is flat past one event loop's worth of work. |
| `503 {"detail":"Broker not ready"}` | Request arrived before lifespan startup finished, or after shutdown began. | Normal during a rolling restart. `/readyz` is the signal your load balancer should be reading. |
| `409` from `POST /v1/keys/rotate` | `session_tokens.enabled` is false — there is no ring to rotate. | Enable session tokens, or stop calling rotate. |
| `400 {"detail":"kid must be a UUID"}` | Malformed `kid` on the revoke route. | Take the `kid` from `nautilus key list`. |
| `ConfigError: Missing env var 'ORDERS_DSN' referenced by source id='orders'` | Startup. `${VAR}` interpolation found nothing. | Fix the environment. This failing at startup is the control working. |
| Pod exits `Completed`, no traffic served | ASGI startup failed — usually a `fail_closed` session store that was unreachable. `nautilus serve` raises `application startup failed; the server never accepted a connection`. | Read the lines above it. The cause is logged. |

## 10. What this does not give you

State it plainly so nobody plans around a control that is not there.

- **No TLS in `nautilus serve`.** §3 is the whole answer.
- **`/metrics` cannot be authenticated in config.** Network-level control only.
- **The `/admin` cookie has no `secure` flag.** TLS is mandatory if you enable the console.
- **No per-key rate limiting.** `api.max_concurrent_requests` is global, not per caller.
- **No key registry.** `api.keys` is a config list; adding or removing one is a restart.
- **No passphrase on `attestation.private_key_path`.** File permissions are the control.
- **`rkm.auto_promote.enabled: true` is refused at load.** Every rule proposal goes to human review — by design, and it will not start if you configure otherwise.
- **`session_store.backend: redis` is refused by name.** Use `postgres` for a shared store.
- **The shipped `deploy/` manifests are plaintext HTTP** with no `NetworkPolicy` and no TLS. They are a starting point, not a hardened deployment.

## See also

- [Operator Guide](operator-guide.md) — install, serve, monitor, back up.
- [The Trust Boundary](../concepts/trust-boundary.md) — why the broker holds the credentials.
- [Configure attestation](configure-attestation.md) and [Verify a token](verify-a-token.md).
- [Monitor with Grafana](monitor-with-grafana.md) — what `/metrics` is for once it is private.
