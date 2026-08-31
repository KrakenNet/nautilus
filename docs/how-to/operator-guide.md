# Operator Guide

End-to-end walkthrough for deploying Nautilus: install, configure,
serve, monitor, rotate keys, and back up the audit trail.

## 1. Install

Requires Python 3.13+.

```bash
uv add nautilus-rkm
# or, in a service checkout:
uv sync
```

Verify:

```bash
nautilus version
```

Install the extras for the source types you configure — the base package
carries no database drivers:

```bash
pip install "nautilus-rkm[postgres,s3]"   # or [all]
```

## 2. Configure `nautilus.yaml`

A minimal production config:

```yaml
sources:
  - id: nvd_db
    type: postgres
    description: "National Vulnerability Database mirror"
    classification: unclassified
    data_types: [cve, vulnerability, patch]
    allowed_purposes: [threat-analysis, incident-response]
    connection: ${DATABASE_URL}
    table: vulns

agents:
  scanner:
    id: scanner
    clearance: unclassified
    allowed_purposes: [threat-analysis]

rules:
  user_rules_dirs: []        # directories of your own rule YAML files

analysis:
  keyword_map: {}            # optional — auto-generated from data_types

audit:
  path: /var/lib/nautilus/audit.jsonl

attestation:
  enabled: true
  private_key_path: /etc/nautilus/attestation.pem   # omit to auto-generate per process

api:
  host: 127.0.0.1
  port: 8000
  keys: ["${NAUTILUS_API_KEY}"]   # enables X-API-Key auth on the REST surface
```

**Declaring agents is what turns enforcement on.** With no `agents:` block the
router has no registered attributes to enforce, so it reads `clearance`,
`compartments` and `purpose` out of the request context — the caller declares
its own clearance, and a request that says `top-secret` reads a secret source.
That is the bootstrap default and the shape the tutorial uses; a broker started
without agents logs a warning at startup saying exactly this. A deployment
declares its agents, and binds credentials to them (below).

### Bind a credential to an agent

The bare form above authenticates the *port*: the key proves the caller may
talk to Nautilus, and the `agent_id` in the request body decides what it may
read. Nothing connects the two, so on a config with three agents at three
clearances, one shared key is a key to the highest of them. `nautilus serve`
says so at startup, and so does the log line every bare key produces.

The bound form connects them:

```yaml
api:
  keys:
    - ${DEV_KEY}                    # bare: still root, still warns
    - key: ${ANALYST_KEY}
      agent_id: analyst             # may only ask as 'analyst'
      capabilities: [query]
    - key: ${OPS_KEY}
      agent_id: ops
      capabilities: [query, audit_read, govern, keys]
```

A bound key asking as another agent gets `403` on REST and MCP alike — the two
surfaces resolve the caller through the same function, so switching ports is
not a way around it. Capabilities gate the surfaces that change what the broker
will do: `govern` for the rule queue and rule retract/rollback, `keys` for
signing-key rotation and revocation, `audit_read` for the audit log, `query`
for everything else. A bare key holds all four.

### Bind an identity your ingress already authenticated

Under `proxy_trust` an ingress terminates mTLS, SPIFFE or OIDC and forwards the
resolved identity. `agents.<id>.subject` is what turns that string into an
agent:

```yaml
api:
  auth:
    mode: proxy_trust
    trusted_proxies: ["10.0.0.0/8"]   # required: the peer the header is believed from

agents:
  analyst:
    clearance: cui
    subject: "spiffe://corp/ns/agents/sa/analyst"
    allowed_purposes: [treatment, operations]
```

`X-Forwarded-User` is a credential only while nobody but the proxy can set it,
which is why `trusted_proxies` is not optional — the config refuses to load
`proxy_trust` without it. A forwarded subject that maps to an agent may only
ask as that agent.

`allowed_purposes` on an agent bounds what it may claim as its `purpose`.
`purpose` is a live authorization input (`deny-purpose-mismatch`, the HIPAA
pack's `deny-phi-outside-tpo`) that the caller types; an agent that declares no
`allowed_purposes` is unrestricted, which is what every config written before
this is.

`nautilus serve` binds to `api.host:api.port`; an explicit `--bind HOST:PORT`
overrides them.

Key behaviors:

- `${VAR}` references are interpolated from the environment at load time.
  A missing variable fails the load with the offending source `id` in the
  error (fail closed — the broker never starts half-configured).
- Source `id` values must be unique; unsupported `type` values are
  rejected at load.
- The intent vocabulary is **auto-generated** from each source's
  `data_types` — you only need `analysis.keyword_map` entries to add
  synonyms or override a generated entry (your entry wins wholesale for
  that data type).

### Choose a session-store backend

Session state powers cumulative-exposure tracking and handoff reasoning.

```yaml
session_store:
  backend: postgres          # memory | redis | postgres | sqlite
  dsn: ${SESSION_DSN}
  ttl_seconds: 3600
  purpose_ttl_seconds: 0        # 0 = no purpose window
  on_failure: fallback_sqlite   # fail_closed | fallback_memory | fallback_sqlite
  sqlite_path: /var/lib/nautilus/sessions.db
  pool_min_size: 1              # postgres only
  pool_max_size: 10             # postgres only
  acquire_timeout_s: 10.0       # postgres only
```

- `memory` — single process, lost on restart. Fine for dev.
- `sqlite` — durable single-node deployments with no Postgres.
- `postgres` — multi-node or existing PG infrastructure.
- `on_failure: fallback_sqlite` degrades to SQLite if Postgres is
  unreachable at startup; sessions survive a broker restart and the
  audit trail records `session_store_mode: degraded_sqlite`.
- `ttl_seconds` bounds how long a session's accumulated state survives being
  idle. A session untouched for longer reads as absent — cumulative exposure
  starts fresh — and expired rows are deleted on the next write, on every
  backend. `0` disables expiry and keeps state forever.
- `purpose_ttl_seconds` bounds how long a session's declared purpose stays
  valid. Non-zero arms the built-in `purpose-expired-deny` rule: once the
  window elapses every source in the request is denied until the agent
  declares a new purpose, which restarts it. `0` (the default) leaves the
  window open indefinitely.

The `postgres` and `sqlite` backends need their schema created before the
first request, and `Broker.setup()` is what creates it — it is a no-op for
`memory` and `redis`. `nautilus serve` calls it for you. In library code, open
the broker as a context manager and it is called on the way in:

```python
with Broker.from_config("nautilus.yaml") as broker:      # setup() runs here
    ...
                                                          # close() runs here

async with await Broker.afrom_config("nautilus.yaml") as broker:
    ...
```

`afrom_config` is `from_config` on a worker thread, so it needs `setup()`
exactly as much as the sync path does.

**Size the Postgres pool against your peak concurrency.** Each in-flight
request holds *two* pooled connections at once — one for the advisory lock
around the exposure ledger, one for the read-modify-write inside it — so a
pool of `N` serves `N / 2` concurrent requests and the rest queue. Set
`pool_max_size` to at least twice peak concurrency. Past that point requests
wait `acquire_timeout_s` and then fail with a `SessionStoreUnavailableError`
naming the pool size; before 1.0 they waited forever, so an over-subscribed
broker hung instead of shedding load. `pool_min_size` is how many connections
are opened at startup.

Cumulative exposure — `sources_visited`, `data_types_seen` and
`pii_sources_accessed_list` — accumulates over the sources actually
queried, and is what escalation packs and any rule matching
`session_exposure` see.

It accumulates **per caller**, not per declared `session_id`. The caller
picks its own session id, so a per-session ledger was a control the
controlled party could reset: enough PII to trip escalation, then a fresh
session id, and the count started over. The broker derives an internal
principal from the caller's identity — `agent_id` plus the transport's
authenticated principal (the API key presented, or `X-Forwarded-User`
under `proxy_trust`) — and a new session id inherits that principal's
exposure. Different callers stay isolated from each other, and
`ttl_seconds` still ages a ledger out.

The built-in escalation pack
(`nautilus/rules/escalation/default.yaml`) declares one entry:
accumulating `email`, `phone`, `dob` and `ssn` within a session escalates
the request's effective classification to `confidential`. The built-in
`session-exposure-escalation-deny` rule denies every source in that request
when the agent's clearance does not dominate the escalated level; an agent
who does clear it routes normally. No single request carries four PII data
types, so the trigger is reachable only through accumulated exposure —
which `session_store.ttl_seconds` ages out. A fresh session id does not
reset it; see above.

### Session tokens (optional)

```yaml
session_tokens:
  enabled: true
  ttl_seconds: 3600
  key_ring_path: /var/lib/nautilus/keyring.json   # required for >1 replica
```

When enabled, the first request in a session mints an EdDSA JWS bound to
the broker instance; subsequent requests present it via
`context["session_token"]` or the `X-Nautilus-Session-Token` header (a
present-but-invalid header is a 401). A valid token's `session_id` claim
overrides the caller-declared session id. Verification is fail-closed.
Session tokens are not what protects the exposure ledger — omitting one is
always allowed — the per-caller principal above is.

`key_ring_path` persists the signing ring. Without it each broker process
generates its own keys at startup, so a restart invalidates every outstanding
token and a second replica rejects the first one's tokens with `unknown_kid`.
Point every replica at one path on shared storage. The file holds private key
material and is written `0600`.

### Running more than one replica

Two brokers can serve one deployment, but they have to share the state that
makes a decision reproducible:

- `session_store.backend: postgres` (or `redis`) — the exposure ledger. The
  broker takes a Postgres advisory lock around each ledger read-modify-write,
  so replicas serialise against each other rather than overwriting.
- `session_tokens.key_ring_path` — one signing ring, as above.
- `attestation.sink` with `chained: true` — **one writer only**. A hash chain
  is a total order; the second replica to append to the same file is refused
  (`SinkAlreadyLockedError`) rather than allowed to corrupt the chain. Give
  each replica its own path, or use `chained: false`, whose appends are atomic.
- MCP over HTTP keeps its transport sessions in process memory, so a client
  must be routed to the replica it initialized against (sticky sessions).

Replicas scale a deployment *out*, not *across*: **one deployment is one
tenant**. The agent registry, the exposure ledger, the signing ring and the
loaded rules are all deployment-wide, so agents in one deployment are
separated by policy — clearance, compartments, purpose, rules — and not by
isolation. A second tenant means a second deployment, with its own config,
source credentials, audit log and key ring. See
[The Trust Boundary](../concepts/trust-boundary.md).

### Relative paths

Every path in `nautilus.yaml` — `audit.path`, `attestation.private_key_path`
and its sink paths, `rules.user_rules_dirs`, `state_dir` — resolves
**relative to the config file's own directory**, not to the process working
directory. So
`/etc/nautilus/nautilus.yaml` with `audit: {path: audit.jsonl}` writes
`/etc/nautilus/audit.jsonl` no matter where the unit file starts the
broker. Absolute paths are used as given. Parent directories are created
on demand.

## 3. Serve

```bash
nautilus serve --config /etc/nautilus/nautilus.yaml \
  --transport rest --bind 127.0.0.1:8000 --log-format json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `nautilus.yaml` | Path to configuration file |
| `--transport` | `rest` | `rest`, `mcp`, or `both` |
| `--mcp-mode` | `stdio` | MCP transport when `mcp`/`both`: `stdio` or `http` |
| `--bind` | `127.0.0.1:8000` | REST bind address (`both` puts MCP http on port+1) |

| `--air-gapped` | — | See below |
| `--log-format` | `text` | `text` or `json` (structured logs for SIEM ingestion) |

Probe it:

```bash
nautilus health --url http://127.0.0.1:8000/readyz
```

`--mcp-mode http` runs the MCP streamable transport with sessions: the server
issues an `mcp-session-id` at `initialize` and every later call must present
it. That id is what keys a caller's session state, so two clients never share
one working memory. Sessions live in the serving process — see
[Running more than one replica](#running-more-than-one-replica).

MCP clients see three tools: `nautilus_request` (ask for data),
`nautilus_sources` (what may be asked for — metadata only, never a connection
string), and `nautilus_declare_handoff` when `mcp.expose_declare_handoff` is
on.

### On Kubernetes

`deploy/` in the repository is a complete manifest set — Deployment, Service,
ConfigMap and Secrets — with the probes wired to `/healthz` and `/readyz` and
every credential resolved from a Secret at config load. `deploy/README.md`
says what to change before applying it.

### Air-gapped mode

`--air-gapped` enforces NFR-1 for disconnected enclaves:

- `analysis.mode` is forced to `pattern`; any `analysis.provider` stanza
  is dropped (WARN on stderr).
- Any `type: llm` source whose `connection` host is not loopback is
  dropped — only a local inference server is air-gap compatible.

The config file on disk is never modified; overrides apply to a temp copy.

### Structured logging

`--log-format json` emits one JSON object per line:

```json
{"ts": "2026-06-06T01:23:45.678+00:00", "level": "INFO", "logger": "nautilus.core.broker", "module": "broker", "msg": "...", "request_id": "..."}
```

`extra={...}` keys from call sites pass through as top-level fields, and
OTel `trace_id`/`span_id` are attached when a span is active. The broker's
*decision* record is the audit log (below) — application logs are for the
surrounding operational events.

## 4. Monitor

- `GET /healthz` — liveness; `GET /readyz` — readiness (verifies the audit
  sink is writable and the session store responds; the `reason` field on a
  503 names which one failed). Every request writes an audit entry before it
  answers, so a sink that has stopped accepting writes fails every request —
  the probe takes the instance out of rotation instead of reporting ready.
- `GET /metrics` — Prometheus exposition (request counts, durations,
  denials, adapter errors).
- `examples/full-showcase/` ships a docker-compose stack with Prometheus,
  Grafana (provisioned dashboards), and Tempo — see
  [Monitor with Grafana](monitor-with-grafana.md).

## 5. Query the audit trail

Every request appends one fsync'd JSONL entry to `audit.path` — success
or failure. Query it over REST (auth-gated):

```bash
curl -H "X-API-Key: $NAUTILUS_API_KEY" \
  "http://127.0.0.1:8000/v1/audit?agent_id=agent-alpha&limit=50&order=desc"
curl -H "X-API-Key: $NAUTILUS_API_KEY" \
  "http://127.0.0.1:8000/v1/audit/<request_id>"
```

Filters: `agent_id`, `source_id`, `event_type`, `start`/`end` (ISO-8601),
`cursor`, `limit` (≤ 500), `order=asc|desc`. The response carries
`next_cursor` for pagination.

**Integrity (optional):** `audit.chained: true` upgrades the log to the same
hash-chained, JWS-signed format the attestation sink can use — every line
commits to its predecessor, so an edited or reordered entry is detectable
offline instead of leaving no trace:

```yaml
audit:
  path: /var/lib/nautilus/audit.jsonl
  chained: true
  checkpoint_interval: 100   # 0 = no checkpoints
```

It signs each line, so it requires `attestation.enabled` with a signing key
and is refused at startup without one. A chain is a total order: one writer
per file, exactly as for `attestation.sink`. Verify with the same
`fathom.chained_log.verify_chain` the admin audit view uses. Checkpoints
anchor the tail, which is what makes a *truncation* — as opposed to an edit —
detectable, so set `checkpoint_interval` if that is part of your threat model.

**Backup:** the audit file is append-only JSONL — rotate and archive it
like any log (e.g. `logrotate` with `copytruncate` disabled; move the file
and HUP is *not* needed since the broker holds the path, so prefer
copy-then-trim during a maintenance window, or ship lines continuously
with a follower like `filebeat`).

## 6. Rotate signing keys

Session-token signing keys live in an in-process `KeyRing`, published at
`GET /v1/keys/jwks.json`. Nothing is persisted: the ring is broker state,
so every `nautilus key` subcommand needs `--url` pointed at the running
broker and exits 2 without one. Rotation is zero-downtime:

```bash
export NAUTILUS_URL=http://localhost:8000
export NAUTILUS_REVIEWER=ops@example.com   # stamped on the audit event

# Mint a new primary; the old key enters a grace window
nautilus key rotate --yes --url "$NAUTILUS_URL" --api-key "$NAUTILUS_API_KEY"

nautilus key list --url "$NAUTILUS_URL" --api-key "$NAUTILUS_API_KEY" --json

# In-flight tokens keep verifying during grace and are lazily re-signed
# under the new kid (original expiry preserved — rotation never extends
# a session). When ready, end the grace window:
nautilus key revoke <old-kid> --reason "scheduled rotation" --yes \
  --url "$NAUTILUS_URL" --api-key "$NAUTILUS_API_KEY"
```

These drive `GET /v1/keys/jwks.json`, `POST /v1/keys/rotate` and
`POST /v1/keys/{kid}/revoke` (the two writes are auth-gated; reviewer
identity comes from `NAUTILUS_REVIEWER`). Revoking the current primary is
refused — rotate first, then revoke. Every rotation/revocation emits a
`signing_key_rotated`/`signing_key_revoked` audit event.

Restarting the broker mints a fresh ring, which invalidates every
outstanding session token. Treat a restart as an unplanned rotation with
no grace window.

The *attestation* key (which signs per-request attestation tokens) is
separate: set `attestation.private_key_path` to persist it across
restarts, or omit it to auto-generate per process — see
[Configure attestation](configure-attestation.md).

## 7. Manage adapters and schema drift

```bash
nautilus adapters list --status quarantined
nautilus adapters schema <source-id> --json
nautilus adapters schema-diff <source-id> --config nautilus.yaml
nautilus adapters schema-ack <source-id> --config nautilus.yaml \
  --reason "intentional migration" --yes
```

The broker fingerprints each adapter's schema when it first connects;
unexpected drift quarantines the source (it stops receiving routed
requests, including the request that discovered the drift) until an
operator acknowledges the change with `schema-ack`.

Baselines live under `.nautilus/adapters/fingerprints/` next to the
config file, so they survive a restart. `schema-diff` and `schema-ack`
take `--config` because they compare against — and rewrite — the same
baselines the broker reads.

**In a container, point `state_dir` at a writable volume.** The config file
is normally mounted read-only, and the broker will not fail a request it has
already allowed just because it cannot write a baseline: it warns once and
keeps them in memory, which means drift is detected within the process but
not across a restart. `state_dir: /var/lib/nautilus` moves them somewhere
writable — the shipped `deploy/configmap.yaml` and the full-showcase compose
file both do this.

```yaml
state_dir: /var/lib/nautilus
```

### When a source is down or answers with too much

- **Unreachable sources are not re-dialled on every request.** A source whose
  `connect()` fails or times out is put in a 30-second cooldown; requests
  routed to it during that window are denied immediately with the connect
  error rather than spending the source's `timeout_s` again. The first request
  after the window retries, so a recovered source comes back on its own.
- **A response is bounded before it is parsed.** The REST adapter refuses a
  body over 8 MiB, and the S3 adapter refuses an object over 8 MiB, in both
  cases before materializing it. Either raises an adapter error naming the
  ceiling; the source is not quarantined for it.
- **A source's rows are bounded in bytes, not only in rows.** The postgres
  adapter's 1000-row cap is not a bound when a row can be any size: a table of
  wide text values turned one request into a 65 MB response and ~115 MB of
  process memory, and eight concurrent requests SIGKILLed the pod under
  `limits.memory: 1Gi` — clients got a dropped socket, not a 413 or a 503, and
  both probes went unreachable because there was no process left to answer.
  `sources[].max_response_bytes` (default 8388608) drops whole rows until the
  result fits and names the source in `truncated_sources`. Postgres stops
  reading at the budget rather than trimming afterwards, which is what bounds
  the peak; every other adapter is held to the same number by the broker. Set
  it to `null` per source to remove the bound.
- **A request body is bounded before it is read.** `api.max_request_bytes`
  (default 1048576) refuses a larger body with 413, and `intent` is capped at
  8192 characters. Neither existed: the audit entry stores the raw intent three
  times, so one 4 MB request wrote 12.6 MB of JSONL, and the audit volume is
  what `/readyz` fails closed on. Set `max_request_bytes: null` to remove the
  body limit.
- **An MCP reply is bounded before it reaches a model.** A tool result is read
  straight into a context window and the MCP SDK puts it on the wire twice, so
  `mcp.max_response_bytes` (default 262144) trims whole rows until the
  serialized response fits and names every source it touched in
  `truncated_sources`. REST is not bounded this way — an HTTP client streams to
  a file. Set it to `null` to turn the bound off.
- **Concurrency is bounded, and saturation says so.**
  `api.max_concurrent_requests` (default 64) holds that many requests in flight
  and answers the rest with 503 and `Retry-After: 1`. Without it throughput was
  flat from 1 concurrent client to 512 while latency grew with the queue — 12 ms
  at 1, 8.5 s at 512, every request still 200 — so nothing in front of the
  broker could tell a saturated one from a healthy one, and retries joined the
  same queue. `/healthz`, `/readyz` and `/metrics` are never gated, so a full
  queue does not take the pod out of rotation. Set it to `null` to remove the
  limit.
- **Waiting for the exposure ledger is bounded.** Requests from one caller are
  served one at a time on purpose: two that both read the ledger empty both pass
  a cumulative cap. The lock is held across the source query, and
  `SourceConfig.timeout_s` only starts once the lock is won, so the queueing
  used to sit outside every deadline in the config — one caller measured 32
  seconds to an HTTP 200. `session_store.lock_timeout_s` (default 30) bounds it;
  past it the request answers 503 with `Retry-After`. Raise it for callers that
  legitimately run long queries back-to-back, or set it to `null` for the old
  unbounded wait.

### Which rules are in force

```bash
curl -H "X-API-Key: $NAUTILUS_API_KEY" http://127.0.0.1:8000/v1/rules
```

Returns every rule the running engine will fire — built-ins, user rules and
pack rules alike — plus a `ruleset_hash`. That hash is recorded on every audit
entry, so an entry can be replayed against the policy that produced it rather
than against whatever is loaded today.

**A name resolves to one distribution, or to an error.** An entry point in the
`nautilus.adapters` group whose name collides with a built-in is refused and
logged at ERROR naming the distribution — scope enforcement lives in the
adapter, so a package that replaced `postgres` would remove the control while
every receipt still recorded it. Register a plugin under a source type of its
own, or name it explicitly in the config's `adapters` block. Accepted
discoveries log at INFO with their distribution. A rule-pack name claimed by
more than one installed distribution is a config error for the same reason:
entry points are ordered by distribution name, so first-match silently
substitutes one policy for another.

**Traces are exported only when you say where.** `OTEL_EXPORTER_OTLP_ENDPOINT`
(or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) turns the OTLP span exporter on.
Unset, the broker still creates spans and still serves every `nautilus_*`
series on `/metrics`; it just does not export, and says nothing about it. It
used to export to localhost:4318 by default, which nothing listens to in the
shipped manifest — three WARNING retries plus an ERROR per span batch, about 39
log lines a minute per replica. `OTEL_SDK_DISABLED=true` is still there but is
the wrong tool for this: it also drops the Prometheus reader and every
`nautilus_*` series with it.

**Watch for a split fleet.** Every rolling deploy passes through a state where
two replicas hold different rulesets, and the identical request then alternates
`allowed` / `denied` behind the load balancer — a caller who is denied retries
and is allowed. Two things make that visible: every `BrokerResponse` carries
the `ruleset_hash` that answered it, and each replica's `/metrics` exposes
`nautilus_ruleset_info{ruleset_hash="…"} 1`. Alert on more than one distinct
hash across the fleet:

```promql
count(count by (ruleset_hash) (nautilus_ruleset_info)) > 1
```

Do not poll `/v1/rules` through the Service for this — it is load-balanced, so
the hash just flaps between the replicas and a split is indistinguishable from
a policy change.

**Retraction changes the running engine.** `POST /v1/rules/{name}/retract`
removes the rule from the engine and, when its YAML lives in a configured
`rules.user_rules_dirs`, from that file too; the response's `engine_updated`
and `engine_note` say which of those happened. A built-in or pack rule can be
retracted for the life of the process but comes back at the next start —
remove the pack from `rules.packs` instead. **Rollback does not:** a lineage
record carries no rule text, so `POST /v1/rules/{name}/rollback` re-promotes a
version in the ledger and returns `engine_updated: false`.

## 8. Validate rules before deploying

```bash
nautilus rules validate my-rules.yaml
nautilus rules test --file my-rules.yaml --audit-log /var/lib/nautilus/audit.jsonl
```

`rules validate` builds the file into a real engine, not just the compiler, so
an unknown module, a slot no template declares, or an operator CLIPS does not
have is caught here rather than at the next broker start.

See the [rule-authoring guide](authoring-rules.md) for the full workflow,
including shadow detection and sandbox replay against production audit
history.
