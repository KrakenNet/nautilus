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
  synonyms. Your keywords are **added** to the generated ones, never
  substituted for them: a data type always matches its own advertised name,
  so `orders: ["purchase order"]` matches both phrasings and never makes the
  word *orders* unmatchable.

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
- Both durable backends stamp a **schema version** (SQLite `PRAGMA
  user_version`, Postgres `nautilus_schema_version`) and refuse to start
  against one they do not understand. `on_failure` does not cover this: a
  version mismatch is a deployment error, not an outage, and degrading to
  memory would leave each replica with a private ledger while the shared one
  sits unread. Finish or roll back the rollout — do not run two builds against
  one store.
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

**A session belongs to a principal.** The first principal to use a
`session_id` owns it; another principal that names the same id gets `403
session_not_yours`. Without that, a session id was only a string, so any
credential could add exposure to any session it could name — driving another
caller's escalation until every source was denied, and reading the result back
through which rules fired.

A session that spans agents still works, through the path that declares it:
after `declare_handoff` allows a handoff to agent B in that session, B's
credential joins the session and inherits what it has already seen. That is
the only way in. The handoff is recorded on the session row when it is
allowed, so `declare_handoff` now writes to the session store — one row, no
adapter calls.

Ownership is enforced for callers that arrive over a transport, which always
identifies them. `Broker.arequest` called directly from your own code presents
no credential and no peer: there is no second caller for the boundary to be
between, and one process running several of its own agents through one session
is the supported shape.

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

A token only ever claims a purpose the agent may claim. `allowed_purposes` on
an agent record is a live authorization input — `fathom_router` denies every
source when the request falls outside it — so the broker mints no token, and
`POST /v1/sessions` answers `403`, rather than signing an assertion the policy
refuses to act on.

### Memory under sustained load

RSS climbs for the first several minutes of traffic and then stops. Measured
over a 10-minute soak at 16 concurrent clients against a two-source broker:

| elapsed | RSS | growth in the last 30s | Python objects |
| --- | --- | --- | --- |
| 0s | 165 MB | — | 158,868 |
| 2m | 200 MB | 6.0 MB | 158,816 |
| 5m | 224 MB | 3.1 MB | 158,817 |
| 8m | 235 MB | 2.5 MB | 158,803 |
| 9m | 243 MB | 1.7 MB | 158,831 |
| load stops | 243 MB | 0.2 MB | 155,588 |

The Python object count is flat the whole way and falls when the load stops, so
nothing is being retained at the Python level. What grows is the CLIPS engine's
own arena and the allocator's, sized to the working set of requests in flight
and never returned to the OS. The per-30s growth decays geometrically and the
curve goes flat the moment traffic does; extrapolating the last few samples
puts the ceiling near 260 MB for that shape of config.

Size the pod from the plateau, not the starting RSS: `deploy/deployment.yaml`
requests 512Mi and limits 1Gi, which leaves room for a larger rule tree and
more sources. A broker whose RSS is still climbing after 15 minutes of steady
traffic, or that keeps climbing after the traffic stops, is not this — capture
`gc` object counts before filing it.

### Session store schema versions

The store carries a schema version — `PRAGMA user_version` for sqlite, the
`nautilus_schema_version` row for Postgres. A build that finds a version it
does not understand refuses to start, and `/readyz` re-reads it on every probe,
so a replica that is already serving when a rolling upgrade migrates the shared
store drains instead of read-modify-writing rows under a schema it cannot read.
`session_store.on_failure` does not cover this: a version mismatch is a
deliberate refusal, not the store being unavailable.

`nautilus session version --sqlite-path PATH` (or `--dsn DSN`) prints what a
store carries and what the running build understands. Version 1 is the only
version there has been, so a mismatch means the store was written by a build
that is not this one: run that build, or point the config at a fresh store. An agent that declares no `allowed_purposes` is
unrestricted, which is the shape every config written before the field existed
has.

A token's `purpose` and `clearance` claims describe the request that was
actually served. Carry a session into a second purpose and the response hands
back a re-minted token stating the new one — with the **original** expiry, so
neither re-binding nor key rotation extends a session's lifetime. Anything
reading the forwarded `X-Nautilus-Session-Token` can therefore trust the claims
against the request they arrived with.

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
| `--log-level` | `info` | `debug`, `info`, `warning`, `error`, `critical` — see below |

Probe it:

```bash
nautilus health --url http://127.0.0.1:8000/readyz
```

The config is read once, here, and never again — check it before you start on
it: [Check what you are about to deploy](#the-config).

`serve` exits **2** when the application fails to start — an unreachable
`on_failure: fail_closed` session store, an unwritable audit path — so a pod
that never served reads as a crash and gets restarted, rather than exiting
Completed. A clean `SIGTERM` after serving exits 0 (uvicorn re-raises the
signal, so the shell reports 143).

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

The Deployment declares `ephemeral-storage` requests and limits and a
`sizeLimit` on both `emptyDir` volumes. The audit log is append-only and grows
with traffic; uncapped it fills the node's disk, and disk pressure is a *node*
condition — the kubelet evicts the neighbours too. Raise the numbers together
if you raise either, and point the audit volume at a PersistentVolumeClaim or
a collector before you rely on the trail.

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

### Log verbosity

`--log-level` sets one threshold for both halves of the stream: the root
logger every `nautilus.*` module writes to, and uvicorn's own logger, which
owns the `Started server process` / `Application startup complete` /
`Uvicorn running on` lines and the per-request access line. It takes
`debug`, `info` (default), `warning`, `error` or `critical`, and it composes
with `--log-format`.

There is no environment variable and no config key for this — the flag is the
whole mechanism, exactly as for `--log-format`. Set it in the same place you
set `--bind`: the `args:` list of the Deployment, or the unit file's
`ExecStart`.

At the default, a boot plus one readiness probe plus one request against a
broker holding a single bare API key produces this, start to finish:

```console
$ nautilus serve --config nautilus.yaml --bind 127.0.0.1:8802
INFO:nautilus.core.broker:discovered adapter entry-point 'influxdb' -> InfluxDBAdapter (from 'nautilus-rkm')
INFO:nautilus.core.broker:discovered adapter entry-point 's3' -> S3Adapter (from 'nautilus-rkm')
INFO:     Started server process [2278776]
INFO:     Waiting for application startup.
WARNING:nautilus.transport.fastapi_app:api.keys[0] is a bare string: bound to no agent_id, so it can ask as any agent and call every governance route. Use the {key, agent_id, capabilities} form to scope it.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8802 (Press CTRL+C to quit)
INFO:     127.0.0.1:55412 - "GET /readyz HTTP/1.1" 200 OK
INFO:     127.0.0.1:55424 - "POST /v1/request HTTP/1.1" 200 OK
INFO:     Shutting down
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
INFO:     Finished server process [2278776]
```

`--log-level warning` reduces that same run to one line, because everything
else in it is `INFO`:

```console
$ nautilus serve --config nautilus.yaml --bind 127.0.0.1:8802 --log-level warning
WARNING:nautilus.transport.fastapi_app:api.keys[0] is a bare string: bound to no agent_id, so it can ask as any agent and call every governance route. Use the {key, agent_id, capabilities} form to scope it.
```

**That is a real trade, not a cosmetic one.** The startup lines this page and
the rest of the how-to guides tell you to read — the bare-key warning, the
"no `agents:` block" warning, the adapter entry-point discoveries, the
rule-pack collision errors — are `INFO` and `WARNING`. At `warning` you keep
the warnings and errors and lose the discoveries and the access log; at
`error` you lose the bare-key warning too. Prefer `--log-format json` and
filter downstream over raising the threshold, unless the access log is what
you are trying to silence.

#### What `--log-level debug` adds

`debug` is where the broker says *why*. It answers seven questions the default
stream cannot, and it still adds `DEBUG` from every library on the root logger
along the way — the first extra line on a normal boot is
`DEBUG:asyncio:Using selector: EpollSelector`, and any library that is chatty
is chatty here.

| Question | Logger | Where |
| --- | --- | --- |
| What config did this process load, and what did its paths and connections resolve to? | `nautilus.core.broker` | once, at construction |
| Why was each source queried, skipped or denied on this request? | `nautilus.core.broker` | one line per configured source, per request |
| Which rules were evaluated, and which fired? | `nautilus.core.broker` | one summary line per request |
| What did an adapter dial, and did it connect? | `nautilus.core.broker` | on the first request that reaches the source |
| Did the SSRF guard resolve a name, and to what? | `nautilus.adapters.base` | on every `rest` / `servicenow` / `llm` connect |
| Why is this request minting a session token? | `nautilus.core.broker` | when one is minted |
| Which stage of `/readyz` spent the time? | `nautilus.transport.fastapi_app` | every probe |

Here is the whole of a real boot, one `/readyz`, and one
`POST /v1/request` against a five-source config — two sources unreachable on
purpose, one above the agent's clearance, one irrelevant to the intent:

```console
$ nautilus serve --config /tmp/nautilus-ops14/nautilus.yaml --bind 127.0.0.1:8814 --log-level debug
INFO:nautilus.core.broker:discovered adapter entry-point 'influxdb' -> InfluxDBAdapter (from 'nautilus-rkm')
INFO:nautilus.core.broker:discovered adapter entry-point 's3' -> S3Adapter (from 'nautilus-rkm')
DEBUG:nautilus.core.broker:loaded config /tmp/nautilus-ops14/nautilus.yaml: 5 source(s), 1 agent(s), audit -> /tmp/nautilus-ops14/audit.jsonl, session store 'memory', session tokens on, state dir /tmp/nautilus-ops14
DEBUG:nautilus.core.broker:config source 'orders': type 'static', classification 'unclassified', data types ['orders'], dials nothing
DEBUG:nautilus.core.broker:config source 'hr-people': type 'static', classification 'unclassified', data types ['personnel'], dials nothing
DEBUG:nautilus.core.broker:config source 'vault': type 'static', classification 'secret', data types ['orders'], dials nothing
DEBUG:nautilus.core.broker:config source 'ext-cases': type 'postgres', classification 'unclassified', data types ['orders'], dials postgresql://cases.example.invalid:5432
DEBUG:nautilus.core.broker:config source 'ext-feeds': type 'rest', classification 'unclassified', data types ['orders'], dials https://localhost:8443
DEBUG:asyncio:Using selector: EpollSelector
INFO:     Started server process [801119]
INFO:     Waiting for application startup.
WARNING:nautilus.transport.fastapi_app:api.keys[0] is a bare string: bound to no agent_id, so it can ask as any agent and call every governance route. Use the {key, agent_id, capabilities} form to scope it.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8814 (Press CTRL+C to quit)
DEBUG:nautilus.transport.fastapi_app:readyz stages: audit sink probe 0.0 ms; session store sentinel read 0.0 ms (total 0.1 ms; each session-store stage is bounded at 2.0s, so the kubelet timeoutSeconds must exceed their sum, not one of them)
INFO:     127.0.0.1:48114 - "GET /readyz HTTP/1.1" 200 OK
DEBUG:nautilus.core.broker:minting a session token for agent 'analyst' in session 'f7d2aef1-2582-43a3-8695-272ed61ea638' (purpose 'reporting', clearance 'unclassified'): the caller declared no session_id, so it is its own session. This writes a session_token_issued audit entry beside the request's own.
DEBUG:nautilus.core.broker:request 'bdafd902-b333-4db4-990b-97851e32e533': intent 'list orders' parsed to data types ['orders']; 6 rules in force, 2 fired: ['nautilus-routing::default-classification-deny', 'nautilus-routing::match-sources-by-data-type']
DEBUG:nautilus.core.broker:request 'bdafd902-b333-4db4-990b-97851e32e533': source 'ext-cases' queried -- data_types overlap
DEBUG:nautilus.core.broker:request 'bdafd902-b333-4db4-990b-97851e32e533': source 'ext-feeds' queried -- data_types overlap
DEBUG:nautilus.core.broker:request 'bdafd902-b333-4db4-990b-97851e32e533': source 'hr-people' skipped -- no data type in common with the intent: source 'hr-people' offers ['personnel'], the request needed ['orders']
DEBUG:nautilus.core.broker:request 'bdafd902-b333-4db4-990b-97851e32e533': source 'orders' queried -- data_types overlap
DEBUG:nautilus.core.broker:request 'bdafd902-b333-4db4-990b-97851e32e533': source 'vault' denied -- clearance does not dominate source classification
DEBUG:nautilus.core.broker:request 'bdafd902-b333-4db4-990b-97851e32e533': source 'ext-feeds' dialling https://localhost:8443 via RestAdapter
DEBUG:nautilus.core.broker:request 'bdafd902-b333-4db4-990b-97851e32e533': source 'ext-cases' dialling postgresql://cases.example.invalid:5432 via PostgresAdapter
DEBUG:nautilus.core.broker:request 'bdafd902-b333-4db4-990b-97851e32e533': source 'orders' dialling no remote endpoint via StaticAdapter
DEBUG:nautilus.core.broker:request 'bdafd902-b333-4db4-990b-97851e32e533': source 'orders' connected to no remote endpoint in 0.0 ms
DEBUG:nautilus.adapters.base:RestAdapter SSRF guard: base_url host localhost resolves to ['127.0.0.1']
WARNING:nautilus.core.broker:source 'ext-feeds' failed (endpoint=https://localhost:8443, error_type=SSRFBlockedError, trace_id=bdafd902-b333-4db4-990b-97851e32e533): connect() failed: RestAdapter refuses base_url host 'localhost': it resolves to private/loopback/link-local address 127.0.0.1
WARNING:nautilus.core.broker:source 'ext-cases' failed (endpoint=postgresql://cases.example.invalid:5432, error_type=AdapterError, trace_id=bdafd902-b333-4db4-990b-97851e32e533): connect() failed: PostgresAdapter failed to connect to source 'ext-cases': [Errno -2] Name or service not known
INFO:     127.0.0.1:48126 - "POST /v1/request HTTP/1.1" 200 OK
```

The same run at the default `info` is eleven lines to the same point and
answers none of the seven — the two `WARNING`s survive, every `DEBUG` above
is gone:

```console
$ nautilus serve --config /tmp/nautilus-ops14/nautilus.yaml --bind 127.0.0.1:8815
INFO:nautilus.core.broker:discovered adapter entry-point 'influxdb' -> InfluxDBAdapter (from 'nautilus-rkm')
INFO:nautilus.core.broker:discovered adapter entry-point 's3' -> S3Adapter (from 'nautilus-rkm')
INFO:     Started server process [803280]
INFO:     Waiting for application startup.
WARNING:nautilus.transport.fastapi_app:api.keys[0] is a bare string: bound to no agent_id, so it can ask as any agent and call every governance route. Use the {key, agent_id, capabilities} form to scope it.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8815 (Press CTRL+C to quit)
INFO:     127.0.0.1:59540 - "GET /readyz HTTP/1.1" 200 OK
WARNING:nautilus.core.broker:source 'ext-feeds' failed (endpoint=https://localhost:8443, error_type=SSRFBlockedError, trace_id=d135a3e2-0149-468e-a47c-338be1c815b2): connect() failed: RestAdapter refuses base_url host 'localhost': it resolves to private/loopback/link-local address 127.0.0.1
WARNING:nautilus.core.broker:source 'ext-cases' failed (endpoint=postgresql://cases.example.invalid:5432, error_type=AdapterError, trace_id=d135a3e2-0149-468e-a47c-338be1c815b2): connect() failed: PostgresAdapter failed to connect to source 'ext-cases': [Errno -2] Name or service not known
INFO:     127.0.0.1:59550 - "POST /v1/request HTTP/1.1" 200 OK
```

**Nothing on this stream is a credential.** Every address above is rebuilt
from scheme, host and port by the same allowlist redactor the error records
use, so the userinfo, path, query and fragment of a `connection` cannot reach
it: the config behind that run holds
`postgresql://nautilus:s3cr3t-dsn-password@cases.example.invalid:5432/nautilus`
and `https://localhost:8443/api?token=s3cr3t-query-token` with a bearer token
beside it, and `grep -c` for each of the three secrets over the whole `debug`
run and over `audit.jsonl` returns **0** — while the two `scheme://host:port`
endpoints appear three times each on stdout and once each in `audit.jsonl`.
Session tokens are named by their session id, never printed.

`DEBUG` is still `DEBUG`: it is per-request, it is `O(sources)` lines per
request, and it turns on every library's debug records too. Raise it while you
are looking, lower it when you are done — do not run a busy deployment on it.

The two flags compose. `--log-format json --log-level warning` emits the
warning above as one object:

```json
{"ts": "2026-09-01T11:17:50.207273+00:00", "level": "WARNING", "logger": "nautilus.transport.fastapi_app", "module": "fastapi_app", "msg": "api.keys[0] is a bare string: bound to no agent_id, so it can ask as any agent and call every governance route. Use the {key, agent_id, capabilities} form to scope it."}
```

## 4. Monitor

- `GET /healthz` — liveness, and the build: it answers
  `{"status": "ok", "version": "0.2.6.dev0", "build": "6b28795…-dirty"}`. The
  version comes from the installed distribution's metadata; the build is the
  revision passed to `docker build --build-arg BUILD_REV=…`, and is `unknown`
  on an image built without it. No credential, so a synthetic check or a
  runbook `curl` can read both; two replicas disagreeing on either means the
  rollout is half done, and two replicas agreeing on `version` while
  disagreeing on `build` is the case the version alone could never show you.
  Releases up to 0.2.5 answer `{"status": "ok"}` with no version, and
  `nautilus version` is no fallback there: those builds look the distribution
  up as `metadata.version("nautilus")` when it is installed as `nautilus-rkm`,
  so the command prints `nautilus (version unknown — package metadata missing)`
  and exits 1 on every install. On those releases nothing the container can be
  asked names the build — identify it by the image digest the node recorded.
- `GET /readyz` — readiness (verifies the audit
  sink is writable and the session store responds; the `reason` field on a
  503 names which one failed). Every request writes an audit entry before it
  answers, so a sink that has stopped accepting writes fails every request —
  the probe takes the instance out of rotation instead of reporting ready.
  Two cases the probe covers that a permission check cannot:
  - With `audit.chained: true` the log admits exactly one writer. The probe
    takes that writer lock, so a replica pointed at a log another process owns
    reports `not_ready` instead of joining the Service and 500ing every
    request. Give each replica its own `audit.path`, or use
    `audit.chained: false`.
  - The session-store check is bounded at 2s and answers `503` with
    `reason: session_store_timeout`. A store that is *down* fails fast; one
    that is reachable but frozen — a paused container, a saturated primary —
    would otherwise never answer the probe at all.
- `GET /metrics` — Prometheus text exposition. Request counts, end-to-end and
  per-adapter durations, denials and adapter errors are all there, but **only
  on an install that has the `otel` extra** — see
  [What `/metrics` exports](#what-metrics-exports) for the exact list, and for
  the two configurations in which most of it disappears.
- `examples/full-showcase/` ships a docker-compose stack with Prometheus,
  Grafana (provisioned dashboards), and Tempo — see
  [Monitor with Grafana](monitor-with-grafana.md).

### What `/metrics` exports

**First: install the extra.** The endpoint is served by `prometheus_client`,
which ships in the `otel` extra and nowhere else. On a base
`pip install nautilus-rkm` the route's import of it fails, and the scrape
answers **HTTP 500** (`Internal Server Error`) with the `ImportError` traceback
in the broker's log. The broker keeps serving traffic normally — only the
scrape target is dead, and nothing warns you at startup:

```bash
pip install "nautilus-rkm[otel]"     # opentelemetry-sdk, the Prometheus
                                     # exporter, prometheus-client
```

With the extra installed, `nautilus serve` needs no further configuration:
the meter provider and the Prometheus reader are installed during app startup
and `GET /metrics` is ungated (no `X-API-Key`, excluded from the OpenAPI
schema).

**Application metrics** — recorded by the broker, exported through the
OpenTelemetry Prometheus exporter. The exporter appends the unit to each
histogram name, which is why the `_seconds` suffix does not appear in the
source:

| Series | Type | Labels | What it answers |
|---|---|---|---|
| `nautilus_requests_total` | counter | — | Request rate. One per broker request whichever transport it arrived on — `POST /v1/request`, `POST /v1/query`, the MCP `nautilus_request` tool — incremented *before* the pipeline runs, so denied and errored requests are counted too. |
| `nautilus_routing_decisions_total` | counter | — | How much work a request is doing: incremented by the number of sources the router selected, not by one. A request denied at every source adds nothing, so this is not a copy of `requests_total`. |
| `nautilus_scope_denials_total` | counter | `rule_name` | Which policy is doing the denying. One increment per denial record, so a request denied across three sources adds three. |
| `nautilus_attestation_total` | counter | `outcome` = `emitted` \| `sink_error` | Whether the signed receipt actually reached the sink. `sink_error` climbing while `emitted` is flat means the attestation trail is being lost. |
| `nautilus_adapter_errors_total` | counter | `source_id`, `error_type` | Which upstream is failing and how. `error_type` is the same string the response's `error_records[].error_type` carries: usually the exception class name (`SSRFBlockedError`, `ScopeEnforcementError`), plus the literal `AdapterError` for an unregistered source or one inside its 30-second connect cooldown, and `ADAPTER_QUARANTINED` for one held out on schema drift. |
| `nautilus_session_exposure_flags_total` | counter | — | How often cumulative-exposure facts are being asserted, i.e. how close callers are running to the escalation packs. |
| `nautilus_request_duration_seconds` | histogram | — | End-to-end latency, broker-side. This is the one to build the p50/p90/p99 panel on. |
| `nautilus_adapter_latency_seconds` | histogram | `source_id` | Which source is the slow one. |
| `nautilus_fathom_evaluation_duration_seconds` | histogram | — | Time in the CLIPS engine alone. Subtract it from `request_duration` to separate "policy is slow" from "the data is slow". |

All three histograms share explicit bucket boundaries in **seconds** —
`0.001 0.005 0.01 0.05 0.1 0.25 0.5 1 2.5 5 10 30` plus `+Inf`. The SDK
default boundaries are millisecond-shaped, so without this every observation
would land in the first bucket and no quantile would mean anything.

**Two exposition details that will otherwise cost you an afternoon:**

- *Counters exist at zero from startup; histograms do not.* The six counters
  are published at `0` before any traffic, so
  `rate(nautilus_scope_denials_total[5m]) > 0` matches a real series on a
  broker that has never denied anything. The three histograms are not primed —
  a `_bucket`/`_sum`/`_count` series only appears after the **first request**.
  A fresh replica with a "no data" latency panel is normal; a replica that has
  served traffic and still has none is not.
- *Priming leaves an empty-label series behind.* Because the zero is published
  with no attributes, a labelled counter carries one extra sample with the
  label empty:

    ```text
    nautilus_scope_denials_total{rule_name=""} 0.0
    nautilus_scope_denials_total{rule_name="purpose-not-permitted"} 1.0
    ```

    It sums to nothing, but it does show up as a phantom entry in a
    `by (rule_name)` breakdown. Filter it with `{rule_name!=""}`.

**Broker-state gauges** — read at scrape time by collectors registered
directly on `prometheus_client`, so these survive `OTEL_SDK_DISABLED=true`
when nothing else does:

| Series | Type | Labels | What it answers |
|---|---|---|---|
| `nautilus_ruleset_info` | gauge | `ruleset_hash` | Which policy this replica loaded. Always `1`; the value carries no information, the label does. Alert on `count(count by (ruleset_hash) (nautilus_ruleset_info)) > 1` to catch a split fleet mid-rollout. |
| `nautilus_rkm_queue_depth` | gauge | — | Pending rule proposals waiting on a reviewer. |
| `nautilus_rkm_queue_oldest_age_seconds` | gauge | — | How long the oldest one has waited. Page on this, not on depth: a queue of one that is three days old is the failure. |

Both `rkm_queue` families are declared (`# HELP` / `# TYPE`) from the first
scrape but carry **no sample** until the review queue has been touched in this
process — a `GET /v1/rkm/queue` is enough. That is not the same as a depth of
zero, and a dashboard that plots the absence as zero will be wrong.

**Runtime metrics you did not ask for but will see:**
`process_resident_memory_bytes`, `process_cpu_seconds_total`,
`process_open_fds`, `process_max_fds`, `process_virtual_memory_bytes`,
`process_start_time_seconds`, `python_info`, `python_gc_objects_collected_total`,
`python_gc_objects_uncollectable_total`, `python_gc_collections_total` — the
`prometheus_client` defaults. Plus the OTel SDK's own
`otel_sdk_span_started_total`, `otel_sdk_span_live`,
`otel_sdk_metric_reader_collection_duration_seconds`, and `target_info` — which
carries these four labels and no others:

```text
target_info{service_name="nautilus",telemetry_sdk_language="python",telemetry_sdk_name="opentelemetry",telemetry_sdk_version="1.41.0"} 1.0
```

**There is no `service_version` label.** `target_info` is the conventional
OpenTelemetry home for a build stamp and it does not hold one here: the resource
is built from `service.name` alone. Do not write a dashboard or an alert that
groups by a version label on `/metrics` — ask
[`GET /healthz`](../reference/rest-api.md#get-healthz) instead, which reports the
build with no credential, no optional dependency and no off-switch.
`telemetry_sdk_version` is the OpenTelemetry SDK's version, not Nautilus's.

`process_resident_memory_bytes` is the series to check against the plateau in
[Memory under sustained load](#memory-under-sustained-load).

**`OTEL_SDK_DISABLED=true` is not a way to quiet the tracer.** It short-circuits
the whole observability setup, so the meter provider is never installed and
every one of the nine `nautilus_*` application series above disappears from the
exposition. What is left is `nautilus_ruleset_info`, the two `rkm_queue`
gauges, and the `process_*` / `python_*` defaults — `/metrics` still answers
`200`, which is what makes this hard to spot. To stop exporting *traces* while
keeping metrics, simply leave `OTEL_EXPORTER_OTLP_ENDPOINT` unset; that is the
supported off-switch (see
[Traces are exported only when you say where](#which-rules-are-in-force)).

## 5. Query the audit trail

The audit log is the broker's decision record: append-only JSONL at
`audit.path`, fsync'd after every write, and the one dependency whose failure
is total. When it stops accepting writes the instance takes itself out of
rotation rather than serving unrecorded requests. Reproduced on a scratch
instance by revoking write permission on the log under a live broker — do not
run the `chmod` against a log you care about:

```console
$ curl -s http://127.0.0.1:8000/readyz
{"status":"ok"}
$ chmod 0444 /var/lib/nautilus/audit.jsonl
$ curl -s -w ' HTTP %{http_code}\n' http://127.0.0.1:8000/readyz
{"status":"not_ready","reason":"audit log /var/lib/nautilus/audit.jsonl is not writable"} HTTP 503
```

`/healthz` keeps answering `200` throughout: liveness is not readiness, and a
broker with an unwritable audit log is working correctly by refusing traffic.

That `chmod` is a **host** command, against a broker you started on the host.
There is no `chmod` and no shell in the distroless container image, so on a
container the same reproduction — and the same repair — goes through the
interpreter that *is* in the image:

```console
$ docker exec nautilus python -c "import os; os.chmod('/var/log/nautilus/audit.jsonl', 0o444)"
$ curl -s -w ' HTTP %{http_code}\n' localhost:8000/readyz
{"status":"not_ready","reason":"audit log /var/log/nautilus/audit.jsonl is not writable"} HTTP 503
$ docker exec nautilus python -c "import os; os.chmod('/var/log/nautilus/audit.jsonl', 0o644)"
$ curl -s -w ' HTTP %{http_code}\n' localhost:8000/readyz
{"status":"ok"} HTTP 200
```

Readiness comes back on the next probe, with no restart. `deploy/README.md`
§11 is the full set: reading, listing, permissions and renaming inside an image
with no shell, and the two things — `chown` and installing anything — that
genuinely cannot be done from inside one.

So size the volume before you rely on it — and size it from the line rate
below, not from the request rate.

### How many lines a request writes

**Two, not one.** The broker writes the `request` entry, and — whenever
attestation is on — a second `attestation_emitted` entry carrying the same
`request_id`. Attestation is on by default: `attestation.enabled` defaults to
`true` and the broker generates a per-process Ed25519 key when
`attestation.private_key_path` is unset, so a `nautilus.yaml` with **no
`attestation:` stanza at all** still writes two lines per request.

Measured against a running broker with one `static` source, 23 identical
`POST /v1/request` calls, no `attestation:` stanza in the config:

```console
$ AUDIT=/var/lib/nautilus/audit.jsonl          # audit.path from nautilus.yaml
$ for i in $(seq 1 23); do
    curl -s -o /dev/null -X POST http://127.0.0.1:8000/v1/request \
      -H "X-API-Key: $NAUTILUS_API_KEY" -H 'Content-Type: application/json' \
      -d "{\"agent_id\":\"analyst\",\"intent\":\"show me orders number $i\"}"
  done
$ curl -s http://127.0.0.1:8000/metrics | grep '^nautilus_requests_total '
nautilus_requests_total 23.0
$ wc -l < "$AUDIT"
46
$ jq -r '.metadata.nautilus_audit_entry | fromjson | .event_type' "$AUDIT" \
    | sort | uniq -c
     23 attestation_emitted
     23 request
$ stat -c %s "$AUDIT"
121160
```

`nautilus_requests_total` is therefore **half** the audit line rate on a
default config. The same 23-call workload, against three configurations of
the same broker:

| Configuration | lines per request | file bytes for 23 requests | bytes per request |
|---|---|---|---|
| default — `attestation.enabled` unset or `true`, plain log | **2** | 121 160 | 5 268 |
| `attestation.enabled: false` | 1 | 64 971 | 2 825 |
| default + `audit.chained: true`, `checkpoint_interval: 10` | 2, plus one genesis line at first write and one checkpoint per 10 entries | 157 592 | 6 852 |

Where the bytes go on that workload: the `request` line is 3 758 B with
attestation on and 2 825 B with it off — the 933 B difference is the JWS the
entry stores in `attestation_token` — and the `attestation_emitted` line is a
flat 1 510 B. Chaining adds a 704 B signed envelope to every line (+27 %); the
genesis and checkpoint lines are 4 029 B of the 157 592 (2.6 %), so
`checkpoint_interval` barely moves the total.

Those byte figures are for *that* workload — one source, a 23-character
intent. The entry stores `raw_intent` verbatim and one `routing_decisions`
plus one `scope_constraints` element per source the router selected, so both
intent length and source fan-out move the number. Re-run the block
above against your own traffic before you size a volume or a `sizeLimit`; on
Kubernetes see [On Kubernetes](#on-kubernetes), where the audit `emptyDir` is
capped and disk pressure evicts the node's other pods.

Requests that never reach the broker write nothing. An unauthenticated
`POST /v1/request` answers `401`, appends 0 lines and does not increment
`nautilus_requests_total`; `GET /v1/sources`, `GET /v1/audit`, `/healthz`,
`/readyz` and `/metrics` append 0 lines. Every request the counter *does*
count writes the full pair — including one the router denied at every source
and one where it skipped every source.

Those last two were then sent to the same broker, taking `$AUDIT` to 25 pairs
and 50 lines. That 50-line file is what the rest of this section reads.

### The order the pair lands in

`attestation_emitted` is written **first**, then `request` — the attestation
is emitted inside the pipeline, the request entry after it returns. A tail
follower sees the attestation line for a request before it sees the request
itself:

```console
$ jq -r '.metadata.nautilus_audit_entry | fromjson | [.request_id, .event_type] | @tsv' "$AUDIT" \
    | awk '{a[$1]=a[$1] " " $2} END {for (k in a) print a[k]}' | sort | uniq -c
     25  attestation_emitted request
```

Correlate on `request_id`, not on adjacency, and do not read the first line of
a pair as the decision — the `attestation_emitted` entry carries
`agent_id: ""`, `raw_intent: ""` and empty `rule_trace`, `sources_queried`,
`sources_denied` and `sources_errored` by construction. Everything about what
was asked and what was allowed is on the `request` line.

### Query it over REST

```bash
curl -H "X-API-Key: $NAUTILUS_API_KEY" \
  "http://127.0.0.1:8000/v1/audit?agent_id=agent-alpha&limit=50&order=desc"
curl -H "X-API-Key: $NAUTILUS_API_KEY" \
  "http://127.0.0.1:8000/v1/audit/<request_id>"
```

Filters: `agent_id`, `source_id`, `event_type`, `start`/`end` (ISO-8601),
`cursor`, `limit` (≤ 500), `order=asc|desc`. The response carries
`next_cursor` for pagination.

`limit` counts audit *entries*, not requests, so on a default config it spans
half as many requests as its value suggests. `event_type` is applied before
`limit`, so filtering restores one row per request:

```console
$ curl -s -H "X-API-Key: $NAUTILUS_API_KEY" "http://127.0.0.1:8000/v1/audit?limit=50" \
    | jq -c '{n:(.entries|length), types:([.entries[].event_type]|unique)}'
{"n":46,"types":["attestation_emitted","request"]}
$ curl -s -H "X-API-Key: $NAUTILUS_API_KEY" "http://127.0.0.1:8000/v1/audit?limit=50&event_type=request" \
    | jq -c '{n:(.entries|length), types:([.entries[].event_type]|unique)}'
{"n":23,"types":["request"]}
```

`GET /v1/audit/{request_id}` needs no such filter: both entries of a pair
carry the same `request_id`, and the single-entry lookup answers with the
`request` one.

### The shape on disk

An on-disk line is **not** the object `/v1/audit` returns. It is a Fathom
`AuditRecord` envelope whose `metadata.nautilus_audit_entry` holds the
Nautilus entry **JSON-encoded as a string** — the entry is encoded twice, and
a parser that stops after the first decode sees none of its fields:

```console
$ head -1 "$AUDIT" | jq -c 'keys'
["asserted_facts","attestation_token","decision","duration_us","input_facts","match_evidence","metadata","modules_traversed","reason","rules_fired","session_id","timestamp"]
$ head -1 "$AUDIT" | jq '{decision, reason, rules_fired, metadata_type: (.metadata.nautilus_audit_entry|type)}'
{
  "decision": "skip",
  "reason": "queried=0 denied=0 skipped=0 errored=0",
  "rules_fired": [],
  "metadata_type": "string"
}
```

The twelve envelope fields, and what the broker puts in each:

| Envelope field | Type | What the broker writes |
|---|---|---|
| `timestamp` | string | Entry timestamp, ISO-8601 UTC with a literal `Z` suffix. Equal to the entry's own `timestamp`. |
| `session_id` | string | The entry's `session_id`, **or its `request_id`** when the request had no session. Never `null` — so this is not a usable "was there a session" test; read `session_id` inside the entry for that. |
| `input_facts` | `null` | Never set. |
| `modules_traversed` | array | Always `[]`. |
| `rules_fired` | array of string | The entry's `rule_trace`, verbatim. |
| `decision` | string | `allow`, `deny`, `error` or `skip` — a summary of the *source fan-out*, not the request's outcome. See below. |
| `reason` | string | `queried=N denied=N skipped=N errored=N` — the four counts `decision` was derived from. |
| `duration_us` | integer | The entry's `duration_ms` × 1000. Millisecond resolution widened to microseconds, not microsecond resolution. |
| `metadata` | object | Exactly one key, `nautilus_audit_entry`, whose value is a **JSON string** — 918–3 102 bytes on the workload above. |
| `asserted_facts` | `null` | Never set. |
| `match_evidence` | `null` | Never set. |
| `attestation_token` | `null` | Never set **here**. The signed token is inside the entry, at `metadata.nautilus_audit_entry.attestation_token`. |

The four always-`null` fields and the empty `modules_traversed` are Fathom
schema fields Nautilus does not use. Checked across every line of a 50-line
log — one distinct combination, so no line ever sets them:

```console
$ jq -s 'map({input_facts, asserted_facts, match_evidence, attestation_token, modules_traversed}) | unique' "$AUDIT"
[
  {
    "input_facts": null,
    "asserted_facts": null,
    "match_evidence": null,
    "attestation_token": null,
    "modules_traversed": []
  }
]
```

**The extraction, worked.** Reading the fields the REST projection documents
straight off a disk line finds nothing — no error, no warning, just `null`:

```console
$ head -2 "$AUDIT" | jq -c '{request_id, agent_id, rule_trace}'
{"request_id":null,"agent_id":null,"rule_trace":null}
{"request_id":null,"agent_id":null,"rule_trace":null}
```

Decode `metadata.nautilus_audit_entry` a second time and the entry appears:

```console
$ head -2 "$AUDIT" | jq -c '.metadata.nautilus_audit_entry | fromjson | {request_id, event_type, agent_id, rule_trace}'
{"request_id":"35a158d0-3a0b-4b3d-9546-4efdf696f687","event_type":"attestation_emitted","agent_id":"","rule_trace":[]}
{"request_id":"35a158d0-3a0b-4b3d-9546-4efdf696f687","event_type":"request","agent_id":"analyst","rule_trace":["nautilus-routing::match-sources-by-data-type"]}
```

`metadata.nautilus_audit_entry | fromjson` is the same object `GET /v1/audit`
returns in `entries[]` — the same 39 fields, no additions and no omissions.
Everything [the REST reference](../reference/rest-api.md) documents about an
audit entry applies to it unchanged.

### `decision` and `reason`

`decision` is a Fathom `AuditRecord` field, and the broker fills it with a
four-value summary of which bucket the request's sources ended up in:

| `decision` | Emitted when | Read it as |
|---|---|---|
| `allow` | `sources_queried` is non-empty | At least one source was queried. **Not** "everything succeeded": a request that queried one source and errored on another is `allow`. |
| `deny` | nothing queried, `sources_denied` non-empty | Every selected source was refused by policy. |
| `error` | nothing queried, nothing denied, `sources_errored` non-empty | Every source that was reached failed. |
| `skip` | none of the above | No source landed in any of those three buckets. Covers both a request whose sources were all *skipped* and every non-request event, which has no sources at all. |

`sources_skipped` never enters the test, so `skip` is the else-branch and not
a synonym for "nothing happened". Two different things land there, and
`reason` is what separates them — `skipped=1` on a request whose sources were
all skipped, `skipped=0` on an event:

```console
$ jq -r '[(.metadata.nautilus_audit_entry|fromjson|.event_type), .decision, .reason] | @tsv' "$AUDIT" | sort | uniq -c
     25 attestation_emitted	skip	queried=0 denied=0 skipped=0 errored=0
     23 request	allow	queried=1 denied=0 skipped=0 errored=0
      1 request	deny	queried=0 denied=1 skipped=0 errored=0
      1 request	skip	queried=0 denied=0 skipped=1 errored=0
```

and, on a second broker whose config adds one source that cannot be reached,
the two rows that show `decision` is a fan-out summary rather than an outcome
— `error` on a request where one source was skipped and one failed, `allow`
on a request that succeeded on one source and failed on another:

```console
$ jq -r 'select((.metadata.nautilus_audit_entry|fromjson|.event_type)=="request") | [.decision, .reason] | @tsv' /var/lib/nautilus/audit-2.jsonl
error	queried=0 denied=0 skipped=1 errored=1
allow	queried=1 denied=0 skipped=0 errored=1
```

`request` is the **only** one of the twenty-one `event_type` values that can
carry a `decision` other than `skip`. It is the only entry the broker builds
with the source buckets filled; every other event — `attestation_emitted`,
`handoff_declared`, `signing_key_rotated`, `proposal_validated`,
`rule_promoted`, all of them — is constructed with all four lists empty and so
lands as `skip` with `reason: queried=0 denied=0 skipped=0 errored=0`.

That is the field's meaning, not a bug, and it is why **`decision` is the
wrong field to alert on**. Alert on `event_type` inside the entry, which names
what actually happened; use `decision` as a cheap pre-filter and `reason` to
disambiguate it. `decision` is also load-bearing on disk under
`audit.chained` — it sits inside the signed payload of every chained line, as
the tamper check below shows — so treat its four values as a stable wire
vocabulary rather than something to re-map at the source.

Non-request events keep their detail in one of two places, depending on which
path wrote them:

| Producer | Where the detail is | Measured example |
|---|---|---|
| Broker lifecycle path — `attestation_emitted`, `signing_key_rotated`, `signing_key_revoked`, the session-token events | The entry's own fields; free-form markers go in `rule_trace`, which the envelope copies into `rules_fired` | `signing_key_rotated` → `rule_trace: ["reviewer=ops@example.com", "previous_kid=267b00a8-…", "new_kid=facbeccc-…"]` |
| Rule-knowledge-management emitter — `proposal_*`, `rule_promoted`, `rule_retracted`, `rule_rolled_back`, `meta_rule_fired`, `relationship_observed`, adapter and schema-drift events | `event_fields`, a free-form object, and `agent_id` is the literal string `"<broker>"` | `proposal_validated` → `event_fields: {"proposal_id": "prop_5e33…", "status": "rejected", "confidence": 0.9, "sandbox_error": "…"}` |

`agent_id` is `""` on an event with no agent behind it — measured on
`attestation_emitted` and on `signing_key_rotated` — so a non-empty `agent_id`
is not a usable "is this a real request" filter either. `event_type` is.

### Ship it to a collector

A shipper that indexes the raw line indexes `nautilus_audit_entry` as one
opaque 0.9–3.1 kB string, and every field an operator wants to search on is
inside it. Decode it once more before indexing. The envelope carries
nothing the entry does not — `timestamp`, `session_id`, `rules_fired` and
`duration_us` are all derivable from it, checked on every line of the file:

```console
$ jq -r '. as $o | ($o.metadata.nautilus_audit_entry|fromjson) as $e
  | [ ($o.timestamp    == $e.timestamp),
      ($o.session_id   == ($e.session_id // $e.request_id)),
      ($o.rules_fired  == $e.rule_trace),
      ($o.duration_us  == ($e.duration_ms * 1000)) ] | @tsv' "$AUDIT" | sort | uniq -c
     50 true	true	true	true
```

so the whole pre-parse is: keep the entry, drop the envelope.

```console
$ jq -c '.metadata.nautilus_audit_entry | fromjson' "$AUDIT" | head -1 | cut -c1-200
{"timestamp":"2026-09-01T15:56:31.760792Z","request_id":"35a158d0-3a0b-4b3d-9546-4efdf696f687","agent_id":"","principal_id":null,"session_id":null,"raw_intent":"","intent_analysis":null,"facts_asserte
```

One filter reads both a plain and a chained log and drops the lines that carry
no entry, so a `filebeat` / Vector / `fluent-bit` pipe does not change when you
turn chaining on:

```console
$ CHAIN=/var/lib/nautilus/audit-chained.jsonl
$ jq -c '(.record // .) | .metadata.nautilus_audit_entry? // empty | fromjson' "$AUDIT" | wc -l
50
$ jq -c '(.record // .) | .metadata.nautilus_audit_entry? // empty | fromjson' "$CHAIN" | wc -l
46
```

51 lines in that chained file, 46 entries: the genesis line and four
checkpoints carry no entry and `// empty` drops them.

If you parse in the shipper rather than in a pipe, the operation to configure
is a **second** JSON decode of the field `metadata.nautilus_audit_entry`
(under `record.metadata.nautilus_audit_entry` on a chained log) — Filebeat's
`decode_json_fields` processor, Splunk's `spath input=`, Vector's
`parse_json`. Those product configurations are not reproduced here because
they were not executed here; the field path is, and it is the part that is
easy to get wrong.

### Integrity: `audit.chained`

`audit.chained: true` upgrades the log to the same hash-chained, JWS-signed
format the attestation sink can use — every line commits to its predecessor,
so an edited or reordered entry is detectable offline instead of leaving no
trace:

```yaml
audit:
  path: /var/lib/nautilus/audit.jsonl
  chained: true
  checkpoint_interval: 100   # 0 = no checkpoints
```

It signs each line, so it requires `attestation.enabled` with a signing key
and is refused at startup without one. A chain is a total order: one writer
per file, exactly as for `attestation.sink`. Verify it offline with
`nautilus attestation verify <path>`, which reads `<path>.pub.pem` from beside
the log and runs `fathom.chained_log.verify_chain` over it — the admin
console's chain badge runs that same check, but over the chained
`attestation.sink` rather than this file. Checkpoints anchor the tail, which
is what makes a *truncation* — as opposed to an edit — detectable, so set
`checkpoint_interval` if that is part of your threat model.

**Chaining does not cost you this API.** A chained line is an envelope —
`{"v", "seq", "prev_sha256", "record", "jws", "iat"}` — with the plain line
above nested whole under `record`, one container deeper than an unchained log.
The reader unwraps it, so `GET /v1/audit`, `GET /v1/audit/{request_id}` and
the admin audit view answer from a chained log exactly as they do from a plain
one. One file gives you the browser and offline-verifiable integrity, from one
`/v1/request`:

```console
$ curl -s -H "X-API-Key: $NAUTILUS_API_KEY" "http://127.0.0.1:8000/v1/audit?limit=50" \
    | jq -c '{n: (.entries|length), first: .entries[0].event_type}'
{"n":2,"first":"request"}
$ nautilus attestation verify /var/lib/nautilus/audit.jsonl
OK: chain valid — 2 records, head b2f74121bb605dfaba94882e874dd6e48d8aaa6a295f52925c772d584fc97363
```

Two entries, two records — and three lines in the file, the third being the
genesis record. `verify` counts entries, not lines. Over the 23-request run
above, with `checkpoint_interval: 10`:

```console
$ wc -l < "$CHAIN"
51
$ jq -r '.record.type // (.record.metadata.nautilus_audit_entry|fromjson|.event_type)' "$CHAIN" \
    | sort | uniq -c
     23 attestation_emitted
      4 fathom.checkpoint
      1 fathom.genesis
     23 request
$ nautilus attestation verify "$CHAIN"
OK: chain valid — 46 records, head 2de841e4fdd6395a465ea5f362787a54f972562fab1dc44893dd5035dbf57c71
```

The signature commits to the whole `record` object, `decision` included, so an
edit anywhere in a line is caught with its line number and `verify` exits
**2**. Prove that on a copy before you rely on it in an audit — flipping one
`decision` from `skip` to `deny`:

```console
$ cp "$CHAIN" /tmp/tamper.jsonl && cp "$CHAIN".pub.pem /tmp/tamper.jsonl.pub.pem
$ python -c 'import json; L=open("/tmp/tamper.jsonl").read().splitlines(); o=json.loads(L[1]); o["record"]["decision"]="deny"; L[1]=json.dumps(o); open("/tmp/tamper.jsonl","w").write("\n".join(L)+"\n")'
$ nautilus attestation verify /tmp/tamper.jsonl; echo "exit=$?"
ERROR: attestation verify: signature claims mismatch at line 2: signed {'iss': 'fathom-chain', 'iat': 1788278328, 'seq': 1, 'prev_sha256': '66286a6324bba4851406cad9d6a1ba18725fa79e5531b0b6a3b1fda6a2313496', 'record_sha256': '91b528f315df8afc4745823999ec85ff89d5a83f0463c1fd97db8772ce828943', 'log_id': 'e93d019ff21a4da8b163ae99ce26164d', 'v': 1}, computed {'iss': 'fathom-chain', 'iat': 1788278328, 'seq': 1, 'prev_sha256': '66286a6324bba4851406cad9d6a1ba18725fa79e5531b0b6a3b1fda6a2313496', 'record_sha256': 'b521301bedd117419b6c82681ff0bf4fbbdfa4845413e34bd19f290f825ac5ba', 'log_id': 'e93d019ff21a4da8b163ae99ce26164d', 'v': 1}
exit=2
```

Those two shapes — the chain's genesis record and its periodic checkpoints —
carry no audit entry and are skipped without comment. So
`Skipping corrupt audit line:` in the broker's log still means what it says — a
line that could not be read — rather than being the normal noise of a chained
log.

### Backup

The audit file is append-only JSONL, so it is the one piece of durable state
that tolerates a copy from a running broker — rotate and archive it like any
log (`logrotate` with `copytruncate` disabled; a HUP is *not* needed since the
broker holds the path, so prefer copy-then-trim during a maintenance window,
or ship lines continuously with a follower like `filebeat`). It is not the
only durable state there is — see
[Back up and restore](#9-back-up-and-restore) for the full list and the
stop-archive-restore procedure.

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

With `audit.chained: true`, make that acknowledgement while the server is
down. `schema-ack` audits the override it records, a chained log admits one
writer, and the running broker holds it — so beside a live server the command
refuses with exit `2` and rewrites nothing, rather than accepting the drift
into a baseline the log has no line for. Stop the broker, run `schema-ack`,
start it again: the baseline is read back at startup and the quarantine lifts
with it. An unchained audit log has no such lock and no such restriction.

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

- **Which host is down is on the error record and in the log.** A failed
  source's `sources_errored[]` entry carries `endpoint` — the address that
  source dials, as `scheme://host[:port]` — and the same value is in the audit
  entry's `error_records[]` and in one `WARNING` on the `nautilus.core.broker`
  logger:

    ```text
    WARNING:nautilus.core.broker:source 'ledger' failed (endpoint=postgresql://127.0.0.1:15499, error_type=AdapterError, trace_id=b8f39914-…): PostgresAdapter: execute failed for source 'ledger': ConnectionRefusedError: [Errno 111] Connect call failed ('127.0.0.1', 15499)
    ```

    It is a `WARNING`, so it is on stdout at the default `--log-level info`
    and you do not have to raise verbosity to see *which* host failed.
    `--log-level debug` adds what happened before it — one
    `source '…' dialling <endpoint> via <Adapter>` line per source, and the
    address the SSRF guard resolved a name to — which is what you want when
    the failure is "why is this source being refused at all"
    ([What `--log-level debug` adds](#what-log-level-debug-adds)).
    `endpoint` is rebuilt from
    scheme, host and port only, so a DSN password or a URL token in
    `connection` is not in the log, the audit trail or the agent's response —
    which also means a `connection` with no host (a filesystem path, a libpq
    keyword DSN) has `endpoint: null` and nothing to show. Full field
    semantics: [the error reference](../reference/errors/adapters.md#endpoint-which-backend-this-was).
- **Unreachable sources are not re-dialled on every request.** A source whose
  `connect()` fails or times out is put in a 30-second cooldown; requests
  routed to it during that window are denied immediately with `connect()
  failed {n}s ago; not retried for another {m}s` rather than spending the
  source's `timeout_s` again — the *cooldown* message, not the original
  connect error, which is on the first failure's entry. The first request after
  the window retries, so a recovered source comes back on its own.
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

## 8. Check what you are about to deploy

### Rules

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

### The config

**A running broker re-reads `nautilus.yaml` on `SIGHUP`, and adopts two stanzas
out of thirteen.** `sources` and `rules` — plus `session_store.lock_timeout_s`
and `session_store.purpose_ttl_seconds`, the only two limits the request path
looks up per request. Everything else is read once, at startup, and a file that
changes one of them is **refused whole**: not half-applied, not silently
ignored. Which key, and why, is [the table below](#which-keys-reload-and-which-need-a-restart).

```bash
kill -HUP "$(pgrep -f 'nautilus serve')"          # or: systemctl reload nautilus
```

```text
INFO:nautilus.cli.serve:SIGHUP: reloaded /etc/nautilus/nautilus.yaml (adopted sources)
```

The reload validates before it swaps, through the same `broker_for_serve` that
`serve` runs before it binds and `config check` runs before a deploy, so a
config those two refuse is refused here **in the same sentence**. On a refusal
nothing moves: the running config keeps answering, the process does not exit,
and the refusal is on the audit log as a `config_reload_refused` entry whose
`raw_intent` is that sentence.

```text
ERROR:nautilus.cli.serve:SIGHUP: refused; the running config is unchanged. Reason: invalid config: classification labels are not levels of the 'classification' hierarchy (unclassified, cui, confidential, secret, top-secret): sources['tickets'].classification='internal'
```

A request already in flight finishes on the config it started with. It pins the
sources, the rules and the limits it began under, and the adapters and rule
engine it retires are closed only once nothing is still reading them — so a
`SIGHUP` landing between a caller's routing decision and its adapter fan-out
cannot change either.

Still check the file first — a refused reload is a reload you did not get, and
finding that out from the config file is cheaper than finding it out from the
log:

```bash
nautilus config check /etc/nautilus/nautilus.yaml && kill -HUP "$(pgrep -f 'nautilus serve')"
```

For a key that needs a restart, it is still the two-step operation it always
was:

```bash
nautilus config check /etc/nautilus/nautilus.yaml && systemctl restart nautilus
```

`config check` runs the exact sequence `serve` runs before it binds — the path
check, the `--air-gapped` pre-pass, and `Broker.from_config` — so it answers
one question, in `serve`'s own words: would a process come up on this file.

```text
OK: /etc/nautilus/nautilus.yaml — serve would start on this config
  bind:          127.0.0.1:8000   (api.host/api.port; serve --bind overrides)
  sources:       2 (tickets, orders)
  agents:        1 (agent-alpha)
  rules:         6 in force
  session store: memory
  audit log:     /etc/nautilus/audit.jsonl
```

Read the summary, not just the exit code. It is built from the broker the
check really constructed, so it is the deployment you are about to have: a
source you thought you added and do not see here is a source the next start
will not serve, and `agents: 0` means the next start takes every caller's word
for its own clearance ([2. Configure `nautilus.yaml`](#2-configure-nautilusyaml)).

A refused config exits **2** and prints what the startup log would have
printed:

```bash
nautilus config check /etc/nautilus/nautilus.yaml; echo "exit=$?"
```

```text
ERROR: invalid config: classification labels are not levels of the 'classification' hierarchy (unclassified, cui, confidential, secret, top-secret): sources['tickets'].classification='internal'
exit=2
```

#### Which keys reload, and which need a restart

Three stanzas swap. The other eleven do not, and each has a reason that is
about this product being **single-writer**, not about effort.

| Key | On `SIGHUP` | Why |
|---|---|---|
| `sources` | **reloads** | The registry and its adapters are rebuilt. A source whose entry is byte-identical keeps the adapter object it already connected — its pool, its connect cooldown, its `connected` state. A source that changed or vanished has its adapter closed, but only after every request still using it has finished. |
| `rules` | **reloads** | The whole Fathom router is rebuilt, so an edit *inside* a `user_rules_dirs` directory arrives even though the stanza itself did not change. `ruleset_hash` moves with it, and the `nautilus_ruleset_info` metric relabels. |
| `session_store.lock_timeout_s` | **reloads** | Read per request, out of the config object. Nothing holds a copy. |
| `session_store.purpose_ttl_seconds` | **reloads** | Same. |
| `audit.*` | restart | The sink is open, and with `audit.chained: true` it holds an exclusive `flock` on `<path>.lock`. Re-pointing it live would mean two chain heads on one file, which is the corruption `verify_chain` cannot distinguish from tampering. |
| `attestation.*` | restart | Same lock, on the attestation sink, plus a signing key the chain's genesis record is pinned to. |
| `session_tokens.*` | restart | The key ring is in memory and already minting tokens. Swapping it invalidates every token in flight; changing `broker_instance_id` rejects them all by name. |
| `session_store.*` (the rest) | restart | `backend`, `dsn`, `sqlite_path`, `ttl_seconds` and the pool sizes are constructor arguments to a store object that is already dialled. Adopting them would publish a config describing a store the broker is not running. |
| `api.*` | restart | `max_request_bytes` and `max_concurrent_requests` are middleware *objects* installed when the ASGI app is built — the concurrency limit is a semaphore sized once, not a value anything looks up again. `api.keys`, `api.auth` and the agent subjects are copied to `app.state` at lifespan startup. `host`/`port` are a socket that is already bound. |
| `mcp.*` | restart | Read once into the tool closures when the MCP server is created. |
| `ui.*` | restart | `ui.enabled` decides whether the admin router is mounted, at app construction. |
| `agents` | restart | The broker would take the new registry, but the transport's `app.state.agent_subjects` — what maps a credential to an agent — would not, and the two disagreeing is worse than neither moving. |
| `analysis` | restart | Adopted implicitly *only* as far as the keyword map, which is generated from `sources`. The stanza itself is held to its startup value because `analysis.provider` reads a credential out of the process environment, and rotating the broker's outbound identity with no process boundary is the same class of change as rotating the key ring. |
| `adapters` | restart | Local adapter code is imported from disk into this process; a reload cannot un-import the old module. |
| `state_dir`, `rkm` | restart | The schema-fingerprint store and the RKM queue are built against them at startup. |

Two things a reload deliberately does **not** clear: the schema-drift
quarantine and the fingerprint baselines. Both are keyed by source id and both
are the record of a drift an operator has to acknowledge — re-pointing a source
at another table must not be a way around `nautilus adapters schema-ack`.

Validating a candidate config has the same side effects `nautilus config check`
has, because it is the same call: a new `audit.path` is created if it does not
exist, even when the reload is then refused.

Same message, same exit code, no restart — that is the whole point of the
command, and it is why the check calls `serve`'s loader instead of
reimplementing it. The `&&` above is the safety property: the restart does not
run.

### What a check cannot tell you

`config check` stops where `serve` stops before it binds. It does **not** call
`Broker.setup()` — the async half of a start, where a Postgres or SQLite
session store stands up its schema — so a config naming an unreachable
`fail_closed` session store passes the check and still kills the process at
startup:

```text
OK: nautilus.yaml — serve would start on this config
  ...
  session store: postgres
```

```text
nautilus.core.session_pg.SessionStoreUnavailableError: PostgresSessionStore unavailable (dsn=postgresql://127.0.0.1:5599): [Errno 111] Connect call failed ('127.0.0.1', 5599)
ERROR:    Application startup failed. Exiting.
ERROR: application startup failed; the server never accepted a connection. The cause is logged above.
```

That failure is not about the file — the same file is correct against a
reachable database — so it belongs to the readiness gate, not to the check.
`serve` exits 2 on it, `/readyz` never turns green, and the rollout below is
what catches it.

What the file *does* decide on its own is settled by the check, and that
includes more than validation: because the broker opens `audit.path` while it
is being constructed, an audit directory this process cannot write to is
refused here, with `ERROR: broker construction failed: [Errno 13] Permission
denied: …` and exit 2 — the same failure the pod would have had, on the
machine where you can still fix it.

The other side of that: opening the file is a side effect. Constructing a
broker creates the audit log's parent directory and opens `audit.path`, so
checking a config in a directory that has never served leaves an empty
`audit.jsonl` beside it. It writes no entries.

### Roll the restart

The refusal is only free if the process that refuses is not the only one
serving. `serve` exits **2** without ever binding a socket when it refuses a
config, so the new process never takes the port and never answers a request —
which means a deployment that starts the new process *before* retiring the old
one loses nothing when the config is bad:

```bash
# old broker serving on :8801, new one brought up on :8802
nautilus serve --config /etc/nautilus/nautilus.yaml --bind 127.0.0.1:8802 &
until nautilus health --url http://127.0.0.1:8802/readyz; do sleep 1; done
kill -TERM "$OLD_PID"        # only after the new one is ready
```

With a bad config the `until` loop never exits — `:8802` refuses connections
because nothing is listening there — so the `kill` never runs and the old
broker on `:8801` is still answering `/readyz` with 200, untouched. (Bound
that loop with a timeout in anything unattended; as written it waits forever,
which is the safe direction but not a finished script.) With a good config the new process is ready before the old one
is asked to stop, and the port the load balancer is pointed at never goes
quiet. Behind one address, that is blue/green or a `RollingUpdate` with
`maxUnavailable: 0`; the mechanism that matters is the ordering, not the tool.

**The manifests in `deploy/` do not have that ordering.** They ship
`replicas: 1` and `strategy: Recreate` — deliberately, because two brokers
sharing one key ring and one `ReadWriteOnce` audit volume is worse than a gap
(see [Running more than one replica](#running-more-than-one-replica)) — and
`Recreate` terminates the old pod *before* the new one starts. There, a config
the new pod refuses is not a safe abort: it is `CrashLoopBackOff` with nothing
serving until you fix the file. On that deployment shape `config check` is not
a convenience, it is the only thing standing between a typo and an outage —
run it on the `nautilus.yaml` you are about to paste into
`deploy/configmap.yaml`, not after.

## 9. Back up and restore

There is no backup command, no snapshot endpoint, and no incremental or
point-in-time restore. Nautilus keeps its durable state as ordinary files in
one directory (plus, optionally, a Postgres database it does not own), so the
whole procedure is: **stop the process, archive the directory, and put it
back**. That is the honest shape of it, and the rest of this section is the
file list, the one ordering constraint that will bite you, and the commands
that prove a restore worked.

### What is durable

Every path below is resolved **relative to the config file's own directory**
unless it is absolute (see [Relative paths](#relative-paths)) — with one
exception, called out in the table.

| Thing | Where | Set by | Lose it and… |
|---|---|---|---|
| Decision record | `audit.jsonl` | `audit.path` | The compliance trail is gone. Nothing else breaks; the broker starts a new file. |
| Audit chain public key | `audit.jsonl.pub.pem` | derived — written beside `audit.path` | Recoverable, not critical: delete it and the next broker start re-exports a byte-identical file from the private key. It is in the archive so a third party can verify the log offline without ever touching the key. |
| Attestation signing key | `attestation.pem` | `attestation.private_key_path` | **Every chained log signed with it becomes unappendable.** See [the ordering constraint](#restore-the-key-with-the-log-not-after-it). |
| Attestation envelopes | e.g. `attestations.jsonl` (+ `.pub.pem`) | `attestation.sink.path`, when `type: file` | The independent receipt trail is gone. |
| Session-token signing ring | `keyring.json` | `session_tokens.key_ring_path` | Every outstanding session token fails with `unknown_kid` — a forced logout, not corruption. Only exists if you set the path; otherwise the ring is in-process and there is nothing to back up. |
| Exposure ledger (SQLite) | `sessions.db` | `session_store.sqlite_path` | Cumulative-exposure counts reset to empty, so escalation rules stop firing until callers re-accumulate. |
| Exposure ledger (Postgres) | tables `nautilus_session_state` and `nautilus_schema_version` in the database at `session_store.dsn` | — | As above. This is an ordinary Postgres database Nautilus does not own: back it up with `pg_dump` on your existing schedule, and restore it before the broker starts. |
| Adapter schema baselines | `<state_dir>/.nautilus/adapters/fingerprints/*.json` | `state_dir` | Every source re-baselines on first connect, which means a drift that was already there is silently accepted as the new normal. Quarantine itself is in-memory and re-derived from these files. |
| Rule review queue and lineage | `.nautilus/rkm/queue/`, `.nautilus/rkm/lineage/` | **not configurable** — always relative to the broker's *working directory* | Pending proposals and promoted-rule history are gone. |
| Your own rule files | whatever `rules.user_rules_dirs` lists | `rules.user_rules_dirs` | `POST /v1/rules/{name}/retract` rewrites these files, so they are state, not just input. |
| The config, and the secrets it interpolates | `nautilus.yaml` | — | Everything. `${VAR}` references are resolved from the environment at load; the file records *which* variables, not their values. |

The RKM row is the one that surprises people: those two directories are **not**
under `state_dir` and **not** next to the config file. Give the broker a
working directory equal to its state directory and the problem goes away —
`WorkingDirectory=/var/lib/nautilus` in the unit file, or a `workingDir` on the
container — after which one archive covers everything.

If you have not set `attestation.private_key_path` yet, there is nothing in
that row to back up — the broker mints a throwaway keypair per process, and a
restart already invalidates every token it signed. Generating a persistent one
is a single command; Nautilus reads a standard PKCS#8 Ed25519 PEM:

```console
$ openssl genpkey -algorithm ed25519 -out "$STATE/attestation.pem" && chmod 600 "$STATE/attestation.pem"
$ ls -l "$STATE/attestation.pem" | awk '{print $1, $NF}'
-rw------- /var/lib/nautilus/attestation.pem
```

Nothing else needs backing up. `session_store.backend: memory`, the in-process
key ring when `key_ring_path` is unset, MCP transport sessions, and the
connect-failure cooldowns are all deliberately per-process and are meant to be
lost on restart.

### Back up

Stop first. This is not paranoia about a torn tarball: `sessions.db` is
SQLite in WAL mode, so while the broker runs there is a `sessions.db-wal`
holding committed transactions that are not yet in the main file, and copying
`sessions.db` alone gives you a database missing its most recent writes.
A clean shutdown checkpoints and removes the `-wal`, which is why it is absent
from the archive listing below.

```bash
export CONFIG=/etc/nautilus/nautilus.yaml
export STATE=/var/lib/nautilus          # state_dir, and the broker's cwd
export BACKUP=/srv/backups/nautilus

systemctl stop nautilus

tar -C "$(dirname "$STATE")" --exclude='*.lock' \
    -czf "$BACKUP/nautilus-$(date -u +%Y%m%dT%H%M%SZ).tgz" "$(basename "$STATE")"
cp "$CONFIG" "$BACKUP/"

systemctl start nautilus
```

**This runs where the files are, not inside the container.** On the container
path that is the host directory you bind-mounted (`/srv/nautilus/state` in
`deploy/README.md` §2.1) with the container stopped — `tar` is not in the
runtime image and neither is a shell to run it from. On Kubernetes there is no
host directory: with the shipped `emptyDir` volumes, scaling the Deployment to
zero **destroys the state you were trying to back up**, so move `state` to a
PersistentVolumeClaim first and then either mount that PVC into a short-lived
`busybox` Job that writes the archive, or run a volume snapshot. Streaming the
files out through `kubectl exec` works for a single file
(`deploy/README.md` §11.3) but not for a consistent directory archive, and
`kubectl cp` fails outright because it needs `tar` in the target container.

The `--exclude='*.lock'` matters. `audit.jsonl.lock` and
`.nautilus/rkm/queue/.lock` are the `flock` files that enforce one-writer-per
chained-log and one-writer-per-queue. They carry no data, and restoring a
stale one onto a live host is a way to confuse yourself, not a way to lose
data.

What is on disk before the archive, and what comes out of it — a broker with a
chained audit log, a SQLite session store, a persisted key ring and one
connected source:

```console
$ ls -A "$STATE"
.nautilus
attestation.pem
audit.jsonl
audit.jsonl.lock
audit.jsonl.pub.pem
keyring.json
keyring.json.lock
sessions.db
$ tar tzf /srv/backups/nautilus/nautilus-20260901T112616Z.tgz
nautilus/
nautilus/keyring.json
nautilus/.nautilus/
nautilus/.nautilus/adapters/
nautilus/.nautilus/adapters/fingerprints/
nautilus/.nautilus/adapters/fingerprints/orders.json
nautilus/audit.jsonl.pub.pem
nautilus/sessions.db
nautilus/attestation.pem
nautilus/audit.jsonl
```

Note what is *not* there: no `sessions.db-wal` and no `sessions.db-shm`. The
clean shutdown checkpointed them into `sessions.db`. If you see those two in
an archive, it was taken from a running broker and the database in it is a
torn copy.

**The archive contains a private key.** `attestation.pem` and `keyring.json`
are both key material, so the archive is as sensitive as the broker's own
secrets — encrypt it at rest and give it the same access control as
`/etc/nautilus`.

If you cannot take an outage, the one piece that tolerates a hot copy is the
audit log: it is append-only, so `cp` gives you a valid prefix, and a partial
final line is the worst case. Use `logrotate` with `copytruncate` **disabled**
and copy-then-trim in a maintenance window, or ship lines continuously with a
follower like `filebeat`. Everything else in the table wants the process
stopped.

### Restore

```bash
systemctl stop nautilus                  # if anything is running
rm -rf "$STATE"                          # a restore replaces, it does not merge
tar -C "$(dirname "$STATE")" -xzf "$BACKUP/nautilus-20260901T112616Z.tgz"
chmod 600 "$STATE/attestation.pem" "$STATE/keyring.json"
systemctl start nautilus
```

`tar` restores the file modes it recorded, but the `chmod` is not
superstition: an archive unpacked as a different user, or copied through a
tool that normalises permissions, will hand you a world-readable
`attestation.pem`. Both files are private keys.

`rm -rf` rather than extracting over the top is deliberate: `tar` will not
remove a file the archive lacks, so an in-place extract leaves yesterday's
fingerprints and yesterday's proposals mixed in with today's, and the
adapter-drift check then compares against a baseline that never existed. There
is no merge mode and no partial restore — the directory is the unit.

For a Postgres session store, restore the database with your Postgres tooling
**before** starting the broker. It refuses to start against a schema version
it does not understand rather than migrating anything, so a mismatched restore
fails at startup with a readable error instead of corrupting rows.

### Verify the restore

Four checks, none of which need a client. Run them against the restored state
directory; the outputs below are from a real stop-destroy-restore cycle.

```console
$ nautilus attestation verify "$STATE/audit.jsonl"
OK: chain valid — 9 records, head b9a0e5c3a31ba8de690729cbf2c706f414200ad8445cc9b8c9270b027596af67
$ curl -s http://127.0.0.1:8000/v1/keys/jwks.json
{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"4bac7e75-ea87-4905-80eb-42ab20c6d755","x":"ODvf1pTI9fD6iUTsfiV5htfLCX3IZvp3C_WBnXh_oLE","use":"sig"}]}
$ nautilus session version --sqlite-path "$STATE/sessions.db"
store schema version: 1
this build understands: 1
$ nautilus adapters schema-diff orders --config "$CONFIG"
OK: no drift for 'orders' (fingerprint matches)
```

Read them as: the audit chain is intact and its **head hash is byte-identical
to the one recorded before the backup** — that is the check that proves the
trail survived, and it is worth writing the head down when you take the
backup. The `kid` is the one that was live before the restore, so the key ring
came back and outstanding session tokens still verify — a fresh ring would
show a new random `kid`. The session store carries a schema this build reads.
The adapter baseline is the one that was captured, so a source that was
already drifting still reports as drifting rather than being silently
re-baselined.

Then prove it is live, and that the chain still accepts appends:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_API_KEY" -H 'Content-Type: application/json' \
    -d '{"agent_id":"analyst","intent":"orders please","context":{"purpose":"analytics"}}'
200
$ nautilus attestation verify "$STATE/audit.jsonl"
OK: chain valid — 12 records, head 1f1eb2410e804b6d36245ee8fe80a94bc37bbf9457c95cb22f8879580e772b8e
```

The record count grew and the head moved: the restored chain is not a
read-only artefact, it is the live log again.

**Governance writes are in the chain too**, so that first check covers them.
`POST /v1/rkm/queue` records `proposal_emitted` and `proposal_validated`
through the broker's own audit logger rather than a sink of its own, which
means a rule submission moves the head like any other write and leaves the log
verifiable:

```console
$ nautilus attestation verify "$STATE/audit.jsonl"
OK: chain valid — 4 records, head 8b7df8593f68f34fc919c7c312dc324a5245f80af6765fc10dd320bd24dc97e8
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8000/v1/rkm/queue \
    -H "X-API-Key: $NAUTILUS_API_KEY" -H 'Content-Type: application/json' \
    -d "{\"rule_yaml\": $(jq -Rs . < proposed-rule.yaml)}"
201
$ nautilus attestation verify "$STATE/audit.jsonl"
OK: chain valid — 6 records, head 5653557bf8de8474498a1ff94d423876728b1d3f5ff42b53010c0ab894752a6b
```

The same holds for the CLI's governance decisions — `rule retract`,
`rule rollback`, `rkm queue submit`, `rkm queue reject` — which write through
the configured sink rather than opening a plain one. What they cannot do is
write while a server holds the chain's single writer lock; see
[`ERROR: this decision cannot be recorded, so it will not be taken`](../reference/errors/cli.md#error-this-decision-cannot-be-recorded-so-it-will-not-be-taken-problem).

### Restore the key with the log, not after it

A chained log pins the fingerprint of the key that opened it, in its genesis
record. Restore `audit.jsonl` next to a *different* `attestation.pem` — a key
that was regenerated because the old one was not in the backup — and the
broker starts, passes its readiness probe, and then fails **every request**:

```console
$ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/readyz
200
$ curl -s -X POST http://127.0.0.1:8000/v1/request -H "X-API-Key: $NAUTILUS_API_KEY" ...
Internal Server Error
```

The reason is only in the broker's log, not in the response:

```text
fathom.errors.AttestationError: chained log /var/lib/nautilus/audit.jsonl is corrupt; refusing append: signing key fingerprint 7e3297e543ef8f4d1227aa1a5dde42e755a1e5eb6109045526baf0fc0130e71e does not match log genesis key fingerprint 555933b595e027c61b025df81bf15c149f00ba064f44d92f29ae3eca92fc57e0
```

`/readyz` does not cover this — it checks that the audit sink is *writable*,
and the refusal happens later, at append time, so the replica joins the
Service and then fails everything. Put the matching `attestation.pem` back
and the next request is a `200` again; the chain resumes where it stopped:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8000/v1/request ...
200
$ nautilus attestation verify "$STATE/audit.jsonl"
OK: chain valid — 15 records, head 910b60b0ad7516a11730466d3a6416ad977a283c05fafe1438f8985df3fb6769
```

If the key is genuinely lost, that log can never be appended to again and its
signatures can never be checked: move it aside as a dead archive and let the
broker open a new chain with a new key. Nothing recovers it — which is why
`attestation.pem` is the one row in the table above set in bold.

Run the whole cycle — stop, archive, destroy, restore, verify — against a
staging copy before you need it. A backup nobody has restored is a file, not
a backup.
