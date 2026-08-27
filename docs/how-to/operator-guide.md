# Operator Guide

End-to-end walkthrough for deploying Nautilus: install, configure,
serve, monitor, rotate keys, and back up the audit trail.

## 1. Install

Requires Python 3.14+.

```bash
uv add nautilus-rkm
# or, in a service checkout:
uv sync
```

Verify:

```bash
nautilus version
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
```

When enabled, the first request in a session mints an EdDSA JWS bound to
the broker instance; subsequent requests present it via
`context["session_token"]` or the `X-Nautilus-Session-Token` header (a
present-but-invalid header is a 401). A valid token's `session_id` claim
overrides the caller-declared session id. Verification is fail-closed.
Session tokens are not what protects the exposure ledger — omitting one is
always allowed — the per-caller principal above is.

### Relative paths

Every path in `nautilus.yaml` — `audit.path`, `attestation.private_key_path`
and its sink paths, `rules.user_rules_dirs` — resolves **relative to the
config file's own directory**, not to the process working directory. So
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

- `GET /healthz` — liveness; `GET /readyz` — readiness (verifies the
  session store responds).
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

## 8. Validate rules before deploying

```bash
nautilus rules validate my-rules.yaml
nautilus rules test --file my-rules.yaml --audit-log /var/lib/nautilus/audit.jsonl
```

See the [rule-authoring guide](authoring-rules.md) for the full workflow,
including shadow detection and sandbox replay against production audit
history.
