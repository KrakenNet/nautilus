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
  port: 8080
  keys: ["${NAUTILUS_API_KEY}"]   # enables X-API-Key auth on the REST surface
```

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
  on_failure: fallback_sqlite   # fail_closed | fallback_memory | fallback_sqlite
  sqlite_path: /var/lib/nautilus/sessions.db
```

- `memory` — single process, lost on restart. Fine for dev.
- `sqlite` — durable single-node deployments with no Postgres.
- `postgres` — multi-node or existing PG infrastructure.
- `on_failure: fallback_sqlite` degrades to SQLite if Postgres is
  unreachable at startup; sessions survive a broker restart and the
  audit trail records `session_store_mode: degraded_sqlite`.

### Session tokens (optional)

```yaml
session_tokens:
  enabled: true
  ttl_seconds: 3600
```

When enabled, the first request in a session mints an EdDSA JWS bound to
the broker instance; subsequent requests present it via
`context["session_token"]`. A valid token's `session_id` claim overrides
the caller-declared session id, so the exposure ledger cannot be reset by
declaring a fresh session. Verification is fail-closed.

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
`GET /v1/keys/jwks.json`. Rotation is zero-downtime:

```bash
# Mint a new primary; the old key enters a grace window
nautilus key rotate --yes

# In-flight tokens keep verifying during grace and are lazily re-signed
# under the new kid (original expiry preserved — rotation never extends
# a session). When ready, end the grace window:
nautilus key revoke <old-kid> --reason "scheduled rotation" --yes

nautilus key list --json
```

Against a live broker, `POST /v1/keys/rotate` and
`POST /v1/keys/{kid}/revoke` do the same over REST (auth-gated; reviewer
identity via the `X-Nautilus-Reviewer` header). Revoking the current
primary is refused — rotate first, then revoke. Every rotation/revocation
emits a `signing_key_rotated`/`signing_key_revoked` audit event.

The *attestation* key (which signs per-request attestation tokens) is
separate: set `attestation.private_key_path` to persist it across
restarts, or omit it to auto-generate per process — see
[Configure attestation](configure-attestation.md).

## 7. Manage adapters and schema drift

```bash
nautilus adapters list --status quarantined
nautilus adapters schema <source-id> --json
nautilus adapters schema-diff <source-id>
nautilus adapters schema-ack <source-id> --reason "intentional migration" --yes
```

The broker fingerprints each adapter's schema; unexpected drift
quarantines the source (it stops receiving routed requests) until an
operator acknowledges the change with `schema-ack`.

## 8. Validate rules before deploying

```bash
nautilus rules validate my-rules.yaml
nautilus rules test --file my-rules.yaml --audit-log /var/lib/nautilus/audit.jsonl
```

See the [rule-authoring guide](authoring-rules.md) for the full workflow,
including shadow detection and sandbox replay against production audit
history.
