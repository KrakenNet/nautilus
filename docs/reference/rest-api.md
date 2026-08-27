# REST API

Nautilus exposes a FastAPI application via `nautilus serve --transport rest`.

## Endpoints

### `POST /v1/request`

Submit a broker request.

**Request body:**

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | `string` | The requesting agent's identifier |
| `intent` | `string` | Natural-language intent describing what data is needed |
| `context` | `object` | Agent context: `clearance`, `purpose`, `session_id`, optional `embedding` |

**Response:** `BrokerResponse` JSON with `request_id`, `data`, `sources_queried`,
`sources_denied`, `attestation_token`, and `duration_ms`.

### `GET /v1/sources`

List all configured sources (no authentication required).

### `GET /healthz`

Liveness probe. Returns `200 OK`.

### `GET /readyz`

Readiness probe. Returns `200 OK` when the broker is fully initialized.

## Authentication

Set `api.keys` in `nautilus.yaml` to require `X-API-Key` header authentication.
Every `/v1` route requires a credential except `GET /v1/keys/jwks.json`, which a
verifier needs before it has one.

A key may be a bare string or a bound entry:

```yaml
api:
  keys:
    - ${DEV_KEY}              # bare: any agent_id, every capability
    - key: ${ANALYST_KEY}
      agent_id: analyst       # this key may only ask as 'analyst'
      capabilities: [query]
```

A bound key that asks as another agent gets `403`. Capabilities gate the routes:

| Capability | Routes |
| --- | --- |
| `query` | `/v1/request`, `/v1/query`, `/v1/sources`, `/v1/adapters*`, `/v1/sessions` |
| `audit_read` | `/v1/audit`, `/v1/audit/{request_id}` |
| `govern` | `/v1/rkm/*`, `/v1/rules/*` |
| `keys` | `/v1/keys/rotate`, `/v1/keys/{kid}/revoke` |

A bound credential is also the reviewer recorded on `/v1/rkm/queue/{id}/approve`
and `/reject`; `X-Nautilus-Reviewer` stays required only for bare keys, which
have no bound identity to derive one from.
