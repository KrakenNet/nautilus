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
