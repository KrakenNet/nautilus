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

List all configured sources. Requires the `query` capability.

### `GET /v1/rules`

The rules the running engine will fire, and the ruleset they came from:

```json
{
  "ruleset_hash": "sha256:…",
  "rules": [{"module": "nautilus-routing", "name": "default-classification-deny"}]
}
```

Built-ins, user rules and pack rules alike. `ruleset_hash` is the same value
every audit entry records, so a deployment can be compared against the policy
it is believed to run and against the entries it produced. Requires the
`query` capability.

### `POST /v1/rules/{rule_name}/retract`

Retracts a rule. Alongside the lineage fields the response says what happened
to the *running* engine:

| Field | Meaning |
| --- | --- |
| `engine_updated` | `true` when the rule was in force and is no longer. `false` means it was never loaded, so only the lineage record changed. |
| `engine_note` | Whether the rule's YAML was also removed from `rules.user_rules_dirs`. A built-in or pack rule comes back at the next restart unless the pack or built-in goes too. |

### `POST /v1/rules/{rule_name}/rollback`

Re-promotes a prior lineage version. A lineage record carries no rule text, so
this never reloads anything: the response returns `engine_updated: false` and
an `engine_note` naming what still has to happen for the restored version to
decide requests.

### `GET /healthz`

Liveness probe. Returns `200 OK`.

### `GET /readyz`

Readiness probe. Returns `200 OK` when the broker is fully initialized, the
audit sink is writable, and the session store answers. `503` otherwise — the
`reason` field names which one failed.

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
| `query` | `/v1/request`, `/v1/query`, `/v1/sources`, `/v1/rules`, `/v1/adapters*`, `/v1/sessions` |
| `audit_read` | `/v1/audit`, `/v1/audit/{request_id}` |
| `govern` | `/v1/rkm/*`, `/v1/rules/{name}/*` |
| `keys` | `/v1/keys/rotate`, `/v1/keys/{kid}/revoke` |

A bound credential is also the reviewer recorded on `/v1/rkm/queue/{id}/approve`
and `/reject`; `X-Nautilus-Reviewer` stays required only for bare keys, which
have no bound identity to derive one from.
