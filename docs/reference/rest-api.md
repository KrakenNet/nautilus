# REST API

Nautilus exposes a FastAPI application via `nautilus serve --transport rest`
(`nautilus/transport/fastapi_app.py`, factory `create_app`). This page documents
every route the app registers.

- **Base URL** — `http://127.0.0.1:8000`. `nautilus serve` binds `--bind
  HOST:PORT`, else `api.host` / `api.port` from the config, else
  `127.0.0.1:8000` (`nautilus/cli/serve.py`, `_DEFAULT_BIND`).
- **Auth header** — `X-API-Key` (`nautilus/transport/auth.py`,
  `api_key_header`). Under `api.auth.mode: proxy_trust` it is `X-Forwarded-User`
  from a peer in `api.auth.trusted_proxies` instead.
- **Content type** — every `/v1` body is `application/json`. `/admin/login` and
  `/admin/attestation/verify` take `application/x-www-form-urlencoded`.
- **The `/admin` console is off by default.** Its routes are registered only
  when `ui.enabled: true`; otherwise they 404 (`create_app`, `if ui_enabled:`).

## Contents

| Group | Routes |
| --- | --- |
| [Broker](#broker) | `POST /v1/request` · `POST /v1/query` · `GET /v1/sources` |
| [Session tokens and signing keys](#session-tokens-and-signing-keys) | `POST /v1/sessions` · `GET /v1/keys/jwks.json` · `POST /v1/keys/rotate` · `POST /v1/keys/{kid}/revoke` |
| [Adapters](#adapters) | `GET /v1/adapters` · `GET /v1/adapters/{name}/schema` |
| [Rules](#rules) | `GET /v1/rules` · `GET /v1/rules/{rule_name}/lineage` · `POST /v1/rules/{rule_name}/retract` · `POST /v1/rules/{rule_name}/rollback` |
| [RKM review queue](#rkm-review-queue) | `POST /v1/rkm/queue` · `GET /v1/rkm/queue` · `GET /v1/rkm/queue/{proposal_id}` · `POST /v1/rkm/queue/{proposal_id}/approve` · `POST /v1/rkm/queue/{proposal_id}/reject` |
| [Audit](#audit) | `GET /v1/audit` · `GET /v1/audit/{request_id}` |
| [Probes, metrics, root](#probes-metrics-root) | `GET /healthz` · `GET /readyz` · `GET /metrics` · `GET /` |
| [OpenAPI](#openapi) | `GET /openapi.json` · `GET /docs` · `GET /docs/oauth2-redirect` · `GET /redoc` |
| [Admin console](#admin-console) | `GET /admin/` · `GET /admin/login` · `POST /admin/login` · `GET /admin/logout` · `GET /admin/playground` · `POST /admin/api/query` · `GET /admin/sources` · `GET /admin/sources/events` · `GET /admin/decisions` · `GET /admin/decisions/{request_id}` · `GET /admin/audit` · `GET /admin/attestation` · `POST /admin/attestation/verify` · `GET /admin/static/{path}` |

## Running the examples

Every example below runs against this broker. It needs no database: `type:
static` serves rows declared in the config (`nautilus/adapters/static.py`).

```bash
mkdir -p /tmp/nautilus-api && cd /tmp/nautilus-api && mkdir -p userrules
cat > nautilus.yaml <<'YAML'
sources:
  - id: orders
    type: static
    description: "Order history"
    classification: unclassified
    data_types: [orders]
    allowed_purposes: [fraud-review]
    rows:
      - {order_id: 1001, user_id: 42, total: 19.99}
      - {order_id: 1002, user_id: 43, total: 5.00}

agents:
  analyst:
    id: analyst
    clearance: unclassified
    compartments: []
    default_purpose: fraud-review
    allowed_purposes: [fraud-review]

rules:
  user_rules_dirs: [./userrules]

analysis:
  mode: pattern
  keyword_map:
    orders: [order, orders, purchase]

audit:
  path: ./audit.jsonl

session_tokens:
  enabled: true

attestation:
  enabled: true

api:
  keys:
    - my-secret-key
    - key: reader-key
      agent_id: analyst
      capabilities: [audit_read]

ui:
  enabled: true
YAML
nautilus serve --config nautilus.yaml --transport rest --bind 127.0.0.1:8000
```

In a second shell, export the two values every `curl` below uses:

```bash
export NAUTILUS=http://127.0.0.1:8000
export KEY=my-secret-key
```

`rules.user_rules_dirs` is set because `POST /v1/rkm/queue/{id}/approve` refuses
to promote a rule with nowhere to persist it — see that route's errors.
`session_tokens.enabled: true` is set because `POST /v1/keys/rotate` and
`POST /v1/keys/{kid}/revoke` answer `409` without it.

## Authentication

`api.keys` in `nautilus.yaml` is the allow-list. A key may be a bare string or a
bound entry:

```yaml
api:
  keys:
    - my-secret-key           # bare: any agent_id, every capability
    - key: reader-key
      agent_id: analyst       # this key may only ask as 'analyst'
      capabilities: [audit_read]
```

An **empty** `api.keys` fails closed: every authenticated route answers `401
API key required` rather than letting everyone in (`verify_api_key`).

A bare-string key names no agent, so it holds every capability and may ask as
any `agent_id`. A bound key that asks as another agent gets `403` naming both
ids. `capabilities` gates routes:

| Capability | Enforced on |
| --- | --- |
| `query` | `/v1/request`, `/v1/query`, `/v1/sources`, `/v1/rules`, `/v1/adapters`, `/v1/adapters/{name}/schema`, `/v1/sessions`, `/admin/playground`, `/admin/api/query`, `/admin/sources` |
| `audit_read` | `/v1/audit`, `/v1/audit/{request_id}`, `/admin/audit`, `/admin/decisions`, `/admin/decisions/{request_id}`, `/admin/attestation`, `/admin/attestation/verify` |
| `govern` | `/v1/rkm/queue` (both methods), `/v1/rkm/queue/{proposal_id}`, `/v1/rkm/queue/{proposal_id}/approve`, `/v1/rkm/queue/{proposal_id}/reject`, `/v1/rules/{rule_name}/lineage`, `/v1/rules/{rule_name}/retract`, `/v1/rules/{rule_name}/rollback` |
| `keys` | `/v1/keys/rotate`, `/v1/keys/{kid}/revoke` |

The console routes are in that table for a reason: `/admin` reaches the same
broker, the same audit trail and the same source catalogue as `/v1`, so it
enforces the same capability. A key that `/v1/audit` refuses is refused at
`/admin/audit` too.

Three routes take no credential at all: `GET /healthz`, `GET /readyz` and
`GET /v1/keys/jwks.json` — a verifier needs the public keys before it has one.
`GET /metrics`, `GET /`, `GET /openapi.json`, `GET /docs`,
`GET /docs/oauth2-redirect`, `GET /redoc`, `GET /admin/`, `GET /admin/login`,
`POST /admin/login` and `GET /admin/logout` also carry no auth dependency.

Two optional headers apply across groups:

| Header | Where | Meaning |
| --- | --- | --- |
| `X-Nautilus-Session-Token` | `/v1/request`, `/v1/query`, `/admin/api/query` | An EdDSA JWS from `POST /v1/sessions`. Verified by `verify_session_token`; a body-borne `context.session_token` wins if both are sent. |
| `X-Nautilus-Reviewer` (alias `X-Reviewer`) | the four routes that record a decision: `POST /v1/rkm/queue/{id}/approve`, `.../reject`, `POST /v1/rules/{rule_name}/retract`, `.../rollback`. The other RKM routes do not read it | Who is recorded as deciding. Required **only** for a bare key: a bound key's `agent_id` is the reviewer, so a bound key never needs the header (`_require_reviewer`). Missing on a bare key ⇒ `400 X-Nautilus-Reviewer header required` |

## Errors common to all routes

These come from shared middleware and dependencies, not from any one handler.
The `detail` strings are the exact text the software emits. Every one of them — and every
message from every route below — is catalogued in the [error reference](errors/index.md),
which quotes the emitted string, says what causes it, and stands up a deliberately narrowed
variant of the scratch broker above to reproduce it.

| Status | `detail` | Cause | What to do |
| --- | --- | --- | --- |
| `401` | `API key required` | `api.keys` is empty | Configure at least one key; the allow-list is fail-closed |
| `401` | `Invalid API key` | `X-API-Key` matched no entry | Check the key; comparison is constant-time over every entry |
| `401` | `Not authenticated` | No `X-API-Key` header and no `nautilus_key` cookie, on a route guarded by `_read_guard` / `get_auth_user` | Send `X-API-Key`, or log in at `/admin/login` for the console |
| `401` | `Forwarded identity rejected: peer is not a trusted proxy` | `api.auth.mode: proxy_trust` and the peer is not in `api.auth.trusted_proxies` | Add the proxy's address, or terminate through the configured one |
| `401` | `Missing X-Forwarded-User` | `proxy_trust` mode, trusted peer, no identity header | Have the proxy set `X-Forwarded-User` |
| `401` | `Invalid session token: <reason_code>` — one of `missing`, `bad_signature`, `unknown_kid`, `expired`, `broker_instance_mismatch`, `agent_mismatch` | `X-Nautilus-Session-Token` failed verification | Re-mint at `POST /v1/sessions`; per-code remedies are in [the table under `POST /v1/request`](#post-v1request). A token carried in `context.session_token` instead is refused as `Invalid session token (<reason_code>): <message>` |
| `403` | `This credential does not hold the 'query' capability (it holds ['audit_read'])` | The key's `capabilities` list omits what the route needs | Use a key that holds it, or widen `capabilities` |
| `403` | `This credential is bound to agent_id='analyst', so it cannot ask as 'other'` | Bound key, different `agent_id` in the body | Send the bound agent's id, or use a key bound to the other agent |
| `404` | FastAPI default `Not Found` | Route not registered — e.g. any `/admin/*` while `ui.enabled` is false | Set `ui.enabled: true` to serve the console |
| `413` | `Request body is 1100041 bytes; this broker accepts at most 1048576 (api.max_request_bytes).` | `Content-Length` over `api.max_request_bytes` (default 1048576) | Send less, or raise `api.max_request_bytes` |
| `422` | a list of `{type, loc, msg, input}` objects | Pydantic rejected the body or a query param | Fix the field named in `loc`; see below |
| `503` + `Retry-After: 1` | `Broker busy: 64 requests are already in flight (api.max_concurrent_requests). Retry.` | More concurrent requests than `api.max_concurrent_requests` (default 64) | Retry after the header's delay. `/healthz`, `/readyz` and `/metrics` are exempt from this limit so saturation never drains the pod |
| `503` | `Broker not ready` | The request arrived before lifespan startup finished | Wait for `GET /readyz` to return 200 |

`422` is what FastAPI returns for every malformed body, and Nautilus's request
model sets `extra="forbid"` — an unknown top-level field is an error, not a
silent drop. `session_id`, `purpose` and `clearance` go **inside** `context`;
sent at the top level they used to be dropped in silence, which handed the
caller a fresh session on every request (so cumulative exposure never
accumulated) and swapped their purpose for the agent's default.

```bash
curl -sS -X POST "$NAUTILUS/v1/request" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"analyst","intent":"orders","session_id":"s-1"}'
```

```json
{
  "detail": [
    {
      "type": "extra_forbidden",
      "loc": ["body", "session_id"],
      "msg": "Extra inputs are not permitted",
      "input": "s-1"
    }
  ]
}
```

`intent` is capped at `MAX_INTENT_LENGTH` = 8192 characters
(`nautilus/core/models.py`); past it the `422` reads `"type":
"string_too_long"`, `"msg": "String should have at most 8192 characters"`.

---

## Broker

### `POST /v1/request`

Submit a broker request. Capability `query`. This and `/v1/query` are the only
routes that reach adapters.

**Body** (`BrokerRequest`, `extra="forbid"`):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `agent_id` | `string` | yes | The requesting agent. Must match a bound key's `agent_id` |
| `intent` | `string` (≤ 8192) | yes | Natural-language description of what data is needed |
| `context` | `object` | no | `purpose`, `session_id`, `clearance`, `session_token`, `scope_constraints`, `embedding` |
| `fact_set_hash` | `string \| null` | no | Pins the fact set a prior turn saw; omit unless replaying |

**Status codes**

| Code | When |
| --- | --- |
| `200` | The broker answered. **A refusal is also a `200`** — read `outcome` |
| `400` | Malformed input inside `context` (notably `scope_constraints`); `detail` is the parser's message |
| `401` | `API key required` · `Invalid API key` · a rejected session token, in one of **two** spellings depending on where it was carried — see below |
| `403` | `This credential does not hold the 'query' capability (it holds ['audit_read'])` · `This credential is bound to agent_id='analyst', so it cannot ask as 'other'` · `session_not_yours: session 's-1' belongs to another principal. A session id is not a credential — either use your own, or have its owner declare a handoff to agent_id='analyst' in it first.` |
| `413` / `422` / `503` | See [Errors common to all routes](#errors-common-to-all-routes) |
| `503` + `Retry-After: 5` | `Nautilus could not record this request and will not serve what it cannot account for: <os error>` — the audit sink stopped accepting writes |

**The two spellings of a rejected session token.** Where the token was carried
decides which component refuses it, and the two do not word it the same way. In
the `X-Nautilus-Session-Token` header it is refused by the transport dependency:

<!-- not-executed: response body for a token sent in the X-Nautilus-Session-Token header -->
```json
{"detail": "Invalid session token: bad_signature"}
```

A token inside `context.session_token` is refused by the handler instead, which
keeps the verifier's own sentence and adds `WWW-Authenticate: Bearer`. Run this:

```bash
curl -sS -X POST "$NAUTILUS/v1/request" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"analyst","intent":"orders",
       "context":{"purpose":"fraud-review","session_token":"not-a-token"}}'
```

```json
{"detail": "Invalid session token (bad_signature): Cannot decode token header"}
```

The `reason_code` in either spelling is one of six
(`nautilus/attestation/session_token.py`, `nautilus/core/broker.py`):

| `reason_code` | Meaning | What to do |
| --- | --- | --- |
| `missing` | `No token provided`, or `session_token must be a string` — a non-string landed in `context.session_token` | Send the string `POST /v1/sessions` returned, or omit the key entirely |
| `bad_signature` | `Cannot decode token header` · `Invalid signature` · `Token decode failed` | The token was edited or truncated in transit. Re-mint |
| `unknown_kid` | `Token header missing kid` · `Unknown kid: '…'` · `Key '…' has been revoked` | Re-mint. Across replicas this means separate rings — point them all at one `session_tokens.key_ring_path` |
| `expired` | `Token has expired` | Re-mint; lifetime is `session_tokens.ttl_seconds` (default 3600) |
| `broker_instance_mismatch` | `Token issued for '<other>', not '<this>'` | The token came from a different broker process. Tokens are not portable across instances that do not share a ring |
| `agent_mismatch` | `session token was minted for agent 'analyst', presented by 'other'` | A token belongs to the agent it was minted for. Mint one for the presenting agent |

```bash
curl -sS -X POST "$NAUTILUS/v1/request" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"analyst","intent":"recent orders for user 42",
       "context":{"purpose":"fraud-review","session_id":"s-1"}}'
```

```json
{
  "request_id": "16a7fa67-a3da-4eeb-af49-a88f26fb6c11",
  "data": {
    "orders": [
      {"order_id": 1001, "user_id": 42, "total": 19.99},
      {"order_id": 1002, "user_id": 43, "total": 5.0}
    ]
  },
  "sources_queried": ["orders"],
  "sources_denied": [],
  "sources_skipped": [],
  "sources_errored": [],
  "denial_records": [],
  "skip_records": [],
  "rule_trace": ["nautilus-routing::match-sources-by-data-type"],
  "scope_restrictions": {},
  "attestation_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9…",
  "duration_ms": 4,
  "cap_breached": null,
  "fact_set_hash": null,
  "truncated_sources": [],
  "source_session_signatures": null,
  "session_token": "eyJhbGciOiJFZERTQSIsImtpZCI6IjFiZTIxYWFi…",
  "source_info": {
    "orders": {
      "description": "Order history",
      "classification": "unclassified",
      "data_types": ["orders"]
    }
  },
  "ruleset_hash": "sha256:1a2d54daeaea3fed330c244c56ca1b5ba8665c7ab9098c0ea4e7bcf434ae63f3",
  "outcome": "allowed"
}
```

**Reading a refusal.** A denied request is a `200` whose `outcome` is `denied`.
Ask with a purpose the source does not accept:

```bash
curl -sS -X POST "$NAUTILUS/v1/request" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"analyst","intent":"orders",
       "context":{"purpose":"marketing","session_id":"s-2"}}'
```

```json
{
  "request_id": "dcb310b6-cbdb-46b3-8ef7-d16f2e538326",
  "data": {},
  "sources_queried": [],
  "sources_denied": ["orders"],
  "denial_records": [
    {
      "source_id": "orders",
      "reason": "purpose not authorized (source 'orders' allows purposes: fraud-review)",
      "rule_name": "deny-purpose-mismatch",
      "relevant": true
    }
  ],
  "rule_trace": [
    "nautilus-routing::deny-purpose-mismatch",
    "nautilus-routing::match-sources-by-data-type"
  ],
  "outcome": "denied"
}
```

| Response field | Meaning |
| --- | --- |
| `outcome` | `allowed` \| `denied` \| `errored` \| `skipped` — what happened, in one word. `denied` only when a source the request actually concerned was refused; an unrelated refusal does not outrank a source that failed to answer |
| `denial_records` | One `{source_id, reason, rule_name, relevant}` per denied source: why it was refused, which rule said so, and whether the refusal concerned this request at all. A purpose refusal names the purposes the source does accept — read it and retry |
| `skip_records` | One `{source_id, reason}` per source that took no part — usually because its `data_types` have nothing to do with the intent |
| `sources_errored` | One `ErrorRecord` per source that failed to answer: `source_id`, `error_type`, `message`, `trace_id`, and `endpoint` — the address that source dials, as `scheme://host[:port]`, or `null` for a source that dials nothing. `endpoint` carries no credential: it is rebuilt from scheme, host and port, so userinfo, path and query in `connection` never reach it. See [the error reference](errors/adapters.md#endpoint-which-backend-this-was) |
| `source_info` | `{source_id: {description, classification, data_types}}` for each queried source — what the rows in `data` actually are |
| `ruleset_hash` | Which ruleset answered. Mid-rollout two replicas hold different ones and the identical request alternates `allowed` / `denied` behind the load balancer; this is how a caller can tell |
| `rule_trace` | The rules that fired, in order — the same trace the audit entry records |
| `truncated_sources` | Sources whose rows were cut short by an adapter row cap or a transport bound. Empty when nothing truncated |
| `session_token` | Present only when `session_tokens.enabled: true`; `null` otherwise |
| `scope_restrictions` | `{source_id: [ScopeConstraint]}` — the narrowing the router imposed on each query |

### `POST /v1/query`

Literal alias of `POST /v1/request` — same handler (`_handle_request`), same
body, same responses, same `query` capability. It exists so a caller that spells
the verb "query" does not need to know the other name.

**Status codes:** identical to `POST /v1/request` — `200` (including for a
refusal), `400`, `401`, `403`, `413`, `422`, `503`.

```bash
curl -sS -X POST "$NAUTILUS/v1/query" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"analyst","intent":"recent orders","context":{"purpose":"fraud-review"}}'
```

```json
{
  "request_id": "9ca8ea18-fd02-4c03-91bc-eba634b080c6",
  "data": {"orders": [{"order_id": 1001, "user_id": 42, "total": 19.99}]},
  "sources_queried": ["orders"],
  "outcome": "allowed",
  "duration_ms": 3
}
```

### `GET /v1/sources`

The configured sources the calling agent is cleared to see. Capability `query`.
Metadata only — never connection strings or credentials. Sources above the
caller's clearance are omitted entirely, because a description is how you learn
what to ask for. A bare API key names no agent, so it has no clearance to filter
against and sees the whole catalogue.

**Status codes:** `200` always when authorized (an unbuilt broker answers
`{"sources": []}`, not an error) · `401` · `403` (`query`) · `503` (busy).

```bash
curl -sS "$NAUTILUS/v1/sources" -H "X-API-Key: $KEY"
```

```json
{
  "sources": [
    {
      "id": "orders",
      "type": "static",
      "description": "Order history",
      "classification": "unclassified",
      "data_types": ["orders"],
      "allowed_purposes": ["fraud-review"]
    }
  ]
}
```

`allowed_purposes` is what a caller refused on `purpose` should read to pick one
that works.

---

## Session tokens and signing keys

### `POST /v1/sessions`

Mint a session-provenance token (EdDSA JWS). Capability `query`.

**Body:** `{"session_id": "...", "agent_id": "...", "purpose": "..."}`.
`clearance` in the body is **ignored** — it comes from the agent registry, so a
key bound to a low-clearance agent cannot mint a token claiming a high one.

**Status codes**

| Code | When |
| --- | --- |
| `200` | Token issued |
| `401` | Bad `X-API-Key` |
| `403` | `This credential does not hold the 'query' capability (it holds ['audit_read'])` · `This credential is bound to agent_id='analyst', so it cannot mint a session token for 'other'` · `purpose 'marketing' is not one of the purposes agent 'analyst' may claim (['fraud-review'])` |
| `422` | Body is not a JSON object |
| `503` | `Key ring not ready` (before lifespan startup) |

```bash
curl -sS -X POST "$NAUTILUS/v1/sessions" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"s-1","agent_id":"analyst","purpose":"fraud-review"}'
```

```json
{
  "token": "eyJhbGciOiJFZERTQSIsImtpZCI6IjFiZTIxYWFiLTQ4MmMtNDc2YS04NjYxLWMxZDdlODMyODRkMiI…",
  "session_id": "s-1",
  "agent_id": "analyst",
  "purpose": "fraud-review",
  "clearance": "unclassified",
  "issued_at": 1788223899,
  "expires_at": 1788227499,
  "broker_instance_id": "beedd374-e86d-4829-a378-b23a512f182e",
  "kid": "1be21aab-482c-476a-8661-c1d7e83284d2"
}
```

Send `token` back as `X-Nautilus-Session-Token` on `/v1/request`. `expires_at`
is `issued_at + session_tokens.ttl_seconds` (default 3600).

**Recovery — the requested purpose is not the agent's.** The token is an
authorization assertion Nautilus forwards downstream, so it never carries a
claim the router would refuse to act on:

```json
{"detail": "purpose 'marketing' is not one of the purposes agent 'analyst' may claim (['fraud-review'])"}
```

Pick one of the listed purposes, or add it to that agent's `allowed_purposes`.

### `GET /v1/keys/jwks.json`

The public half of the session-token signing ring, as an RFC 7517 JWK Set.
**No credential** — a verifier needs the keys before it has one.

**Status codes:** `200` always. Before lifespan startup, or with no ring, the
body is `{"keys": []}`.

```bash
curl -sS "$NAUTILUS/v1/keys/jwks.json"
```

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "1be21aab-482c-476a-8661-c1d7e83284d2",
      "x": "BcDcMetbxS2sOWhwrkVqiW2sC7k_zKq85V8Hyo66bsI",
      "use": "sig"
    }
  ]
}
```

Both the outgoing and incoming key appear here during a rotation grace window —
that is what makes in-flight tokens keep verifying.

### `POST /v1/keys/rotate`

Promote a fresh signing key. Capability `keys`. The old primary moves to
rotating-out: in-flight tokens keep verifying and are lazily re-signed. Close
the window with `POST /v1/keys/{kid}/revoke`.

**Body:** `{"reviewer": "<operator identity>"}` — required.

**Status codes:** `200` · `400 reviewer is required (no control characters)` ·
`401` · `403` (`keys`) · `409` when session tokens are disabled ·
`422` (body not an object) · `503 Broker not ready`.

```bash
curl -sS -X POST "$NAUTILUS/v1/keys/rotate" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' -d '{"reviewer":"ops@example.com"}'
```

```json
{
  "new_primary_kid": "9c877400-fd62-4e3f-b3cc-3ac75038372e",
  "reviewer": "ops@example.com"
}
```

**Recovery — `409`.** The exact string is:

```json
{"detail": "session tokens are disabled (session_tokens.enabled: false)"}
```

Set `session_tokens.enabled: true` and restart. There is no key ring to rotate
until then.

### `POST /v1/keys/{kid}/revoke`

End a key's grace window. Capability `keys`. `kid` must be a UUID; take it from
`GET /v1/keys/jwks.json`.

**Body:** `{"reviewer": "...", "reason": "..."}` — both required.

**Status codes**

| Code | `detail` |
| --- | --- |
| `200` | — |
| `400` | `kid must be a UUID` · `reviewer and reason are required (no control characters)` |
| `401` | `API key required` · `Invalid API key` |
| `403` | `This credential does not hold the 'keys' capability (it holds ['query'])` |
| `404` | `kid '00000000-0000-0000-0000-000000000000' not found` |
| `409` | `session tokens are disabled (session_tokens.enabled: false)` — set it and restart · `kid '1be21aab-482c-476a-8661-c1d7e83284d2' is the current primary; rotate first, then revoke` — `POST /v1/keys/rotate`, then revoke the kid that rotated out |
| `503` | `Broker not ready` |

<!-- not-executed: KID comes from the jwks.json response above; substitute a kid you actually hold -->
```bash
KID=1be21aab-482c-476a-8661-c1d7e83284d2
curl -sS -X POST "$NAUTILUS/v1/keys/$KID/revoke" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"reviewer":"ops@example.com","reason":"rotated out"}'
```

```json
{
  "revoked_kid": "1be21aab-482c-476a-8661-c1d7e83284d2",
  "reviewer": "ops@example.com",
  "reason": "rotated out"
}
```

---

## Adapters

### `GET /v1/adapters`

Every adapter and its live status **in this process**. Capability `query`.
Quarantine state is in-memory and per-process, so it cannot be answered by
rebuilding a broker from the config file. `nautilus adapters list --url` reads
this route.

**Status codes:** `200` (no broker yet ⇒ `{"adapters": []}`) · `401` · `403`
(`query`) · `503` (busy).

```bash
curl -sS "$NAUTILUS/v1/adapters" -H "X-API-Key: $KEY"
```

```json
{"adapters": [{"id": "orders", "type": "static", "status": "active"}]}
```

`status` is `active` or `quarantined`.

### `GET /v1/adapters/{name}/schema`

The adapter's current `AdapterSchema` — tables, fields, indexes, capability
flags. Capability `query`. `name` is a source `id` from `GET /v1/adapters`.

**Status codes**

| Code | `detail` |
| --- | --- |
| `200` | — |
| `401` | `API key required` · `Invalid API key` |
| `403` | `This credential does not hold the 'query' capability (it holds ['audit_read'])` |
| `404` | `Adapter 'nope' not found` |
| `501` | `Adapter 'custom' does not support schema introspection` — the adapter has no `get_schema`, or inherits the base one and never overrode it, so calling it raised `NotImplementedError`. Both are permanent: do not retry, implement `get_schema` |
| `503` | `Broker not ready` · `Schema fetch failed: <error>` — the introspection call raised something other than `NotImplementedError`, so the condition is transient and worth retrying. Adapters connect lazily, so a broker that has served no request yet answers `Schema fetch failed: StaticAdapter.get_schema() called before connect()`. A store that refused the query puts its own driver error in the same slot |

Every adapter type shipped in `nautilus/adapters/` (`static`, `postgres`,
`rest`, `s3`, `elasticsearch`, `neo4j`, `pgvector`, `influxdb`, `servicenow`,
`llm`) overrides `get_schema`, so neither of those two applies to a stock config.

```bash
curl -sS "$NAUTILUS/v1/adapters/orders/schema" -H "X-API-Key: $KEY"
```

```json
{
  "adapter_id": "orders",
  "source_type": "static",
  "tables": [
    {
      "name": "orders",
      "fields": [
        {"name": "order_id", "type": "yaml", "nullable": true, "description": ""},
        {"name": "user_id", "type": "yaml", "nullable": true, "description": ""},
        {"name": "total", "type": "yaml", "nullable": true, "description": ""}
      ],
      "indexes": [],
      "primary_key": []
    }
  ],
  "capability_flags": {},
  "fetched_at": "2026-09-01T00:47:18.923328Z"
}
```

---

## Rules

### `GET /v1/rules`

Every rule the running engine will fire, and the ruleset they came from.
Capability `query`. Built-ins, user rules and pack rules alike.

**Status codes:** `200` · `401` · `403` (`query`) · `503 Broker not ready`.

```bash
curl -sS "$NAUTILUS/v1/rules" -H "X-API-Key: $KEY"
```

```json
{
  "ruleset_hash": "sha256:1a2d54daeaea3fed330c244c56ca1b5ba8665c7ab9098c0ea4e7bcf434ae63f3",
  "rules": [
    {"module": "nautilus-routing", "name": "default-classification-deny"},
    {"module": "nautilus-routing", "name": "deny-purpose-mismatch"},
    {"module": "nautilus-routing", "name": "information-flow-violation"},
    {"module": "nautilus-routing", "name": "match-sources-by-data-type"},
    {"module": "nautilus-routing", "name": "purpose-expired-deny"},
    {"module": "nautilus-routing", "name": "session-exposure-escalation-deny"}
  ]
}
```

`ruleset_hash` is the same value every audit entry and every `BrokerResponse`
records, so a deployment can be compared against the policy it is believed to
run and against the entries it produced.

### `GET /v1/rules/{rule_name}/lineage`

The lineage DAG for one rule: who proposed it, who approved it, every version
and when each was promoted or retired. Capability `govern`.

**Status codes:** `200` · `401` · `403` (`govern`) · `404 rule 'nope' not
found` — the name has no lineage record, which is the answer for every
built-in: lineage exists only for rules promoted through the RKM queue.

<!-- not-executed: promote a rule through POST /v1/rkm/queue first — the name below is the one that example promotes -->
```bash
curl -sS "$NAUTILUS/v1/rules/ve-expiring-scope-probe/lineage" -H "X-API-Key: $KEY"
```

```json
{
  "rule_name": "ve-expiring-scope-probe",
  "proposer": "pipeline",
  "approver": "ops@example.com",
  "observation_ids": {},
  "derived_from": [],
  "versions": [
    {
      "rule_name": "ve-expiring-scope-probe",
      "version": 1,
      "proposer": "pipeline",
      "observation_ids": {},
      "sandbox_results": {},
      "approver": "ops@example.com",
      "derived_from": [],
      "promoted_at": "2026-09-01T00:48:12.120992+00:00",
      "retired_at": null,
      "retire_reason": null,
      "retire_reviewer": null,
      "module": "nautilus-routing"
    }
  ]
}
```

### `POST /v1/rules/{rule_name}/retract`

Retire a rule version. Capability `govern`. Destructive, so it demands
`yes: true` (`confirm: true` is accepted as an alias).

**Body**

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `yes` | `bool` | yes | Confirmation. `confirm` works too |
| `reason` | `string` | yes | Recorded on the lineage record |
| `version` | `int` | no | Defaults to the latest version |
| `cascade` | `string` | no | `none` (default), `cascade`, or `orphan-children` |

**Status codes**

| Code | `detail` |
| --- | --- |
| `200` | — |
| `400` | `X-Nautilus-Reviewer header required` (bare key, no header) · `reason is required for retraction` |
| `401` | `API key required` · `Invalid API key` |
| `403` | `This credential does not hold the 'govern' capability (it holds ['query'])` |
| `404` | `rule 'nope' not found` — no lineage record for that name at all · `rule 've-expiring-scope-probe' version 7 not found` — the name exists but the `version` you asked for does not |
| `412` | `yes=true required for destructive operation` |

<!-- not-executed: names a rule you promoted through the RKM queue -->
```bash
curl -sS -X POST "$NAUTILUS/v1/rules/ve-expiring-scope-probe/retract" \
  -H "X-API-Key: $KEY" -H 'X-Nautilus-Reviewer: ops@example.com' \
  -H 'Content-Type: application/json' \
  -d '{"yes":true,"reason":"superseded"}'
```

```json
{
  "rule_name": "ve-expiring-scope-probe",
  "version": 1,
  "affected_descendants": [],
  "engine_updated": true,
  "engine_note": "removed from the running engine and from its rule file"
}
```

Alongside the lineage fields the response says what happened to the *running*
engine:

| Field | Meaning |
| --- | --- |
| `engine_updated` | `true` when the rule was in force and is no longer. `false` means it was never loaded, so only the lineage record changed |
| `engine_note` | One of three exact strings: `removed from the running engine and from its rule file`; `removed from the running engine; its YAML is not in rules.user_rules_dirs, so a restart reloads it`; `the rule was not in force; only the lineage record changed` |

The second note is the one to act on: a built-in or pack rule comes back at the
next restart unless the pack or built-in goes too.

### `POST /v1/rules/{rule_name}/rollback`

Re-promote a prior lineage version as a new version. Capability `govern`.

**Body:** `{"yes": true, "to_version": <int>, "reason": "..."}`. `to_version` is
required; `yes` (or `confirm`) is required.

**Status codes:** `200` · `400 X-Nautilus-Reviewer header required` ·
`400 to_version is required for rollback` · `401` · `403` (`govern`) ·
`404 rule 'nope' version 1 not found` · `412 yes=true required for destructive
operation` · `422` when `to_version` is not an integer.

<!-- not-executed: names a rule you promoted through the RKM queue -->
```bash
curl -sS -X POST "$NAUTILUS/v1/rules/ve-expiring-scope-probe/rollback" \
  -H "X-API-Key: $KEY" -H 'X-Nautilus-Reviewer: ops@example.com' \
  -H 'Content-Type: application/json' \
  -d '{"yes":true,"to_version":1,"reason":"restore"}'
```

```json
{
  "rule_name": "ve-expiring-scope-probe",
  "rolled_back_from_version": 1,
  "new_version": 2,
  "engine_updated": false,
  "engine_note": "lineage only: the restored version's rule text is not stored, so the running engine still has the newer rule. Re-submit it through the RKM queue, or restart against the rule files you want in force.",
  "record": {
    "rule_name": "ve-expiring-scope-probe",
    "version": 2,
    "proposer": "pipeline",
    "approver": "ops@example.com",
    "derived_from": [],
    "promoted_at": "2026-09-01T00:48:12.188086+00:00",
    "retired_at": null,
    "module": "nautilus-routing"
  }
}
```

**`engine_updated` is always `false` here, by construction.** A lineage record
carries no rule text, so rollback never reloads anything — it is a ledger entry,
not a deploy. `engine_note` names what still has to happen for the restored
version to decide requests.

---

## RKM review queue

Rule-knowledge-management: a proposed rule is validated (static → shadow →
sandbox → score), queued, and promoted only on human approval. Every route in
this group needs capability `govern`. The two routes that record a decision —
`approve` and `reject` — additionally need a reviewer identity: a bound key
supplies it, a bare key must send `X-Nautilus-Reviewer` or get
`400 X-Nautilus-Reviewer header required`.

### `POST /v1/rkm/queue`

Validate a rule and queue the resulting proposal. Returns **`201`**.

**Body:** `{"rule_yaml": "<contents of the rule file>"}`.

**Status codes:** `201` · `400 body must carry 'rule_yaml': the contents of the
rule file` (missing, non-string, or blank) · `401` · `403` (`govern`) · `413`
for a rule file over `api.max_request_bytes` · `422` when the body is not a JSON
object.

A rule the engine rejects is queued as `rejected` with the reason recorded — it
is still a `201`, because "it does not compile" is a validation verdict.

```bash
cat > /tmp/nautilus-api/probe-rule.yaml <<'YAML'
module: nautilus-routing
ruleset: ve-expiring-scope
version: "1.0"
rules:
  - name: ve-expiring-scope-probe
    description: "Attach a future-dated ScopeConstraint."
    salience: 50
    when:
      - template: agent
        conditions:
          - slot: purpose
            bind: ?purpose
          - test: '(eq ?purpose "ve-expiring-probe")'
      - template: source
        conditions:
          - slot: id
            bind: ?sid
    then:
      action: scope
      reason: "expiring-scope probe"
      assert:
        - template: scope_constraint
          slots:
            source_id: "?sid"
            field: "classification"
            operator: "="
            value: "cui"
            expires_at: "2030-01-01T00:00:00Z"
YAML
curl -sS -X POST "$NAUTILUS/v1/rkm/queue" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  --data "$(jq -Rs '{rule_yaml: .}' < /tmp/nautilus-api/probe-rule.yaml)"
```

```json
{
  "proposal_id": "prop_de70fef5bfa84892be7c9ed4e94a74b6",
  "status": "pending",
  "confidence": 0.9,
  "static_ok": true,
  "static_errors": [],
  "shadow_flags": [],
  "sandbox": {
    "replayed_n": 1000,
    "replayed_n_actual": 2,
    "regressions": 0,
    "relaxations": 0,
    "fired": 0,
    "cascade_max": 0,
    "insufficient_history": true,
    "skipped_no_input_facts": 2,
    "skipped_drifted": 0,
    "top_triggers": [],
    "error": null
  }
}
```

`insufficient_history: true` means the audit log held fewer than
`rkm.sandbox.min_entries` replayable entries — the score is provisional.

### `GET /v1/rkm/queue`

List proposals. Capability `govern`.

| Query param | Type | Default | Meaning |
| --- | --- | --- | --- |
| `status` | `string` | none | Filter: `pending`, `approved`, `promoted`, `rejected` |
| `limit` | `int` | `100` | Cap on returned proposals; `0` or less returns all |

**Status codes:** `200` · `401` · `403` (`govern`) · `422` if `limit` is not an
integer.

```bash
curl -sS "$NAUTILUS/v1/rkm/queue?status=pending&limit=2" -H "X-API-Key: $KEY"
```

```json
{
  "proposals": [
    {
      "proposal_id": "prop_de70fef5bfa84892be7c9ed4e94a74b6",
      "schema_version": 2,
      "status": "pending",
      "proposer": "pipeline",
      "proposed_at": "2026-09-01T00:47:50.001413+00:00",
      "target_module": "curator",
      "artifact_type": "rule",
      "artifact": {
        "yaml_path": "/tmp/nautilus-api/.nautilus/rkm/queue/rules/8869666c454c459db5d7fa5a5e62235d.yaml",
        "name": "ve-expiring-scope-probe",
        "module": "nautilus-routing"
      },
      "validation": {
        "static_ok": true,
        "static_errors": [],
        "confidence": 0.9,
        "sandbox": {"replayed_n": 1000, "regressions": 0, "fired": 0}
      },
      "shadow_flags": []
    }
  ]
}
```

### `GET /v1/rkm/queue/{proposal_id}`

One proposal with the full validation breakdown. Capability `govern`.

**Status codes:** `200` · `401` · `403` (`govern`) ·
`404 proposal 'prop_deadbeef' not found`.

<!-- not-executed: PROPOSAL_ID comes from POST /v1/rkm/queue above -->
```bash
PROPOSAL_ID=prop_de70fef5bfa84892be7c9ed4e94a74b6
curl -sS "$NAUTILUS/v1/rkm/queue/$PROPOSAL_ID" -H "X-API-Key: $KEY"
```

```json
{
  "proposal_id": "prop_de70fef5bfa84892be7c9ed4e94a74b6",
  "status": "pending",
  "proposer": "pipeline",
  "proposed_at": "2026-09-01T00:47:50.001413+00:00",
  "proposed_rule": {
    "yaml_path": "/tmp/nautilus-api/.nautilus/rkm/queue/rules/8869666c454c459db5d7fa5a5e62235d.yaml",
    "name": "ve-expiring-scope-probe",
    "module": "nautilus-routing"
  },
  "confidence": 0.9,
  "confidence_breakdown": {
    "base": 1.0,
    "regression_penalty": -0.0,
    "relaxation_penalty": -0.0,
    "shadow_penalty": -0.0,
    "fire_rate_penalty": -0.1,
    "cascade_penalty": 0.0,
    "drift_penalty": 0.0,
    "total": 0.9
  },
  "sandbox": {"replayed_n": 1000, "regressions": 0, "fired": 0, "top_triggers": []},
  "shadow_flags": [],
  "top_triggers": []
}
```

`confidence_breakdown` is what to read before approving: each penalty names the
check that cost the proposal score.

### `POST /v1/rkm/queue/{proposal_id}/approve`

Approve a pending proposal and promote the rule into the running engine.
Capability `govern`. Body is optional (`{}`).

**Status codes**

| Code | `detail` |
| --- | --- |
| `200` | — |
| `400` | `X-Nautilus-Reviewer header required` — bare key with no reviewer header |
| `401` | `API key required` · `Invalid API key` |
| `403` | `This credential does not hold the 'govern' capability (it holds ['query'])` |
| `404` | `proposal 'prop_deadbeef' not found` |
| `409` | `{"error": "already_decided", "current_status": "promoted"}` |
| `422` | `{"error": "promotion_failed", "message": "…", "current_status": "approved", "recovery": "fix the rule and re-approve to retry the promotion, or reject the proposal"}` — full body below |

A failed promotion leaves the proposal in `approved`, not `pending`: re-approving
retries the promotion, and rejecting is the other way out. The `422` says so,
because `approved` with nothing promoted otherwise reads as a dead end.

<!-- not-executed: PROPOSAL_ID comes from POST /v1/rkm/queue above -->
```bash
PROPOSAL_ID=prop_de70fef5bfa84892be7c9ed4e94a74b6
curl -sS -X POST "$NAUTILUS/v1/rkm/queue/$PROPOSAL_ID/approve" \
  -H "X-API-Key: $KEY" -H 'X-Nautilus-Reviewer: ops@example.com' \
  -H 'Content-Type: application/json' -d '{}'
```

```json
{
  "proposal_id": "prop_de70fef5bfa84892be7c9ed4e94a74b6",
  "reviewer": "ops@example.com",
  "approved_at": "2026-09-01T00:48:12.120992Z",
  "promoted": true
}
```

**Recovery — the `422`.** Approval succeeded; loading the rule into the running
engine did not. The commonest cause is the one the scratch config above avoids:
no `rules.user_rules_dirs`, so there is nowhere to write the promoted rule and a
"promoted" proposal would evaporate at the next restart. Against a broker whose
config omits `rules.user_rules_dirs`, the same approve call answers:

<!-- not-executed: this is the response from a broker whose config omits rules.user_rules_dirs; the scratch config above sets it, so approvals there succeed -->
```json
{
  "detail": {
    "error": "promotion_failed",
    "message": "FathomRouter.reload_rule failed for proposal 'prop_de70fef5bfa84892be7c9ed4e94a74b6': cannot promote rule 've-expiring-scope-probe': no rules.user_rules_dirs is configured, so the rule would live only in this process and be gone at the next restart while the proposal reads 'promoted'. Configure a writable rules directory and retry the approval.",
    "current_status": "approved",
    "recovery": "fix the rule and re-approve to retry the promotion, or reject the proposal"
  }
}
```

`message` is `FathomRouter.reload_rule failed for proposal <proposal_id>: ` then
the engine's own complaint — which names the *rule*, not the proposal. Set
`rules.user_rules_dirs` to a writable directory, restart, and POST the same
approve again; the proposal is still `approved` and the retry promotes it. The
other `message` tail from the same branch is `cannot promote rule '<name>':
writing <path> failed: <os error>` — the directory exists but is not writable.

**Recovery — the `409`.** `current_status` tells you what already happened.
`promoted` means the rule is in force; there is nothing to re-approve.

### `POST /v1/rkm/queue/{proposal_id}/reject`

Reject a pending proposal. Capability `govern`.

**Body:** `{"reason": "..."}` — required.

**Status codes:** `200` · `400 X-Nautilus-Reviewer header required` ·
`400 reason is required for rejection` · `401` · `403` (`govern`) ·
`404 proposal 'prop_deadbeef' not found` ·
`409 {"error": "already_decided", "current_status": "<status>"}`.

<!-- not-executed: PROPOSAL_ID comes from POST /v1/rkm/queue above -->
```bash
PROPOSAL_ID=prop_de70fef5bfa84892be7c9ed4e94a74b6
curl -sS -X POST "$NAUTILUS/v1/rkm/queue/$PROPOSAL_ID/reject" \
  -H "X-API-Key: $KEY" -H 'X-Nautilus-Reviewer: ops@example.com' \
  -H 'Content-Type: application/json' -d '{"reason":"fires on every source"}'
```

```json
{
  "proposal_id": "prop_de70fef5bfa84892be7c9ed4e94a74b6",
  "reviewer": "ops@example.com",
  "rejected_at": "2026-09-01T00:56:27.095720Z",
  "reason": "fires on every source"
}
```

---

## Audit

### `GET /v1/audit`

Paginated audit-entry query with server-side filters — the SIEM / compliance
ingestion route. Capability `audit_read`.

| Query param | Type | Default | Meaning |
| --- | --- | --- | --- |
| `agent_id` | `string` | none | Exact match |
| `source_id` | `string` | none | Entries touching this source |
| `event_type` | `string` | none | e.g. `decision`, `session_token_issued` |
| `start` / `end` | ISO-8601 | none | Inclusive time window |
| `cursor` | `string` | none | Opaque cursor from `next_cursor` |
| `limit` | `int` 1–500 | `50` | Page size |
| `order` | `asc` \| `desc` | `desc` | Newest first by default |

**Status codes:** `200` · `400 invalid datetime: 'yesterday'` (unparseable
`start`/`end`) · `401` · `403` (`audit_read`) · `422` when `limit` is outside
1–500 or `order` is not `asc`/`desc` · `503 Broker not ready`.

```bash
curl -sS "$NAUTILUS/v1/audit?limit=1&order=desc" -H "X-API-Key: $KEY"
```

```json
{
  "entries": [
    {
      "timestamp": "2026-09-01T00:47:18.918669Z",
      "request_id": "16a7fa67-a3da-4eeb-af49-a88f26fb6c11",
      "agent_id": "analyst",
      "principal_id": "principal:7b41e5ad587f80378421202c8fb499e1",
      "session_id": "s-1",
      "raw_intent": "recent orders for user 42",
      "intent_analysis": {
        "raw_intent": "recent orders for user 42",
        "data_types_needed": ["orders"],
        "entities": [],
        "temporal_scope": null,
        "estimated_sensitivity": null
      },
      "routing_decisions": [{"source_id": "orders", "reason": "data_types overlap"}],
      "sources_queried": ["orders"],
      "sources_denied": [],
      "sources_errored": [],
      "truncated_sources": null,
      "attestation_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9…",
      "duration_ms": 3,
      "source_response_hashes": {
        "orders": "sha256:69b6f90db745d72a4252d5d88a747fcee9fe489d4cff8598a63af6d7e106deb8"
      },
      "scope_hash_version": "v1"
    }
  ],
  "next_cursor": "MTE3ODE="
}
```

Pass `next_cursor` back as `cursor` for the next page. `next_cursor` is `null`
on the last page — that is the stop condition, not an empty `entries` list.

### `GET /v1/audit/{request_id}`

One audit entry by `request_id` — the value `POST /v1/request` returned.
Capability `audit_read`. Scans newest to oldest until found.

**Status codes:** `200` · `401` · `403` (`audit_read`) ·
`404 audit entry 'nope' not found` · `503 Broker not ready`.

<!-- not-executed: REQUEST_ID comes from a POST /v1/request response -->
```bash
REQUEST_ID=16a7fa67-a3da-4eeb-af49-a88f26fb6c11
curl -sS "$NAUTILUS/v1/audit/$REQUEST_ID" -H "X-API-Key: $KEY"
```

```json
{
  "timestamp": "2026-09-01T00:47:18.918669Z",
  "request_id": "16a7fa67-a3da-4eeb-af49-a88f26fb6c11",
  "agent_id": "analyst",
  "principal_id": "principal:7b41e5ad587f80378421202c8fb499e1",
  "session_id": "s-1",
  "raw_intent": "recent orders for user 42",
  "facts_asserted_summary": {"agent": 1, "intent": 1, "source": 1, "session": 1, "escalation_rule": 1},
  "rule_trace": ["nautilus-routing::match-sources-by-data-type"],
  "sources_queried": ["orders"],
  "sources_denied": [],
  "denial_records": [],
  "scope_constraints": [],
  "duration_ms": 3,
  "llm_provider": null,
  "llm_model": null,
  "raw_response_hash": null,
  "source_response_hashes": {
    "orders": "sha256:69b6f90db745d72a4252d5d88a747fcee9fe489d4cff8598a63af6d7e106deb8"
  },
  "scope_hash_version": "v1"
}
```

The body is the same `AuditEntry` shape `GET /v1/audit` returns in `entries`,
unwrapped.

---

## Probes, metrics, root

### `GET /healthz`

Liveness, **and the answer to "which build is this?"**. **No credential**, and
exempt from `api.max_concurrent_requests` — a full request queue must not take
the pod out of rotation. It touches no broker state, so it never fails while the
process is alive.

**Status codes:** `200` only.

```bash
curl -sS "$NAUTILUS/healthz"
```

```json
{"status": "ok", "version": "0.2.6.dev0", "build": "6b2879595e642133a8a04ba184659a8a8389d336-dirty"}
```

Two fields, because they answer two different questions.

`version` is read from the installed distribution's metadata — the same string
`nautilus version` prints and the same one `GET /openapi.json` reports in
`info.version`. It is a property of the wheel, not of the process: restarting,
reconfiguring or reloading rules never changes it, and two replicas answering
different strings means the rollout is half done. It is also shared by every
commit between two releases, which is what makes the second field necessary.

`build` is the revision the image was built from. It cannot be derived inside
the image — `.dockerignore` excludes `.git/`, so no layer can run
`git describe` — so it is handed to the build and carried as an environment
variable:

```bash
docker build --target runtime \
  --build-arg BUILD_REV="$(git rev-parse HEAD)$(git diff --quiet || echo -dirty)" \
  -t nautilus:0.2.6.dev0 .
```

The `-dirty` suffix is why the sample above ends in one: that image was built
from a working tree with uncommitted changes, and a bare commit sha would have
named a commit whose contents are not what is in the image. A release image,
built by CI from a clean checkout, carries the sha alone.

**An image built without that argument answers `"build": "unknown"`.** It does
not fall back to `version`, and that is deliberate: for 76 commits every image
answered with a well-formed `0.2.2`, so two builds that differed by an entire
release's worth of behaviour looked identical over the network. `unknown` is
not a build identifier, does not compare equal to one, and makes a rollout that
lost its provenance say so. The build is not refused without the argument —
an sdist or a source tarball has no revision to supply, and inventing one is
worse than admitting there is none.

The pair is what a rollout check needs: `version` separates release lines,
`build` separates two images on one release line, and two replicas of the same
image agree on both.

**It is the only credential-free surface that carries it.** `/metrics` was the
other candidate and is the wrong one: `target_info` comes from the OpenTelemetry
SDK, which lives in the optional `otel` extra, and `/metrics` itself imports
`prometheus_client` from that same extra — so on a `pip install nautilus-rkm`
with no extras the route raises, and even with the extra installed
`OTEL_SDK_DISABLED=true` (a supported setting, see the
[operator guide](../how-to/operator-guide.md#4-monitor)) removes `target_info`
from the exposition entirely. A build stamp that disappears when observability
is off is not an answer at 3 a.m. `/healthz` has no optional dependency, no
off-switch and no auth.

**On releases up to and including 0.2.5 neither field exists** — `/healthz`
answers `{"status": "ok"}` and nothing on the network names the build. **And
the CLI is no fallback there.** On those releases `nautilus version` looks the
distribution up under the *import* name:

```python
ver = metadata.version("nautilus")     # v0.2.5, nautilus/cli/version.py
```

The distribution is `nautilus-rkm`, so that raises `PackageNotFoundError` on
every real install and the command prints
`nautilus (version unknown — package metadata missing)` to stderr and exits
`1`. It is not a packaging problem and no build flag fixes it. Against a
release at or below 0.2.5, the only identifier left is the one the node
recorded — `docker inspect --format '{{.Image}}' <container>`, or
`kubectl get pod <pod> -o jsonpath='{.status.containerStatuses[0].imageID}'`.

From this build on, both work:

<!-- not-executed: needs an image tag / pod name this page does not have -->
```bash
docker run --rm <image> version           # line 1 version, line 2 build
kubectl exec <pod> -- nautilus version
```

### `GET /readyz`

Readiness. **No credential**, exempt from the concurrency limit. `200` iff
lifespan startup finished, the audit sink accepts writes, and the session store
answers a sentinel read plus a schema check within 2.0 s each.

**Status codes:** `200` · `503` — and the `reason` field names which check
failed.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' "$NAUTILUS/readyz"
curl -sS "$NAUTILUS/readyz"
```

```json
{"status": "ok"}
```

**Recovery.** A `503` body is `{"status": "not_ready", "reason": "<why>"}`:

| `reason` | Meaning |
| --- | --- |
| `startup_incomplete` | Lifespan has not finished, or has torn down |
| `session_store_timeout` | The store did not answer within 2.0 s — reachable but wedged |
| the audit sink's own message | `audit_logger.probe()` complained; the sink is the fail-closed path, so every request would 503 anyway |
| an exception class name, e.g. `OperationalError` | The session store raised; the pod drains rather than serving |

A rolling upgrade that migrates a shared session store re-trips this on every
pod that has not been replaced — that is deliberate, and it is what stops an old
replica read-modify-writing rows it does not understand.

### `GET /metrics`

Prometheus scrape endpoint (`text/plain; version=1.0.0`). **No credential**,
exempt from the concurrency limit, and excluded from the OpenAPI schema.

**Status codes:** `200` with the `otel` extra installed · **`500`** without it.
The handler imports `prometheus_client`, which ships in `nautilus-rkm[otel]` and
in no other extra, so a plain `pip install nautilus-rkm` serves this route as an
`ImportError`. Install `nautilus-rkm[otel]` before pointing a scrape at it. This
is also why `/metrics` is not where the build version lives — see
[`GET /healthz`](#get-healthz).

```bash
curl -sS "$NAUTILUS/metrics" | head -5
```

<!-- not-executed: sample of the text/plain exposition format, not a command -->
```
# HELP python_gc_objects_collected_total Objects collected during gc
# TYPE python_gc_objects_collected_total counter
python_gc_objects_collected_total{generation="0"} 1183.0
# HELP nautilus_rkm_queue_depth Current pending proposal queue size
# TYPE nautilus_rkm_queue_depth gauge
nautilus_rkm_queue_depth 0.0
# HELP nautilus_ruleset_info Always 1; the ruleset_hash label names the policy this replica runs
```

Nautilus adds three collectors of its own: `nautilus_rkm_queue_depth`,
`nautilus_rkm_queue_oldest_age_seconds`, and `nautilus_ruleset_info` — whose
`ruleset_hash` label is how a fleet mid-rollout is told apart from one running a
single ruleset.

### `GET /`

**No credential**; excluded from the OpenAPI schema. What it answers depends on
whether the console is mounted:

- `ui.enabled: true` — **`302`** to `/admin`.
- `ui.enabled: false` (the default) — **`200`** with a JSON index of the routes
  that do exist.

**Status codes:** `302` (console on) · `200` (console off). No error path: the
handler raises nothing and takes no credential.

**Both branches are newer than every published release.** Up to and including
**0.2.5**, `GET /` is an unconditional `302` to `/admin`, and the console router
is mounted whether or not `ui.enabled` is set. `/` itself still takes no
credential on those builds — but `/admin` does, so a browser or a `curl -L`
follows the redirect straight into `401 {"detail":"Not authenticated"}`, and a
`curl` without `-L` gets a `302` with an empty body. Either way the JSON index
below is not there. Measured on 0.2.0, 0.2.1 and 0.2.5, `ui.enabled` left at its
default.

None of that is an authentication difference: `/admin` requires a credential on
every build, and making it stop would be a downgrade, not a fix. What changed is
that the redirect became conditional and grew a fallback body, because on a
default config the redirect had nowhere real to land. To read the build off a
released instance at or below 0.2.5, neither this route nor `nautilus version`
inside the container will tell you — see [`GET /healthz`](#get-healthz) for what
does.

The scratch broker on this page sets `ui.enabled: true`, so it takes the first
branch — a `302` with an empty body. Ask for the head, not the body:

```bash
curl -sS -i "$NAUTILUS/" | head -3
```

<!-- not-executed: response head, not a command -->
```http
HTTP/1.1 302 Found
location: /admin
```

`location: /admin` is the mount point; FastAPI then sends `/admin` → `/admin/` →
`/admin/playground`. `curl -L` walks all three.

With `ui.enabled: false` — the default, and what a fresh deployment has —
`curl -sS "$NAUTILUS/"` returns `200` and this body instead:

<!-- not-executed: this is the ui.enabled: false response; the scratch broker above has the console on -->
```json
{
  "service": "nautilus",
  "version": "0.2.6.dev0",
  "admin_console": "disabled (set ui.enabled: true to serve /admin)",
  "routes": {
    "openapi": "/docs",
    "liveness": "/healthz",
    "readiness": "/readyz",
    "metrics": "/metrics",
    "request": "POST /v1/request",
    "sources": "/v1/sources"
  }
}
```

---

## OpenAPI

FastAPI registers these four; they are the machine-readable half of this page.

### `GET /openapi.json`

The generated OpenAPI 3.1 document for every route with `include_in_schema`
left on. **No credential.**

Six routes set `include_in_schema=False` and are absent from it: `GET /metrics`,
`GET /`, `GET /admin/`, `GET /admin/login`, `POST /admin/login` and
`GET /admin/logout`. So are the four routes in this group and the
`/admin/static` mount. This page is their reference.

**Status codes:** `200` on this build. **On every release up to and including
0.2.5, `500 Internal Server Error`** — `nautilus/ui/dependencies.py` and
`nautilus/ui/sse.py` imported `Broker` under `if TYPE_CHECKING:` while the module
used `from __future__ import annotations`, so the admin routes' annotations were
strings FastAPI could not resolve, and schema generation raised
`PydanticUserError: ... is not fully defined`. The console router was mounted
unconditionally on those builds, so the failure was unconditional too. `/docs`
and `/redoc` still answer `200` there — they are HTML shells — but the document
they fetch is the `500`, so both render empty in a browser. Both modules now
import `Broker` at runtime, with a comment saying why.

```bash
curl -sS "$NAUTILUS/openapi.json" | jq '{title: .info.title, version: .info.version, paths: (.paths | keys | length)}'
```

```json
{"title": "Nautilus", "version": "0.2.6.dev0", "paths": 30}
```

`info.version` is the build, taken from the installed distribution's metadata —
the same string [`GET /healthz`](#get-healthz) reports. It used to be the literal
`"0.1.0"`, FastAPI's default for the `version=` argument, which named no build
that has ever existed; every release up to 0.2.5 carries it (in the schema they
`500` on producing).

That count is with `ui.enabled: true`; with the console off it drops by the nine
`/admin` paths that do appear in the schema.

### `GET /docs`

Swagger UI over `/openapi.json`. **No credential.**

**Status codes:** `200` only, `text/html`.

```bash
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' "$NAUTILUS/docs"
```

<!-- not-executed: command output, not a command -->
```
200 text/html; charset=utf-8
```

### `GET /docs/oauth2-redirect`

The OAuth2 redirect target Swagger UI posts back to after an authorization
flow. **No credential.** Nautilus declares no OAuth2 flow — it authenticates
with `X-API-Key` — so nothing reaches this route in practice; it is registered
because FastAPI mounts it alongside `/docs`.

**Status codes:** `200` only, `text/html`.

```bash
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' "$NAUTILUS/docs/oauth2-redirect"
```

<!-- not-executed: command output, not a command -->
```
200 text/html; charset=utf-8
```

### `GET /redoc`

ReDoc over the same document. **No credential.**

**Status codes:** `200` only, `text/html`.

```bash
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' "$NAUTILUS/redoc"
```

<!-- not-executed: command output, not a command -->
```
200 text/html; charset=utf-8
```

---

## Admin console

Registered **only** when `ui.enabled: true`; every path below is a `404`
otherwise. Pages return HTML, not JSON. Authentication accepts either
`X-API-Key` or the `nautilus_key` cookie that `POST /admin/login` sets.

Browsers get a redirect where an API client gets a status: a `401` on a request
whose `Accept` contains `text/html` becomes `302 → /admin/login`; without it the
plain `401` is returned, so `curl` and tests see the real code. A `403` is
rendered as an HTML error page carrying status `403`; its body quotes the same
refusal the JSON routes emit — `This credential does not hold the 'audit_read'
capability (it holds ['query'])` — so the fix is the same: use a key whose
`capabilities` list holds it. A request that arrives before lifespan startup
gets a `503` HTML page that re-fetches itself every 5 s until the broker is up.

Every read page returns the full page normally and only the table-body partial
when the request carries `HX-Request: true` (HTMX swap).

### `GET /admin/`

Redirects to `/admin/playground`. No credential.

**Status codes:** `302` only, `location: /admin/playground`.

```bash
curl -sS -i "$NAUTILUS/admin/" | head -3
```

<!-- not-executed: response head, not a command -->
```http
HTTP/1.1 302 Found
location: /admin/playground
```

### `GET /admin/login`

The API-key login form. No credential. Optional query param `error` is rendered
back into the page.

**Status codes:** `200` only, `text/html`.

```bash
curl -sS "$NAUTILUS/admin/login" | head -8
```

<!-- not-executed: page excerpt, not a command -->
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Nautilus — Login</title>
```

### `POST /admin/login`

Exchange an API key for the `nautilus_key` session cookie
(`httponly`, `samesite=lax`, `max_age=86400`). No prior credential.

**Body:** `application/x-www-form-urlencoded`, field `api_key`.

**Status codes**

| Code | Meaning |
| --- | --- |
| `302` → `/admin/sources` | Key accepted; `Set-Cookie: nautilus_key=…` |
| `401` | Key rejected — the login page is re-rendered with `Invalid API key` |
| `422` | `api_key` field missing: `{"detail": [{"type": "missing", "loc": ["body", "api_key"], "msg": "Field required", "input": null}]}` |

```bash
curl -sS -i -X POST "$NAUTILUS/admin/login" \
  --data-urlencode "api_key=$KEY" | head -4
```

<!-- not-executed: response head, not a command -->
```http
HTTP/1.1 302 Found
location: /admin/sources
set-cookie: nautilus_key=my-secret-key; HttpOnly; Max-Age=86400; Path=/; SameSite=lax

# behind TLS (or an ingress sending X-Forwarded-Proto: https) the same line ends `; Secure`
```

### `GET /admin/logout`

Clears the `nautilus_key` cookie and redirects. No credential.

**Status codes:** `302` → `/admin/login`, with `Set-Cookie` expiring the cookie.

```bash
curl -sS -i "$NAUTILUS/admin/logout" | head -3
```

<!-- not-executed: response head, not a command -->
```http
HTTP/1.1 302 Found
location: /admin/login
```

### `GET /admin/playground`

Interactive query page. Capability `query`.

**Status codes:** `200` (`text/html`) · `302 → /admin/login` for an
unauthenticated browser · `401` for an unauthenticated API client ·
`403` (HTML error page) without `query`.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' "$NAUTILUS/admin/playground" -H "X-API-Key: $KEY"
```

<!-- not-executed: command output, not a command -->
```
200
```

### `POST /admin/api/query`

What the playground page posts to. Capability `query`. Same body as
`POST /v1/request`, same broker, same exposure ledger — it exists only so the
browser can authenticate with the httponly cookie instead of a header.

**Status codes** — note these are `JSONResponse` bodies keyed `error`, not
FastAPI's `detail`:

| Code | Body |
| --- | --- |
| `200` | A full `BrokerResponse`, identical in shape to `POST /v1/request` |
| `400` | `{"error": "Invalid JSON"}` · `{"error": "intent is required"}` |
| `401` | `{"error": "Not authenticated"}` |
| `403` | `{"error": "This credential does not hold the 'query' capability (it holds ['audit_read'])"}` · `{"error": "This credential is bound to agent_id='analyst', so it cannot ask as 'other'"}` · `{"error": "session_not_yours: session 's-1' belongs to another principal. A session id is not a credential — either use your own, or have its owner declare a handoff to agent_id='analyst' in it first."}` |
| `500` | `{"error": "<exception message>"}` — anything the broker raised that is not one of the above |
| `503` | `{"error": "Broker not ready"}` · busy, with `Retry-After: 1` · `{"error": "Nautilus could not record this request: <os error>"}` with `Retry-After: 5` |

```bash
curl -sS -X POST "$NAUTILUS/admin/api/query" -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"analyst","intent":"orders","context":{"purpose":"fraud-review"}}'
```

```json
{
  "request_id": "9ca8ea18-fd02-4c03-91bc-eba634b080c6",
  "data": {"orders": [{"order_id": 1001, "user_id": 42, "total": 19.99}]},
  "sources_queried": ["orders"],
  "sources_denied": [],
  "outcome": "allowed",
  "duration_ms": 3
}
```

### `GET /admin/sources`

Source-status page. Capability `query`. Applies the same clearance filter
`GET /v1/sources` applies, and never renders `SourceConfig.connection` —
credentials and DSNs stay out of the template.

**Status codes:** `200` · `302`/`401` unauthenticated · `403` without `query` ·
`503` (HTML page that auto-refreshes every 5 s) while the broker is starting.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' "$NAUTILUS/admin/sources" -H "X-API-Key: $KEY"
```

<!-- not-executed: command output, not a command -->
```
200
```

Add `-H 'HX-Request: true'` to get just `partials/source_table_body.html`.

### `GET /admin/sources/events`

Server-sent events stream of source-table updates, one `source-update` event
every 5 s until the client disconnects. Authenticated by `get_auth_user`
(header or cookie). `data` is the rendered HTML table body the page swaps in.

**Status codes:** `200`, `text/event-stream` · `401` unauthenticated.

<!-- not-executed: long-lived stream; interrupt with Ctrl-C -->
```bash
curl -sS -N "$NAUTILUS/admin/sources/events" -H "X-API-Key: $KEY"
```

<!-- not-executed: stream excerpt, not a command -->
```
event: source-update
data: <tr><td>orders</td><td>static</td><td>unclassified</td>…</tr>
```

### `GET /admin/decisions`

Decision list with filters. Capability `audit_read`.

| Query param | Meaning |
| --- | --- |
| `agent_id` | Exact match |
| `start` / `end` | ISO-8601 window |
| `outcome` | `denied` (entry has denial records) or `allowed` (it has none) |
| `search` | Free text over `request_id`, `agent_id`, `raw_intent` |

**Status codes:** `200` · `302`/`401` unauthenticated · `403` without
`audit_read` · `503` while the broker is starting.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  "$NAUTILUS/admin/decisions?outcome=denied" -H "X-API-Key: $KEY"
```

<!-- not-executed: command output, not a command -->
```
200
```

With `HX-Request: true` the response is the `<tr>` rows alone, or an
`<div class="empty-state"><p>No decisions found</p></div>` row when nothing
matched.

### `GET /admin/decisions/{request_id}`

Detail fragment for one decision — rule trace, routing decisions, scope
constraints, denial records, facts summary. Capability `audit_read`.

**Status codes:** `200` · `302`/`401` · `403` · `503`. There is **no `404`**: an
unknown `request_id` is a `200` carrying the empty-state fragment, because the
fragment is swapped into a modal.

<!-- not-executed: REQUEST_ID comes from a POST /v1/request response -->
```bash
REQUEST_ID=16a7fa67-a3da-4eeb-af49-a88f26fb6c11
curl -sS "$NAUTILUS/admin/decisions/$REQUEST_ID" -H "X-API-Key: $KEY"
```

For an id that is genuinely not in the log:

<!-- not-executed: response body, not a command -->
```html
<div class="empty-state"><p>Decision not found</p></div>
```

The whole log is paged, the same scan `GET /v1/audit/{request_id}` performs — so
"not found" means not present, not merely old. It used to read one page, which
made every decision past the newest 50 report as missing.

### `GET /admin/audit`

Full audit log, cursor-paginated, with a page-level attestation-chain badge.
Capability `audit_read`.

| Query param | Meaning |
| --- | --- |
| `agent_id`, `source_id`, `event_type` | Exact-match filters |
| `start` / `end` | ISO-8601 window |
| `cursor` | Opaque cursor from the pagination fragment |
| `sort` | `-timestamp` (desc, default) or `timestamp` (asc) |

**Status codes:** `200` · `302`/`401` · `403` without `audit_read` · `503` while
the broker is starting.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  "$NAUTILUS/admin/audit?sort=-timestamp" -H "X-API-Key: $KEY"
```

<!-- not-executed: command output, not a command -->
```
200
```

The chain badge runs a full offline verification of the chained attestation log
— hash linkage plus every JWS — cached until the file changes, and skipped
entirely on `HX-Request` row refreshes so pagination does not re-verify.

### `GET /admin/attestation`

Attestation-verification form. Capability `audit_read`. The page reports whether
a signing key is configured on this broker.

**Status codes:** `200` · `302`/`401` · `403` without `audit_read`.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' "$NAUTILUS/admin/attestation" -H "X-API-Key: $KEY"
```

<!-- not-executed: command output, not a command -->
```
200
```

### `POST /admin/attestation/verify`

Verify an EdDSA JWT against the broker's attestation public key. Capability
`audit_read`.

**Body:** `application/x-www-form-urlencoded`, field `token`.

**Status codes:** `200` (`text/html` result card — **including for an invalid
token**; validity is in the card, not the status) · `302`/`401` · `403` ·
`422` when `token` is missing.

```bash
curl -sS -X POST "$NAUTILUS/admin/attestation/verify" -H "X-API-Key: $KEY" \
  --data-urlencode 'token=not.a.jwt' | head -4
```

<!-- not-executed: page excerpt, not a command -->
```html
<div class="card" style="margin-top:1rem">
  <h2><span class="badge badge-danger">Invalid</span> Verification Result</h2>
```

The card carries one of four errors, verbatim: `Attestation not configured on
this broker instance` (set `attestation.enabled: true`), `Token has expired`,
the PyJWT `InvalidTokenError` message, or nothing at all with a
`badge-success` **Valid** badge and the decoded claims. The token itself is
echoed back truncated to 64 characters.

### `GET /admin/static/{path}`

Static assets for the console (`nautilus/ui/static`), mounted with
`StaticFiles` under the name `admin-static`. No credential.

**Status codes:** `200` with the file · `404` when the path does not exist under
the static directory.

```bash
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' "$NAUTILUS/admin/static/styles.css"
```

<!-- not-executed: command output, not a command -->
```
200 text/css; charset=utf-8
```

A path with no file under that directory is `404 {"detail":"Not Found"}`.
