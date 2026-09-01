# HTTP transport

Failures produced by the REST surface itself — readiness, limits, request validation and route
lookups — before or around the policy decision. Source: `nautilus/transport/fastapi_app.py`.

`curl` examples assume the [scratch broker](index.md#a-scratch-broker) on
`127.0.0.1:8001` and `export NAUTILUS=http://127.0.0.1:8001`.

## Readiness

### `Broker not ready`

**HTTP 503.** Raised on `/v1/request`, `/v1/query`, `/v1/keys/rotate`,
`/v1/keys/{kid}/revoke`, `/v1/adapters/{name}/schema`, `/v1/rules/{rule_name}/lineage` and
`/v1/audit` (`nautilus/transport/fastapi_app.py:583`, `:940`, `:978`, `:1066`, `:1413`,
`:1637`).

**Means.** `app.state.broker` is unset: the ASGI lifespan has not finished, or it failed.

**Fix.** Read the startup log — the real cause (a `ConfigError`, an unreachable session store) is
there. `/readyz` reports the same condition as `startup_incomplete`.

### `/readyz` refusal payloads

`/readyz` returns **200** `{"status": "ok"}` or **503** with a `reason`
(`nautilus/transport/fastapi_app.py:759-806`). The four reasons are checked in this order, and the
first one to fire is the one you get.

<!-- not-executed: needs the scratch broker from index.md -->
```bash
curl -s -o /dev/null -w '%{http_code} ' "$NAUTILUS/readyz"; curl -s "$NAUTILUS/readyz"; echo
```

#### `{"status": "not_ready", "reason": "startup_incomplete"}`

**HTTP 503.** `nautilus/transport/fastapi_app.py:763-766`. `app.state.broker` is `None` or
`app.state.ready` is false: the lifespan has not finished, or it failed. Nothing is interpolated.

**Means.** The process is listening but the broker was never built. This is the normal answer for
the second or two between the socket opening and the config loading, and the permanent answer when
the config is bad.

**Fix.** Read the startup log — the `ConfigError`, driver import failure or unreachable session
store is printed there, and `serve` exits **2** with
`ERROR: broker construction failed: {exc}` when the failure is at construction time.

#### `{"status": "not_ready", "reason": "<audit probe text>"}`

**HTTP 503.** `nautilus/transport/fastapi_app.py:772-774`. The `reason` is the string returned by
`broker.audit_logger.probe()` — free text from the sink, not a fixed vocabulary. A `FileSink`
whose directory went read-only reports the `OSError` text.

**Means.** The audit sink is checked before the session store, because an audit entry is written
before any request answers: a sink that stopped accepting writes fails every request. Nautilus
refuses to serve what it cannot account for.

**Fix.** Restore write access to `audit.path`, or point it somewhere writable and restart. The
matching per-request failure is
[`Nautilus could not record this request…`](#nautilus-could-not-record-this-request-and-will-not-serve-what-it-cannot-account-for-exc).

<!-- not-executed: needs the scratch broker from index.md -->
```bash
chmod a-w /tmp/nautilus-errors/audit.jsonl && curl -s "$NAUTILUS/readyz"; echo
chmod u+w /tmp/nautilus-errors/audit.jsonl
```

#### `{"status": "not_ready", "reason": "session_store_timeout"}`

**HTTP 503.** `nautilus/transport/fastapi_app.py:800-802`. The sentinel read of
`_READY_PROBE_KEY` (`_ready_probe_`) or the `averify_schema()` re-check exceeded
`_READY_PROBE_TIMEOUT_S` — **2.0 seconds**. Nothing is interpolated; the reason is this literal
string.

**Means.** The store is reachable but not answering. Both probes are bounded on purpose: a store
that is *down* answers fast, and a store that is frozen never answers at all, so an unbounded
probe is one the kubelet gives up on — the pod never drains and every probe leaves a wedged
handler.

**Fix.** Check the store's own health and its connection pool. If the pool is merely saturated you
will also see `session-store pool exhausted: …` in the log
(see [sessions.md](sessions.md)).

#### `{"status": "not_ready", "reason": "{type(exc).__name__}"}`

**HTTP 503.** `nautilus/transport/fastapi_app.py:803-805`. Any other exception from the store,
reported as its **class name only** — never its message, so a DSN in an exception string cannot
leak through a probe endpoint that needs no credentials.

`{type(exc).__name__}` interpolates to values such as:

| `reason` | What happened |
| --- | --- |
| `SessionSchemaError` | The shared store was migrated under a pod that has not been replaced yet — the schema stamp no longer matches this build. Expected mid-rollout; it drains this pod instead of letting it read-modify-write rows it does not understand. |
| `SessionStoreError` | The backend refused the sentinel read. |
| `ConnectionRefusedError`, `OSError` | The store is not accepting connections. |

**Fix.** The class name alone will not tell you why. The full exception, message included, is in
the broker log at the moment the probe ran.

`/healthz` and `/metrics` never gate — a full request queue must not take the pod out of
rotation and turn saturation into a restart loop.

```bash
curl -s "$NAUTILUS/readyz"; echo
curl -s "$NAUTILUS/healthz"; echo
```

## Limits

### `Request body is {declared} bytes; this broker accepts at most {limit} (api.max_request_bytes).`

**HTTP 413.** `_send_too_large`, `nautilus/transport/fastapi_app.py:300-320`. Answered from
`Content-Length` before a single byte of body is read.

**Means.** The declared body size exceeds `api.max_request_bytes`. The audit entry stores the
raw intent three times, so an unbounded body is a write amplifier onto the audit volume — and
that volume is the fail-closed path.

**Fix.** Send less, or raise `api.max_request_bytes`. The scratch config sets 4096.

```bash
python - <<'PY' > /tmp/nautilus-big-body.json
import json
print(json.dumps({"agent_id": "analyst", "intent": "x" * 8000}))
PY
curl -s -X POST "$NAUTILUS/v1/request" \
  -H 'X-API-Key: query-key' -H 'Content-Type: application/json' \
  --data-binary @/tmp/nautilus-big-body.json
```

### `request body exceeded api.max_request_bytes ({self.max_bytes} bytes)`

**`BodyTooLargeError`** (`nautilus/transport/fastapi_app.py:241`), raised at `:280-283`.

**Means.** The same limit, hit by a client that sent **no** `Content-Length` — a chunked upload,
counted as it streams. There is no clean JSON response here: the read is aborted mid-body, so
the client sees a dropped connection and the server logs this exception. Deliberately less
graceful than the 413.

**Fix.** Send `Content-Length` to get the 413 instead, or stay under the limit.

### `Broker busy: {limit} requests are already in flight (api.max_concurrent_requests). Retry.`

**HTTP 503** with `Retry-After: 1`. `_send_busy`, `nautilus/transport/fastapi_app.py:360-380`.

**Means.** `api.max_concurrent_requests` are in flight and this one was refused rather than
queued behind them. Per-request work is dominated by synchronous CPU on one event loop, so
offered concurrency buys latency, not throughput: without this, requests still returned 200 —
some after 17 seconds — and nothing in front of the broker could tell saturation from health.

**Not 429.** The caller did nothing wrong and the identical request will succeed later.

**Fix.** Retry after the interval. To serve more, add replicas; raising
`api.max_concurrent_requests` mostly converts refusals back into latency. `/healthz`, `/readyz`
and `/metrics` are exempt, so a saturated broker is still probeable.

<!-- not-executed: needs enough concurrent load to fill api.max_concurrent_requests; outcome is timing-dependent -->
```bash
for i in $(seq 1 64); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST "$NAUTILUS/v1/request" \
    -H 'X-API-Key: query-key' -H 'Content-Type: application/json' \
    -d '{"agent_id":"analyst","intent":"list notes"}' &
done | sort | uniq -c
wait
```

### `Nautilus could not record this request and will not serve what it cannot account for: {exc}`

**HTTP 503** with `Retry-After: 5`. `nautilus/transport/fastapi_app.py:655-668`, on any `OSError`
from the audit sink. `{exc}` is the OS error — typically `[Errno 28] No space left on device` or
a permission failure on `audit.path`.

**Means.** The recorder is down. Failing closed is the design: an unrecorded decision is not
served. This is not a bad request.

**Fix.** Free space or fix permissions on `audit.path`. `/readyz` reports the same sink, so the
pod drains itself; it recovers without a restart once writes succeed.

## Request validation

### `context['scope_constraints'] entry is not a scope constraint: {reasons}`

**HTTP 400.** `nautilus/core/broker.py:2224-2228`, surfaced by
`nautilus/transport/fastapi_app.py:670-677`. Rendered example:

```text
context['scope_constraints'] entry is not a scope constraint:
source_id: Field required; field: Field required; operator: Field required; value: Field required
```

**Means.** A caller-supplied entry in `context.scope_constraints` did not validate as a
`ScopeConstraint`. `{reasons}` lists each missing or wrong field. Before this existed the same
input left as a 500.

**Fix.** Each entry needs `source_id`, `field`, `operator` and `value`; `operator` must be in the
allowlist (see [adapters.md](adapters.md)).

```bash
curl -s -X POST "$NAUTILUS/v1/request" \
  -H 'X-API-Key: query-key' -H 'Content-Type: application/json' \
  -d '{"agent_id":"analyst","intent":"list notes","context":{"scope_constraints":[{"nope":1}]}}'
```

### `invalid datetime: {value!r}`

**HTTP 400.** `_parse_audit_dt`, `nautilus/transport/fastapi_app.py:1648-1660`. The `start` or
`end` query parameter on `GET /v1/audit` is not ISO-8601. Parsed with
`datetime.fromisoformat`, so `2026-01-01T00:00:00Z` and `2026-01-01` both work.

```bash
curl -s "$NAUTILUS/v1/audit?start=yesterday" -H 'X-API-Key: govern-key'
```

## Lookups

### `Adapter '{name}' not found`

**HTTP 404.** `nautilus/transport/fastapi_app.py:1072-1077`. `{name}` is the path segment of
`GET /v1/adapters/{name}/schema` and must be a configured **source id**, not a source type.
`GET /v1/adapters` lists what exists.

```bash
curl -s "$NAUTILUS/v1/adapters/nosuch/schema" -H 'X-API-Key: query-key'
curl -s "$NAUTILUS/v1/adapters" -H 'X-API-Key: query-key'
```

### `Adapter '{name}' does not support schema introspection`

**HTTP 501.** The adapter exists but cannot introspect: it carries no `get_schema()`
attribute at all, or it inherits the protocol default, which raises
`NotImplementedError("AC-21.b: this adapter must implement get_schema() (task-006)")` —
see [library.md](library.md). Both are permanent. This used to answer `503` for the
second, far more common case, telling clients to retry a method that will never exist.

### `Schema fetch failed: {exc}`

**HTTP 503.** `get_schema()` ran and raised something other than `NotImplementedError`, so
the condition is transient. `{exc}` carries the adapter's own message — for example
`StaticAdapter.get_schema() called before connect()` on a broker that has served no request
yet (adapters connect lazily), or a driver error for a source whose server is down. Look up
`{exc}` in [adapters.md](adapters.md).

### `audit entry not found: {request_id!r}`

**HTTP 404.** `nautilus/transport/fastapi_app.py:1719-1724`. No audit entry carries that
`request_id`. The id is the one in `BrokerResponse.request_id`. If it is recent, check that
`audit.path` points at the same file this broker writes.

```bash
curl -s "$NAUTILUS/v1/audit/no-such-request" -H 'X-API-Key: govern-key'
```

### `Not Found`

**HTTP 404**, body `{"detail":"Not Found"}`. Starlette's default for an unregistered path — not a
Nautilus message. The registered routes are `/healthz`, `/readyz`, `/metrics`,
`/v1/request`, `/v1/query`, `/v1/sources`, `/v1/adapters`, `/v1/adapters/{name}/schema`,
`/v1/sessions`, `/v1/keys/jwks.json`, `/v1/keys/rotate`, `/v1/keys/{kid}/revoke`,
`/v1/rkm/queue`, `/v1/rkm/queue/{proposal_id}`, `/v1/rkm/queue/{proposal_id}/approve`,
`/v1/rkm/queue/{proposal_id}/reject`, `/v1/rules`, `/v1/rules/{rule_name}/lineage`,
`/v1/rules/{rule_name}/retract`, `/v1/rules/{rule_name}/rollback`, `/v1/audit` and
`/v1/audit/{request_id}`.

```bash
curl -s "$NAUTILUS/v1/nope" -H 'X-API-Key: query-key'
```
