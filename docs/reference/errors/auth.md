# Credentials, capabilities and identity

Refusals raised before a request reaches the policy engine. All of them come from
`nautilus/transport/auth.py` or the dependency wiring in
`nautilus/transport/fastapi_app.py`; the MCP transport reuses the same sentences via
`nautilus/transport/mcp_server.py`.

`curl` examples assume the [scratch broker](index.md#a-scratch-broker) on
`127.0.0.1:8001` and `export NAUTILUS=http://127.0.0.1:8001`.

## `Not authenticated`

**HTTP 401.** FastAPI's `APIKeyHeader(name="X-API-Key", auto_error=True)`
(`nautilus/transport/auth.py`, `api_key_header`) answers before any Nautilus code runs, and
`nautilus/ui/dependencies.py:62` emits the same sentence for the admin console.

**Means.** The `X-API-Key` header was absent — not wrong, absent.

**Happens when.** A client forgot the header; a proxy stripped it; or the broker is in
`api.auth.mode: api_key` (the default) while the caller was written for `proxy_trust`.

**Fix.** Send the header. Every route except `/healthz`, `/readyz` and `/metrics` requires it.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$NAUTILUS/v1/request" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"analyst","intent":"list notes"}'
```

## `API key required`

**HTTP 401.** `nautilus/transport/auth.py:220-226`, raised by `verify_api_key` when the
operator-configured allow-list is empty.

**Means.** `api.keys` has zero entries, so nobody is allowed. This is fail-closed on purpose: an
empty allow-list means "nobody", never "everybody".

**Happens when.** `nautilus.yaml` omits `api.keys`, or an environment interpolation produced an
empty list.

**Fix.** Add at least one entry under `api: keys:`. `nautilus init` writes one. The broker also
warns at startup — look for this line in the log before the first request arrives:

```text
api.keys is empty, so every data and governance route will answer 401 Not authenticated.
Only /healthz, /readyz and /metrics are reachable. Add a key under 'api: keys:' —
'nautilus init' writes one for you.
```

(`nautilus/transport/fastapi_app.py:192-198`, one `log.warning` line.)

```bash
python - <<'PY'
from fastapi import HTTPException
from nautilus.transport.auth import verify_api_key
try:
    verify_api_key("anything", [])
except HTTPException as exc:
    print(exc.status_code, exc.detail)
PY
```

## `Invalid API key`

**HTTP 401.** `nautilus/transport/auth.py:230-233`.

**Means.** The header was present and matched none of the configured keys. Comparison is
`secrets.compare_digest` per entry, so a near-miss and a wild guess take the same time.

**Happens when.** Wrong environment's key; trailing whitespace or a newline captured by
`$(cat keyfile)`; the key was rotated in config but not in the client.

**Fix.** Compare against the `key:` values in `api.keys`. Keys are matched whole — no prefix
matching, no fallback to "any configured key".

```bash
curl -s -X POST "$NAUTILUS/v1/request" \
  -H 'X-API-Key: wrong-key' -H 'Content-Type: application/json' \
  -d '{"agent_id":"analyst","intent":"list notes"}'
```

## `This credential does not hold the {capability!r} capability (it holds {sorted(held)})`

**HTTP 403.** `capability_refusal`, `nautilus/transport/auth.py:194`. Rendered example:

```text
This credential does not hold the 'audit_read' capability (it holds ['query'])
```

**Interpolates.** `{capability!r}` — what the route required. `{sorted(held)}` — what the
matched `api.keys` entry declares under `capabilities`.

**Means.** The key authenticated, but it is not scoped for this route. The four capabilities are
`query`, `audit_read`, `govern`, `keys` (`CAPABILITIES` in `nautilus/config/models.py`;
`ALL_CAPABILITIES` in `nautilus/transport/auth.py`).

| Capability | Routes |
| --- | --- |
| `query` | `/v1/request`, `/v1/query`, `/v1/sources`, `/v1/adapters`, `/v1/adapters/{name}/schema`, `/v1/sessions`, `/v1/rules` |
| `audit_read` | `/v1/audit`, `/v1/audit/{request_id}` |
| `govern` | `/v1/rkm/queue…`, `/v1/rules/{rule_name}/lineage`, `/retract`, `/rollback` |
| `keys` | `/v1/keys/rotate`, `/v1/keys/{kid}/revoke` |

**Fix.** Add the capability to that key's `capabilities` list, or call with a key that has it.
A key entry written as a bare string (`keys: ["secret"]`) holds *all* capabilities — the
refusal only exists for the `{key, agent_id, capabilities}` form.

```bash
curl -s "$NAUTILUS/v1/audit" -H 'X-API-Key: query-key'
```

## `This credential is bound to agent_id={bound!r}, so it cannot ask as {body.agent_id!r}`

**HTTP 403.** `nautilus/transport/fastapi_app.py:679-685`. The MCP transport raises the same
sentence as a tool error (`nautilus/transport/mcp_server.py:413-417`, with `{agent_id!r}` in
place of `{body.agent_id!r}`). Rendered example:

```text
This credential is bound to agent_id='analyst', so it cannot ask as 'other'
```

**Means.** The `api.keys` entry that authenticated declares `agent_id: analyst`; the request
body claimed a different `agent_id`. The key decides who is calling, not the body.

**Happens when.** One shared key is used for several agents; or a client hard-codes
`agent_id` while the deployment issued per-agent keys.

**Fix.** Send `agent_id` matching the key's binding, or issue one key per agent. To let one
credential speak for many agents, drop `agent_id` from that `api.keys` entry — note that this
also removes the binding that makes cross-agent handoff meaningful.

```bash
curl -s -X POST "$NAUTILUS/v1/request" \
  -H 'X-API-Key: query-key' -H 'Content-Type: application/json' \
  -d '{"agent_id":"other","intent":"list notes"}'
```

## `This credential is bound to agent_id={bound!r}, so it cannot mint a session token for {requested_agent!r}`

**HTTP 403.** `nautilus/transport/fastapi_app.py:1007-1013`, on `POST /v1/sessions`.

**Means.** Same binding rule, applied to token minting. Without it a key bound to a low-clearance
agent could mint a broker-valid token naming a high-clearance one, and the token verifies against
the deliberately-unauthenticated JWKS at `/v1/keys/jwks.json`.

**Fix.** Mint with the key bound to that agent. `clearance` in the request body is ignored
regardless — it is read from the agent registry inside `Broker.issue_session_token`.

```bash
curl -s -X POST "$NAUTILUS/v1/sessions" \
  -H 'X-API-Key: query-key' -H 'Content-Type: application/json' \
  -d '{"session_id":"s1","agent_id":"someone-else","purpose":"research"}'
```

## `Forwarded identity rejected: peer is not a trusted proxy`

**HTTP 401.** `nautilus/transport/auth.py:319-323`, `_vet_forwarded_user`.

**Means.** `api.auth.mode` is `proxy_trust`, so `X-Forwarded-User` *is* the credential — and the
socket peer address is not inside any entry of `api.auth.trusted_proxies`.

**Happens when.** The broker is reached directly instead of through the mesh; the ingress was
renumbered; the pod CIDR changed; `trusted_proxies` lists the load-balancer's public address
while the connection arrives from its private one.

**Fix.** Put the real peer address in `api.auth.trusted_proxies`. Entries are addresses or CIDR
blocks parsed with `ipaddress`. The peer Nautilus sees is `request.client.host` — the address of
whatever opened the TCP connection, not the contents of `X-Forwarded-For`.

## `Missing X-Forwarded-User`

**HTTP 401.** `nautilus/transport/auth.py:324-329`.

**Means.** The peer is trusted but the header is absent or empty. A trusted proxy should always
set it, so a missing header reads as a bypass attempt rather than an oversight.

**Fix.** Configure the upstream (mTLS/SPIFFE/OIDC) to set `X-Forwarded-User` on every proxied
request, including health-check and retry paths.

## `X-Nautilus-Reviewer header required`

**HTTP 400.** `_require_reviewer`, `nautilus/transport/fastapi_app.py:1372-1380`.

**Means.** A governance route needs a human identity to write into the audit record and the
credential could not supply one. The header is only consulted when the `api.keys` entry has no
`agent_id`; a bound key supplies the reviewer itself.

**Raised by.** `POST /v1/rkm/queue/{proposal_id}/approve`, `…/reject`,
`POST /v1/rules/{rule_name}/retract`, `POST /v1/rules/{rule_name}/rollback`.

**Fix.** Send `X-Nautilus-Reviewer: <operator identity>` (`X-Reviewer` is accepted as an alias),
or bind the key with `agent_id`.

## Startup warning: bare string keys

```text
api.keys[0] is a bare string: bound to no agent_id, so it can ask as any agent and call
every governance route. Use the {key, agent_id, capabilities} form to scope it.
```

`nautilus/transport/fastapi_app.py:201-208`. The index and the pluralisation change with the
number of bare entries — `api.keys[0] is` for one, `api.keys[0, 2] are` for several.

**Fix.** Rewrite each entry as a mapping:

```yaml
api:
  keys:
    - key: query-key
      agent_id: analyst
      capabilities: [query]
```

## Auth configuration refused at startup

These are `ConfigError`s wrapping pydantic validation; see [config.md](config.md) for the
`Config validation failed:` envelope they arrive in.

### `api.auth.mode 'proxy_trust' requires api.auth.trusted_proxies. Without it, X-Forwarded-User is settable by anyone who can reach the port, so every caller can assert every identity.`

`nautilus/config/models.py:508-513`. Set `api.auth.trusted_proxies` to the ingress addresses, or
return to `api.auth.mode: api_key`.

### `api.auth.trusted_proxies entry {entry!r} is not an address or CIDR block: {exc}`

`nautilus/config/models.py:517-522`. `{exc}` is the `ipaddress` parse failure. Use
`10.0.0.0/8`, `192.168.1.7`, or an IPv6 equivalent — hostnames are not resolved.

### `api.keys entry declares unknown capabilities {unknown}. Known capabilities: {list(CAPABILITIES)}`

`nautilus/config/models.py:482-487`. Rendered example:

```text
api.keys entry declares unknown capabilities ['bogus'].
Known capabilities: ['query', 'audit_read', 'govern', 'keys']
```

Reproduce all three:

```bash
python - <<'PY'
import pathlib, tempfile
from nautilus.config.loader import ConfigError, load_config
d = pathlib.Path(tempfile.mkdtemp())
cases = {
  "proxy_trust": "sources: []\napi:\n  auth:\n    mode: proxy_trust\n",
  "cidr": "sources: []\napi:\n  auth:\n    mode: proxy_trust\n    trusted_proxies: ['not-an-ip']\n",
  "capability": "sources: []\napi:\n  keys:\n    - key: k\n      agent_id: a\n      capabilities: [bogus]\n",
}
for name, text in cases.items():
    p = d / f"{name}.yaml"
    p.write_text(text)
    try:
        load_config(str(p))
    except ConfigError as exc:
        print(f"--- {name} ---\n{exc}")
PY
```
