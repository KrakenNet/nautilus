# Hardening Nautilus

This is the security surface of Nautilus, key by key. Every config key, every
environment variable, every request header, every CLI flag and every route that
changes what the broker will accept, refuse, sign or record has its own entry
below, with the exact string the software prints when it is set wrong.

`nautilus init` writes a config that runs. It does not write a config that is
safe to expose. Working through this page turns the first into the second.

Report a vulnerability through
[SECURITY.md](https://github.com/KrakenNet/nautilus/blob/main/SECURITY.md).
This page is about configuration.

## How to read an entry

Every entry has the same five parts:

- a **signature line** — full dotted path, type, default, and where it is read
  in the source;
- **Defends** — the specific attack or accident it stops;
- **Costs** — what turning it on takes away, so you can decide against it;
- **Fails with** — the literal text Nautilus emits when the key is missing,
  malformed or violated. Copy it into a log search and it will match;
- **Example** — YAML you can paste, and where a control can be demonstrated, a
  command that makes it refuse something.

Conventions for the runnable blocks:

- Every value in an example is literal and will run as written, except values
  written `<LIKE_THIS>`, which are named where they appear and are yours to fill in.
- `$KEY` in a `curl` means the shell variable set by the generation command
  immediately above it. Nothing on this page reads a credential you have not created.
- Blocks assume `nautilus` is on `PATH` (`pip install nautilus-broker`) and a
  config at `/etc/nautilus/nautilus.yaml`. Substitute your own path in `--config`.

## The complete configuration surface

`nautilus.yaml` is validated by a Pydantic model tree rooted at
`nautilus.config.models.NautilusConfig`, which is the authoritative,
machine-readable list of every key. There are **121 distinct keys**. Print all
of them, with types and defaults, at the version you actually have installed:

```bash
python - <<'PY'
import json
from nautilus.config.models import NautilusConfig
print(json.dumps(NautilusConfig.model_json_schema(), indent=2))
PY
```

Of those 121, 22 are container blocks (`api`, `api.auth`, `attestation.sink`,
`rkm.sandbox` and the like) that hold no value of their own, leaving 99 leaf
keys. **81 of them are security-relevant and have their own entry below.** The
other 18 are marked *query shape* in the index: they change which rows an
adapter fetches, not who may fetch them, so they are listed with their type and
default and nothing more — the JSON Schema above is their complete reference.

The index maps every key to the entry that documents it.

**Unknown keys are rejected, everywhere.** Every model sets
`model_config = ConfigDict(extra="forbid")`, so a typo is a startup failure and
never a silently-ignored setting:

```console
$ printf 'sources: []\nsesion_store:\n  backend: memory\n' > /tmp/typo.yaml
$ nautilus serve --config /tmp/typo.yaml
ERROR: invalid config: Config validation failed:
  sesion_store: Extra inputs are not permitted [type=extra_forbidden]
$ echo $?
2
```

The one exception is deliberate: top-level keys beginning `x-` or `_` are
dropped before validation (`NautilusConfig._drop_anchor_blocks`) so YAML anchor
blocks work.

### Index — `api`

| Key | Type | Default | Documented in |
|---|---|---|---|
| `api.host` | `str` | `"127.0.0.1"` | [`api.host`](#apihost) |
| `api.port` | `int` | `8000` | [`api.port`](#apiport) |
| `api.keys` | `list[str \| ApiKeyEntry]` | `[]` | [`api.keys`](#apikeys) |
| `api.keys[].key` | `str` | required | [`api.keys[].key`](#apikeyskey) |
| `api.keys[].agent_id` | `str \| None` | `None` | [`api.keys[].agent_id`](#apikeysagent_id) |
| `api.keys[].capabilities` | `list[str]` | `["query"]` | [`api.keys[].capabilities`](#apikeyscapabilities) |
| `api.auth.mode` | `"api_key" \| "proxy_trust"` | `"api_key"` | [`api.auth.mode`](#apiauthmode) |
| `api.auth.trusted_proxies` | `list[str]` | `[]` | [`api.auth.trusted_proxies`](#apiauthtrusted_proxies) |
| `api.max_request_bytes` | `int \| None` | `1048576` | [`api.max_request_bytes`](#apimax_request_bytes) |
| `api.max_concurrent_requests` | `int \| None` | `64` | [`api.max_concurrent_requests`](#apimax_concurrent_requests) |

### Index — `agents`

| Key | Type | Default | Documented in |
|---|---|---|---|
| `agents.<id>.id` | `str` | required | [`agents.<id>.id`](#agentsidid) |
| `agents.<id>.clearance` | `str` | required | [`agents.<id>.clearance`](#agentsidclearance) |
| `agents.<id>.compartments` | `list[str]` | `[]` | [`agents.<id>.compartments`](#agentsidcompartments) |
| `agents.<id>.subject` | `str \| None` | `None` | [`agents.<id>.subject`](#agentsidsubject) |
| `agents.<id>.default_purpose` | `str \| None` | `None` | [`agents.<id>.default_purpose`](#agentsiddefault_purpose) |
| `agents.<id>.allowed_purposes` | `list[str]` | `[]` | [`agents.<id>.allowed_purposes`](#agentsidallowed_purposes) |

### Index — `sources`

| Key | Type | Default | Documented in |
|---|---|---|---|
| `sources[].id` | `str` | required | [`sources[].id`](#sourcesid) |
| `sources[].type` | `str` | required | [`sources[].type`](#sourcestype) |
| `sources[].classification` | `str` | required | [`sources[].classification`](#sourcesclassification) |
| `sources[].compartments` | `str` | `""` | [`sources[].compartments`](#sourcescompartments) |
| `sources[].data_types` | `list[str]` | required | [`sources[].data_types`](#sourcesdata_types) |
| `sources[].allowed_purposes` | `list[str] \| None` | `None` | [`sources[].allowed_purposes`](#sourcesallowed_purposes) |
| `sources[].purpose_field` | `str` | `""` | [`sources[].purpose_field`](#sourcespurpose_field) |
| `sources[].connection` | `str` | `""` | [`sources[].connection`](#sourcesconnection) |
| `sources[].auth.type` | `"bearer" \| "basic" \| "mtls" \| "none"` | discriminator | [`sources[].auth.type`](#sourcesauthtype) |
| `sources[].auth.token` | `str` | required for `bearer` | [`sources[].auth.token`](#sourcesauthtoken) |
| `sources[].auth.username` | `str` | required for `basic` | [`sources[].auth.username`](#sourcesauthusername-sourcesauthpassword) |
| `sources[].auth.password` | `str` | required for `basic` | [`sources[].auth.password`](#sourcesauthusername-sourcesauthpassword) |
| `sources[].auth.cert_path` | `str` | required for `mtls` | [`sources[].auth.cert_path`](#sourcesauthcert_path-sourcesauthkey_path-sourcesauthca_path) |
| `sources[].auth.key_path` | `str` | required for `mtls` | [`sources[].auth.key_path`](#sourcesauthcert_path-sourcesauthkey_path-sourcesauthca_path) |
| `sources[].auth.ca_path` | `str \| None` | `None` | [`sources[].auth.ca_path`](#sourcesauthcert_path-sourcesauthkey_path-sourcesauthca_path) |
| `sources[].timeout_s` | `float \| None` | `15.0` | [`sources[].timeout_s`](#sourcestimeout_s) |
| `sources[].max_response_bytes` | `int \| None` | `8388608` | [`sources[].max_response_bytes`](#sourcesmax_response_bytes) |
| `sources[].description` | `str` | `""` | query shape |
| `sources[].label` | `str \| None` | `None` | query shape |
| `sources[].sub_category` | `str` | `""` | query shape |
| `sources[].table` | `str \| None` | `None` | query shape |
| `sources[].index` | `str \| None` | `None` | query shape |
| `sources[].model` | `str \| None` | `None` | query shape |
| `sources[].rows` | `list[dict]` | `[]` | query shape (`type: static`) |
| `sources[].top_k` | `int` | `10` | query shape |
| `sources[].embedder` | `"default" \| None` | `None` | query shape |
| `sources[].embedding_column` | `str \| None` | `None` | query shape |
| `sources[].metadata_column` | `str \| None` | `None` | query shape |
| `sources[].distance_operator` | `"<=>" \| "<->" \| "<#>"` | `"<=>"` | query shape |
| `sources[].like_style` | `"starts_with" \| "regex"` | `"starts_with"` | query shape |
| `sources[].endpoints[].path` | `str` | required | query shape (`type: rest`) |
| `sources[].endpoints[].method` | `"GET" \| "POST" \| "PUT" \| "PATCH" \| "DELETE"` | `"GET"` | query shape |
| `sources[].endpoints[].path_params` | `list[str]` | `[]` | query shape |
| `sources[].endpoints[].query_params` | `list[str]` | `[]` | query shape |
| `sources[].endpoints[].operator_templates` | `dict[str, str]` | `{}` | query shape |

### Index — `attestation` and `audit`

| Key | Type | Default | Documented in |
|---|---|---|---|
| `attestation.enabled` | `bool` | `true` | [`attestation.enabled`](#attestationenabled) |
| `attestation.private_key_path` | `str \| None` | `None` | [`attestation.private_key_path`](#attestationprivate_key_path) |
| `attestation.sink.type` | `"null" \| "file" \| "http"` | `"null"` | [`attestation.sink.type`](#attestationsinktype) |
| `attestation.sink.path` | `str` | required for `file` | [`attestation.sink.path`](#attestationsinkpath) |
| `attestation.sink.chained` | `bool` | `false` | [`attestation.sink.chained`](#attestationsinkchained) |
| `attestation.sink.checkpoint_interval` | `int` | `0` | [`attestation.sink.checkpoint_interval`](#attestationsinkcheckpoint_interval) |
| `attestation.sink.url` | `str` | required for `http` | [`attestation.sink.url`](#attestationsinkurl) |
| `attestation.sink.dead_letter_path` | `str \| None` | `None` | [`attestation.sink.dead_letter_path`](#attestationsinkdead_letter_path) |
| `attestation.sink.retry_policy.max_retries` | `int` | `3` | [`attestation.sink.retry_policy`](#attestationsinkretry_policy) |
| `attestation.sink.retry_policy.initial_backoff_s` | `float` | `0.1` | [`attestation.sink.retry_policy`](#attestationsinkretry_policy) |
| `attestation.sink.retry_policy.max_backoff_s` | `float` | `5.0` | [`attestation.sink.retry_policy`](#attestationsinkretry_policy) |
| `audit.path` | `str` | `"./audit.jsonl"` | [`audit.path`](#auditpath) |
| `audit.chained` | `bool` | `false` | [`audit.chained`](#auditchained) |
| `audit.checkpoint_interval` | `int` | `0` | [`audit.checkpoint_interval`](#auditcheckpoint_interval) |

### Index — sessions

| Key | Type | Default | Documented in |
|---|---|---|---|
| `session_tokens.enabled` | `bool` | `false` | [`session_tokens.enabled`](#session_tokensenabled) |
| `session_tokens.ttl_seconds` | `int` | `3600` | [`session_tokens.ttl_seconds`](#session_tokensttl_seconds) |
| `session_tokens.key_ring_path` | `str \| None` | `None` | [`session_tokens.key_ring_path`](#session_tokenskey_ring_path) |
| `session_tokens.broker_instance_id` | `str \| None` | `None` | [`session_tokens.broker_instance_id`](#session_tokensbroker_instance_id) |
| `session_store.backend` | `"memory" \| "postgres" \| "sqlite"` | `"memory"` | [`session_store.backend`](#session_storebackend) |
| `session_store.dsn` | `str \| None` | `None` | [`session_store.dsn`](#session_storedsn) |
| `session_store.on_failure` | `"fail_closed" \| "fallback_memory" \| "fallback_sqlite"` | `"fail_closed"` | [`session_store.on_failure`](#session_storeon_failure) |
| `session_store.sqlite_path` | `str` | `"./.nautilus/sessions.db"` | [`session_store.sqlite_path`](#session_storesqlite_path) |
| `session_store.ttl_seconds` | `int` | `3600` | [`session_store.ttl_seconds`](#session_storettl_seconds) |
| `session_store.purpose_ttl_seconds` | `int` | `0` | [`session_store.purpose_ttl_seconds`](#session_storepurpose_ttl_seconds) |
| `session_store.lock_timeout_s` | `float \| None` | `30.0` | [`session_store.lock_timeout_s`](#session_storelock_timeout_s) |
| `session_store.acquire_timeout_s` | `float` | `10.0` | [`session_store.acquire_timeout_s`](#session_storeacquire_timeout_s) |
| `session_store.pool_min_size` | `int` | `1` | [`session_store` pool sizes](#session_storepool_min_size-pool_max_size-lock_pool_max_size) |
| `session_store.pool_max_size` | `int` | `10` | [`session_store` pool sizes](#session_storepool_min_size-pool_max_size-lock_pool_max_size) |
| `session_store.lock_pool_max_size` | `int` | `32` | [`session_store` pool sizes](#session_storepool_min_size-pool_max_size-lock_pool_max_size) |

### Index — governance, transports and analysis

| Key | Type | Default | Documented in |
|---|---|---|---|
| `rules.user_rules_dirs` | `list[str]` | `[]` | [`rules.user_rules_dirs`](#rulesuser_rules_dirs) |
| `rules.packs` | `list[str]` | `[]` | [`rules.packs`](#rulespacks) |
| `rules.consistency_checks` | `bool` | `true` | [`rules.consistency_checks`](#rulesconsistency_checks) |
| `rkm.auto_promote.enabled` | `bool` | `false` | [`rkm.auto_promote.enabled`](#rkmauto_promoteenabled) |
| `rkm.sandbox.min_entries` | `int` | `100` | [`rkm.sandbox.min_entries`](#rkmsandboxmin_entries) |
| `ui.enabled` | `bool` | `false` | [`ui.enabled`](#uienabled) |
| `mcp.expose_declare_handoff` | `bool` | `false` | [`mcp.expose_declare_handoff`](#mcpexpose_declare_handoff) |
| `mcp.max_response_bytes` | `int \| None` | `262144` | [`mcp.max_response_bytes`](#mcpmax_response_bytes) |
| `analysis.mode` | `"pattern" \| "llm-first" \| "llm-only"` | `"pattern"` | [`analysis.mode`](#analysismode) |
| `analysis.timeout_s` | `float` | `2.0` | [`analysis.timeout_s`](#analysistimeout_s) |
| `analysis.keyword_map` | `dict[str, list[str]]` | `{}` | [`analysis.keyword_map`](#analysiskeyword_map) |
| `analysis.provider.type` | `"anthropic" \| "openai" \| "local"` | discriminator | [`analysis.provider.type`](#analysisprovidertype) |
| `analysis.provider.api_key_env` | `str` (`str \| None` for `local`) | required / `None` | [`analysis.provider.api_key_env`](#analysisproviderapi_key_env) |
| `analysis.provider.base_url` | `str` | required for `local` | [`analysis.provider.base_url`](#analysisproviderbase_url) |
| `analysis.provider.model` | `str` | `"claude-sonnet-4-5"` / `"gpt-4o-mini"` / required | [`analysis.provider.model`](#analysisprovidermodel) |
| `analysis.provider.timeout_s` | `float` | `2.0` | [`analysis.provider.timeout_s`](#analysisprovidertimeout_s) |
| `adapters[].module_path` | `str` | required | [`adapters[]`](#adaptersmodule_path-class-source_type) |
| `adapters[].class` | `str` | required | [`adapters[]`](#adaptersmodule_path-class-source_type) |
| `adapters[].source_type` | `str` | required | [`adapters[]`](#adaptersmodule_path-class-source_type) |
| `state_dir` | `str \| None` | `None` | [`state_dir`](#state_dir) |

## Read this first: Nautilus does not terminate TLS

`nautilus serve` builds its uvicorn server with host, port and log level only —
there is no `--tls-cert`, no `--ssl-keyfile`, no `api.tls` config key. Run it as
shipped and **every `X-API-Key` header crosses the network in cleartext**. The
Kubernetes manifests under `deploy/` are plaintext HTTP too: `service.yaml`
exposes `port: 8000` named `http`, and nothing in `deploy/` mentions TLS.

There is no config key for this, so it cannot be an entry below. The two
supported answers are in [Transport](#transport-tls-nautilus-does-not-do-it).

## What Nautilus is trusted with

The broker is the only process that holds source credentials. An agent sends an
intent and gets rows; it never sees a DSN
(see [The Trust Boundary](../concepts/trust-boundary.md)). Three things follow,
and they set the priority order of everything below:

1. **An API key is a data-exfiltration credential.** It is not a rate-limit
   token. Whoever holds one queries every source the agent it maps to may reach.
2. **The signing keys are the audit trail.** `attestation.private_key_path` signs
   decisions; the `session_tokens` key ring signs session provenance. Either one
   leaking makes the receipts forgeable.
3. **The audit log is evidence.** `audit.path` accumulates every intent, every
   decision and every denial, in plaintext JSONL, on a volume you choose.

## Generate the credentials first

Three secrets exist. Create all three before writing any config; every entry
below refers back to these.

```bash
# 1. One 256-bit API key per calling agent. One key per caller is what makes
#    revocation possible without an outage for everyone else.
export NAUTILUS_KEY_REPORTING="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export NAUTILUS_KEY_ONCALL="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

# 2. The attestation signing key — Ed25519 PEM, PKCS#8, unencrypted (the loader
#    calls AttestationService.from_private_key_bytes on the raw file bytes).
sudo install -d -m 0700 -o nautilus -g nautilus /etc/nautilus/keys
sudo -u nautilus openssl genpkey -algorithm ed25519 \
  -out /etc/nautilus/keys/attestation.pem
sudo chmod 0400 /etc/nautilus/keys/attestation.pem
# Publish the public half to whoever verifies your receipts.
sudo -u nautilus openssl pkey -in /etc/nautilus/keys/attestation.pem -pubout \
  -out /etc/nautilus/keys/attestation.pub.pem

# 3. The session-token key ring. Nautilus writes it itself, at 0600, on first
#    boot; you create the directory it may write into.
sudo install -d -m 0700 -o nautilus -g nautilus /var/lib/nautilus/keyring
```

Do not paste any of these into `nautilus.yaml`. Reference them with `${VAR}`,
which the loader interpolates from the process environment
(`nautilus.config.loader.EnvInterpolator`) — see
[`${VAR}` interpolation](#var-any-name-config-value-interpolation).

## `api` — who reaches the broker

### `api.host`

`str` · default `"127.0.0.1"` · read in `nautilus/cli/serve.py`, overridable by `nautilus serve --bind`

**Defends** against exposing the broker before it is configured. The loopback
default means a freshly-installed broker is reachable only from its own host, so
the window between `nautilus init` and your first `api.keys` entry is not a
window in which anyone else can reach the port.

**Costs** you container and Kubernetes deployments: a Pod that binds `127.0.0.1`
answers its own `nautilus health` probe and nothing else, and the Service in
front of it has no endpoint. Containers must set `0.0.0.0` and then rely on the
network policy and the reverse proxy to do the scoping the loopback bind was
doing.

**Fails with** nothing — a wrong value here is silent by design. A broker bound
to `127.0.0.1` inside a Pod fails as a `readinessProbe` timeout and
`connection refused` from the Service, not as a Nautilus message. Confirm the
bind rather than assuming it:

```console
$ ss -lntp | grep 8000
LISTEN 0  2048  127.0.0.1:8000  0.0.0.0:*  users:(("nautilus",pid=4211,fd=9))
```

**Example**

```yaml
api:
  host: 0.0.0.0   # container: bind wide, scope with NetworkPolicy + proxy
  port: 8000
```

`nautilus serve --bind 0.0.0.0:8000` overrides both `api.host` and `api.port`
without editing the file; when neither the flag nor the keys are set the default
bind is `127.0.0.1:8000`.

### `api.port`

`int` · default `8000` · read in `nautilus/cli/serve.py`, overridable by `nautilus serve --bind`

**Defends** nothing on its own — a port number is not a control. It is listed
here because it is the port every other control on this page applies to: the
REST API, `/metrics`, the admin console and (with `--transport both --mcp-mode
http`) MCP all share it. There is no second port to put the private surface on.
Separating them is a reverse-proxy job, not a config key; see
[Keep the private surface off the public listener](#keep-the-private-surface-off-the-public-listener).

**Costs** nothing.

**Fails with** a uvicorn startup error, not a Nautilus one, when the port is
taken:

```console
$ nautilus serve --config /etc/nautilus/nautilus.yaml
ERROR:    [Errno 98] error while attempting to bind on address ('127.0.0.1', 8000): address already in use
```

**Example**

```yaml
api:
  port: 8000
```

### `api.keys`

`list[str | ApiKeyEntry]` · default `[]` · read in `nautilus/transport/auth.py:verify_api_key`

**Defends** the entire data surface. The list is the allow-list; a request whose
`X-API-Key` matches no entry is refused. Comparison is
`secrets.compare_digest` per entry, so it does not leak the secret through
response timing.

**Costs** you an outage if you rotate wrong: an empty list fails *closed*, not
open. Every data and governance route answers 401, and only `/healthz`,
`/readyz` and `/metrics` stay reachable.

**Fails with**, when the list is empty, this WARN at startup and a 401 on every
subsequent call:

```
api.keys is empty, so every data and governance route will answer 401 Not
authenticated. Only /healthz, /readyz and /metrics are reachable. Add a key
under 'api: keys:' — 'nautilus init' writes one for you.
```

```console
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8000/v1/request \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers"}'
401
```

with body `{"detail":"Not authenticated"}` when the header is absent, and
`{"detail":"Invalid API key"}` when it is present and wrong.

**Example**

```yaml
api:
  keys:
    - key: "${NAUTILUS_KEY_REPORTING}"
      agent_id: reporting
      capabilities: [query]
```

### `api.keys[].key`

`str` · required · the secret compared against `X-API-Key`

**Defends** by being the secret itself. Generate it with
`python -c 'import secrets; print(secrets.token_urlsafe(32))'` (256 bits) and
never write the literal into YAML — use `${VAR}` so the value lives in the
process environment and not in the file your config-management system copies.

**Costs** you one environment variable per caller, and a restart to add or
remove one: the list is read once during lifespan startup into
`app.state.api_keys`.

**Fails with**, if you write the structured form and omit `key`:

```
Config validation failed:
  api.keys.0.str: Input should be a valid string [type=string_type]
  api.keys.0.function-after[_known_capabilities(), ApiKeyEntry].key: Field required [type=missing]
```

The two lines are the two arms of the `str | ApiKeyEntry` union — the second is
the one that names your mistake. Note that the loader strips rejected *values*
from validation errors (`nautilus/config/loader.py:_redacted_errors`), so a
malformed key never puts the secret itself into the startup log.

**Example**

```yaml
api:
  keys:
    - key: "${NAUTILUS_KEY_REPORTING}"   # never a literal
      agent_id: reporting
      capabilities: [query]
```

### `api.keys[].agent_id`

`str | None` · default `None` · read in `nautilus/transport/auth.py:caller_identity`

**Defends** against a caller asking as someone else. Without it the request body
names its own `agent_id`, and the registry hands that name its clearance — so
any key holder can ask as the most-cleared agent in the file. With it, the
credential *proves* which agent is calling and a body that disagrees is refused
before the broker runs.

**Costs** you one key per agent. A single shared key cannot be bound, because it
would bind every caller to one identity.

**Fails with**, when the body disagrees with the binding:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"incident-response","intent":"list customers","context":{}}'
{"detail":"This credential is bound to agent_id='reporting', so it cannot ask as 'incident-response'"}
```

HTTP 403. The same check guards `POST /v1/sessions`, where the message is
`This credential is bound to agent_id='reporting', so it cannot mint a session
token for 'incident-response'`.

**Example**

```yaml
agents:
  reporting:
    id: reporting
    clearance: cui
api:
  keys:
    - key: "${NAUTILUS_KEY_REPORTING}"
      agent_id: reporting
```

### `api.keys[].capabilities`

`list[str]` · default `["query"]` · valid values `query`, `audit_read`, `govern`, `keys` (`nautilus/config/models.py:CAPABILITIES`)

**Defends** against a query credential being a governance credential. The four
values map to four route groups:

| Capability | Grants |
|---|---|
| `query` | `POST /v1/request`, `POST /v1/query`, `POST /v1/sessions`, `GET /v1/sources`, `GET /v1/adapters`, `GET /v1/adapters/{name}/schema`, `GET /v1/rules`, and the console's `/admin/playground` and `/admin/sources` |
| `audit_read` | `GET /v1/audit`, `GET /v1/audit/{request_id}`, and the console's `/admin/decisions`, `/admin/decisions/{request_id}`, `/admin/audit`, `/admin/attestation`, `POST /admin/attestation/verify` |
| `govern` | `POST /v1/rkm/queue`, `GET /v1/rkm/queue`, `GET /v1/rkm/queue/{id}`, `POST /v1/rkm/queue/{id}/approve`, `POST /v1/rkm/queue/{id}/reject`, `GET /v1/rules/{name}/lineage`, `POST /v1/rules/{name}/retract`, `POST /v1/rules/{name}/rollback` |
| `keys` | `POST /v1/keys/rotate`, `POST /v1/keys/{kid}/revoke` |

**Costs** you the convenience of one key that does everything, and a 403 the
first time a caller needs a route you did not grant. The default is `["query"]`
for the structured form — but note the asymmetry in
[`api.keys`, bare string form](#the-bare-string-key-form): a bare string holds
*all four*.

**Fails with**, when a route needs a capability the credential lacks:

```console
$ curl -s http://127.0.0.1:8000/v1/audit -H "X-API-Key: $NAUTILUS_KEY_REPORTING"
{"detail":"This credential does not hold the 'audit_read' capability (it holds ['query'])"}
$ curl -s -X POST http://127.0.0.1:8000/v1/keys/rotate \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'X-Nautilus-Reviewer: alice' \
    -H 'Content-Type: application/json' -d '{"reviewer":"alice"}'
{"detail":"This credential does not hold the 'keys' capability (it holds ['query'])"}
```

Both are HTTP 403. An unauthenticated request still gets 401 first: the
capability dependency is listed *after* the auth guard on every route.

An unknown capability is a startup failure:

```
Config validation failed:
  api.keys.0.str: Input should be a valid string [type=string_type]
  api.keys.0.function-after[_known_capabilities(), ApiKeyEntry]: Value error, api.keys entry declares unknown capabilities ['read']. Known capabilities: ['query', 'audit_read', 'govern', 'keys'] [type=value_error]
```

**Example**

```yaml
api:
  keys:
    - key: "${NAUTILUS_KEY_REPORTING}"
      agent_id: reporting
      capabilities: [query]
    - key: "${NAUTILUS_KEY_ONCALL}"
      agent_id: incident-response
      capabilities: [query, audit_read]
```

#### The bare-string key form

`api.keys: ["s3cret"]` still loads, and it is what `nautilus init` writes. It
means: bound to no agent, holding **every** capability — it can rotate the
signing key and retract a rule merely by existing. It is not deprecated and it
is not silent:

```
api.keys[0] is a bare string: bound to no agent_id, so it can ask as any agent
and call every governance route. Use the {key, agent_id, capabilities} form to
scope it.
```

Search your startup logs for `is a bare string` before you call a deployment
hardened. With more than one, the message names all of them:
`api.keys[0, 2] are a bare string: ...`.

### `api.auth.mode`

`Literal["api_key", "proxy_trust"]` · default `"api_key"` · read in `nautilus/transport/auth.py`

**Defends** by choosing who does authentication. `api_key`: Nautilus does it,
against `api.keys`. `proxy_trust`: your ingress already did it (mTLS, SPIFFE,
OIDC) and forwards the result in `X-Forwarded-User`; Nautilus resolves that to
an agent through `agents.<id>.subject`.

**Costs** — under `proxy_trust`, the header *is* the credential. Anything that
can reach the port and set that header is that user, so the mode is only safe
with `api.auth.trusted_proxies` set *and* a network path that makes the proxy
the only reachable peer. Under `proxy_trust` the `api.keys` list stops gating
REST; the admin console login form still verifies against it.

**Fails with**, when the peer is outside the trusted set:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request -H 'X-Forwarded-User: alice' \
    -H 'Content-Type: application/json' -d '{"agent_id":"reporting","intent":"x","context":{}}'
{"detail":"Forwarded identity rejected: peer is not a trusted proxy"}
```

and, when the peer is trusted but the proxy did not set the header:
`{"detail":"Missing X-Forwarded-User"}`. Both are HTTP 401.

**Example**

```yaml
api:
  auth:
    mode: proxy_trust
    trusted_proxies: ["10.42.0.0/16"]
agents:
  reporting:
    id: reporting
    clearance: cui
    subject: "spiffe://cluster.local/ns/agents/sa/reporting"
```

### `api.auth.trusted_proxies`

`list[str]` · default `[]` · CIDR blocks or bare addresses · validated by `ipaddress.ip_network(entry, strict=False)`

**Defends** the `proxy_trust` mode from being an open door. Only a socket peer
inside one of these blocks may assert `X-Forwarded-User`.

**Costs** you a config change whenever the ingress moves. Set it to the Pod CIDR
of your ingress controller, not to `0.0.0.0/0` — which validates, and which
turns the header into a self-service identity for anyone who can reach the port.

**Fails with**, when `proxy_trust` is selected and the list is empty, a refusal
to start:

```console
$ nautilus serve --config /etc/nautilus/nautilus.yaml
ERROR: invalid config: Config validation failed:
  api.auth: Value error, api.auth.mode 'proxy_trust' requires api.auth.trusted_proxies. Without it, X-Forwarded-User is settable by anyone who can reach the port, so every caller can assert every identity. [type=value_error]
$ echo $?
2
```

and, for a malformed entry:

```
Config validation failed:
  api.auth: Value error, api.auth.trusted_proxies entry '10.0.0.0/33' is not an address or CIDR block: '10.0.0.0/33' does not appear to be an IPv4 or IPv6 network [type=value_error]
```

**Example**

```yaml
api:
  auth:
    mode: proxy_trust
    trusted_proxies:
      - "10.42.0.0/16"    # ingress-nginx Pod CIDR
      - "127.0.0.1/32"    # sidecar on the same Pod
```

### `api.max_request_bytes`

`int | None` · default `1048576` (1 MiB) · enforced by the `_BodySizeLimit` ASGI middleware

**Defends** memory: the body is rejected on the declared `Content-Length`, and
again mid-stream if a chunked body runs past the limit, so an oversized intent
never reaches the JSON parser.

**Costs** you large bodies. `null` removes the bound entirely; if your callers
legitimately post big `context` payloads, raise the number rather than removing
it.

**Fails with** HTTP 413 and a body that names the key and both numbers:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d "{\"agent_id\":\"reporting\",\"intent\":\"$(python -c 'print("x"*2000000)')\",\"context\":{}}"
{"detail": "Request body is 2000045 bytes; this broker accepts at most 1048576 (api.max_request_bytes)."}
```

**Example**

```yaml
api:
  max_request_bytes: 262144   # 256 KiB — intents are short
```

### `api.max_concurrent_requests`

`int | None` · default `64` · enforced by the `_ConcurrencyLimit` ASGI middleware

**Defends** latency under load. Past the limit the broker refuses rather than
queueing, because queueing turns a saturated broker into one that looks healthy
and slow — which is exactly what makes load balancers retry into the same queue.

**Costs** you refusals under burst. `/healthz`, `/readyz` and `/metrics` are
deliberately exempt (`_UNGATED_PATHS`), so saturation does not take the Pod out
of rotation and turn load into a restart loop.

**Fails with** HTTP 503, a `Retry-After: 1` header, and:

```json
{"detail": "Broker busy: 64 requests are already in flight (api.max_concurrent_requests). Retry."}
```

Deliberately 503 and not 429: the caller did nothing wrong and the same request
will work.

**Example**

```yaml
api:
  max_concurrent_requests: 64
```

## `agents` — who the credential may speak for

### `agents.<id>.id`

`str` · required · the map key and this field must both be present

**Defends** nothing by itself; it is the join key that `api.keys[].agent_id`,
`X-Forwarded-User` → `subject`, and every rule's `agent_id` slot all resolve
against. An agent absent from the registry has no clearance and no compartments.

**Costs** nothing.

**Fails with**, when a request names an id the registry does not hold:

```
Unknown agent id='reporting'
```

raised as `nautilus.config.agent_registry.UnknownAgentError` and surfaced in the
response's error records.

**Example**

```yaml
agents:
  reporting:
    id: reporting
    clearance: cui
```

### `agents.<id>.clearance`

`str` · required · must be a level of the loaded `classification` hierarchy

**Defends** the read side of the policy: a source's `classification` is compared
against this. An agent cleared `cui` is denied a `secret` source by the shipped
`deny-insufficient-clearance` rule.

**Costs** you a startup failure if you invent a label. That is the point — a
typo that silently created a new, unranked clearance would be a control that
looks configured and does nothing.

**Fails with** a refusal to start that names every bad label at once:

```console
$ nautilus serve --config /etc/nautilus/nautilus.yaml
ERROR: invalid config: classification labels are not levels of the 'classification' hierarchy (unclassified, cui, confidential, secret, top-secret): sources['customers'].classification='internal'; agents['reporting'].clearance='internal'
$ echo $?
2
```

The five levels shown are the shipped hierarchy; a rule pack that installs its
own hierarchy changes the list in the message.

**Example**

```yaml
agents:
  reporting:
    id: reporting
    clearance: cui
  incident-response:
    id: incident-response
    clearance: secret
```

### `agents.<id>.compartments`

`list[str]` · default `[]`

**Defends** need-to-know on top of clearance: an agent with `secret` clearance
but no `phi` compartment is still denied a `phi`-compartmented source. Empty
means "no compartments held", not "all compartments".

**Costs** you an explicit grant per compartment, and denials that look like
clearance failures until you read the denial record's `reason`.

**Fails with** a denial rather than a startup error — the broker answers 200 and
the source appears in `denial_records`:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list patients","context":{}}' \
  | python -m json.tool
{
    "sources_denied": ["patients"],
    "denial_records": [{"source_id": "patients", "reason": "compartment 'phi' not held by agent 'reporting'", "...": "..."}]
}
```

The exact `reason` text comes from the rule that fired, so it changes with your
rule pack — `sources_denied` and the presence of a `denial_records` entry do not.

**Example**

```yaml
agents:
  incident-response:
    id: incident-response
    clearance: secret
    compartments: [phi, pci]
```

### `agents.<id>.subject`

`str | None` · default `None` · read in `nautilus/transport/auth.py:caller_identity`

**Defends** the `proxy_trust` mode's binding. It is the value your ingress puts
in `X-Forwarded-User`, and it is the only thing that turns a forwarded identity
into a *bound* agent. A subject with no match stays unbound, which means the
caller names its own `agent_id` again — the exact hole `agent_id` binding
closes under `api_key`.

**Costs** you keeping SPIFFE IDs / OIDC subjects in `nautilus.yaml` and updating
them when your identity provider reissues.

**Fails with** no error at all — this is the quietest failure on the page. An
unmapped subject authenticates (the peer was trusted) and runs unbound. Detect
it by asserting that a request forwarded as an unregistered subject cannot ask
as a privileged agent:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H 'X-Forwarded-User: spiffe://cluster.local/ns/agents/sa/unregistered' \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"incident-response","intent":"list customers","context":{}}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["request_id"])'
```

If that returns a `request_id` instead of a 403, the subject is unmapped. Under
`proxy_trust`, audit every `agents.*.subject` against your IdP's issued
identities as part of the same review that rotates keys.

**Example**

```yaml
agents:
  reporting:
    id: reporting
    clearance: cui
    subject: "spiffe://cluster.local/ns/agents/sa/reporting"
```

### `agents.<id>.default_purpose`

`str | None` · default `None`

**Defends** against a caller omitting `purpose` and getting an unbounded one.
`purpose` is a live authorization input — the shipped `deny-purpose-mismatch`
rule and the HIPAA pack both read it — and it is typed by the caller. Setting a
default means the field is always populated with something you chose.

**Costs** you a policy decision: a default that is too broad is worse than none,
because it silently satisfies purpose rules for every request that forgot to say
why.

**Fails with** nothing when unset; the purpose is simply empty and any rule that
requires a specific purpose denies. Pair it with `allowed_purposes`, which is
the key that actually refuses.

**Example**

```yaml
agents:
  reporting:
    id: reporting
    clearance: cui
    default_purpose: quarterly-reporting
```

### `agents.<id>.allowed_purposes`

`list[str]` · default `[]` (empty means unrestricted) · enforced by `AgentRecord.may_claim`

**Defends** against purpose laundering: an agent claiming `emergency-care` to
clear a HIPAA rule it should not clear. The same method is read by the router,
which denies the request, and by the broker, which refuses to mint a session
token asserting the claim — so the two cannot disagree.

**Costs** you an enumeration per agent, and a denial the first time a caller
uses a purpose you forgot. Empty is unrestricted, which is the shape every
pre-existing config has, so adding this key is always a tightening.

**Fails with**, when the agent claims a purpose outside the list:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/sessions \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"session_id":"s-1","agent_id":"reporting","purpose":"emergency-care"}'
{"detail":"purpose 'emergency-care' is not one of the purposes agent 'reporting' may claim (['audit-response', 'quarterly-reporting'])"}
```

HTTP 403, raised as `PurposeNotPermittedError`. On `POST /v1/request` the same
condition denies the sources rather than failing the call.

**Example**

```yaml
agents:
  reporting:
    id: reporting
    clearance: cui
    default_purpose: quarterly-reporting
    allowed_purposes: [quarterly-reporting, audit-response]
```

## `sources` — what the broker holds credentials for

### `sources[].id`

`str` · required · unique across the file

**Defends** the integrity of every rule and every audit record: rules select by
`source_id`, denial records name it, and the exposure ledger accumulates by it.
Two sources with one id would silently merge policy.

**Costs** nothing.

**Fails with** a refusal to start:

```
ERROR: invalid config: Duplicate source id='customers'
```

and, when the key is absent, `Each source entry must have a string 'id'`.

**Example**

```yaml
sources:
  - id: customers
    type: postgres
    connection: "${CUSTOMERS_DSN}"
    table: customers
    classification: cui
    data_types: [pii]
```

### `sources[].type`

`str` · required · built-ins: `postgres`, `pgvector`, `elasticsearch`, `rest`, `neo4j`, `servicenow`, `influxdb`, `s3`, `llm`, `static`

**Defends** against a config that names an adapter which does not exist, and
against a source that would fail at query time rather than at boot. The check
runs before Pydantic validation, in `nautilus/config/loader.py`.

**Costs** you nothing — the set is extended automatically by installed
`nautilus.adapters` entry points and by any `adapters[].source_type` you declare.

**Fails with** a refusal to start that lists what is actually available:

```
ERROR: invalid config: Unsupported source type='postgress' for id='customers' (supported: ['elasticsearch', 'influxdb', 'llm', 'neo4j', 'pgvector', 'postgres', 'rest', 's3', 'servicenow', 'static'])
```

and, when the key is missing entirely:

```
ERROR: invalid config: Source id='customers' is missing the required key 'type' (one of: ['elasticsearch', 'influxdb', 'llm', 'neo4j', 'pgvector', 'postgres', 'rest', 's3', 'servicenow', 'static'])
```

**Example**

```yaml
sources:
  - id: customers
    type: postgres
```

### `sources[].classification`

`str` · required · must be a level of the loaded `classification` hierarchy

**Defends** the read side of every clearance rule. This is the label an agent's
`clearance` is compared against; get it wrong downward and a `secret` table is
readable by a `cui` agent, with a receipt that says the decision was correct.

**Costs** you the discipline of classifying every source, including the boring
ones. There is no default; omitting it is a startup failure.

**Fails with**, for an unranked label, the same message as
[`agents.<id>.clearance`](#agentsidclearance):

```
ERROR: invalid config: classification labels are not levels of the 'classification' hierarchy (unclassified, cui, confidential, secret, top-secret): sources['customers'].classification='internal'
```

and, when omitted:

```
Config validation failed:
  sources.0.classification: Field required [type=missing]
```

**Example**

```yaml
sources:
  - id: customers
    type: postgres
    connection: "${CUSTOMERS_DSN}"
    table: customers
    classification: cui
    data_types: [pii]
```

### `sources[].compartments`

`str` · default `""` · space-separated, not a list

**Defends** need-to-know on the source side. Note the type: this is a
space-separated **string** (`"phi pci"`), while `agents.<id>.compartments` is a
**list**. Writing a YAML list here is a startup failure, which is the only
reason the asymmetry is survivable.

**Costs** you nothing beyond remembering the shape. Empty means uncompartmented.

**Fails with**, if you write it as a list:

```
Config validation failed:
  sources.0.compartments: Input should be a valid string [type=string_type]
```

**Example**

```yaml
sources:
  - id: patients
    type: postgres
    connection: "${PATIENTS_DSN}"
    table: patients
    classification: secret
    compartments: "phi"
    data_types: [phi, pii]
```

### `sources[].data_types`

`list[str]` · required

**Defends** the escalation machinery. Cumulative exposure is accumulated by data
type, so `escalation` rules that fire on a *combination* (`pii` plus `phi` in one
session) only work if every source declares what it yields. An under-declared
source is invisible to those rules.

**Costs** you an inventory pass over your sources, and — once the types are
honest — denials that did not happen before, because combinations now trigger.

**Fails with**, when omitted:

```
Config validation failed:
  sources.0.data_types: Field required [type=missing]
```

**Example**

```yaml
sources:
  - id: customers
    type: postgres
    connection: "${CUSTOMERS_DSN}"
    table: customers
    classification: cui
    data_types: [pii, contact]
```

### `sources[].allowed_purposes`

`list[str] | None` · default `None` (unrestricted)

**Defends** the source side of purpose binding: this source may only be read
under these purposes, whatever the agent is allowed to claim. `None` and `[]`
both mean unrestricted, so this key only ever tightens.

**Costs** you a denial whenever a legitimate new use case appears, until you add
its purpose here as well as to the agent.

**Fails with** a denial in the response, not a startup error:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list patients","context":{"purpose":"marketing"}}' \
  | python -c 'import json,sys; d=json.load(sys.stdin); print(d["sources_denied"], d["denial_records"])'
['patients'] [{'source_id': 'patients', 'reason': "...purpose 'marketing'...", ...}]
```

**Example**

```yaml
sources:
  - id: patients
    type: postgres
    connection: "${PATIENTS_DSN}"
    table: patients
    classification: secret
    data_types: [phi]
    allowed_purposes: [treatment, emergency-care]
```

### `sources[].purpose_field`

`str` · default `""`

**Defends** row-level purpose filtering: names the column carrying each row's
own permitted purpose, so the adapter filters rows rather than the policy
denying the whole source. Empty disables it.

**Costs** you a column on the table and a query predicate on every read.

**Fails with** an adapter-level error naming the column when it does not exist —
for postgres, surfaced in `sources_errored` with the driver's own text, e.g.
`column "purpose" does not exist`.

**Example**

```yaml
sources:
  - id: patients
    type: postgres
    connection: "${PATIENTS_DSN}"
    table: patients
    classification: secret
    data_types: [phi]
    purpose_field: allowed_purpose
```

### `sources[].connection`

`str` · default `""` · required for every adapter that dials out

**Defends** the trust boundary itself. This is where the DSN lives — the string
the agent must never see. Always write it as `${VAR}`; a literal here puts
production credentials in the file your config management copies, diffs and
backs up.

**Costs** you an environment variable per source and a restart to change one.

**Fails with**, when the adapter needs it and it is empty:

```
Config validation failed:
  sources.0: Value error, source 'customers' has type 'postgres' but no 'connection'. The postgres adapter has nothing to dial, so every request to this source would fail at runtime. [type=value_error]
```

and, when the referenced variable is not in the environment:

```
ERROR: invalid config: Missing env var 'CUSTOMERS_DSN' referenced by source id='customers'
```

**Example**

```yaml
sources:
  - id: customers
    type: postgres
    connection: "${CUSTOMERS_DSN}"   # postgresql://nautilus@db.internal:5432/customers
    table: customers
    classification: cui
    data_types: [pii]
```

### `sources[].auth`

Discriminated on `sources[].auth.type` ∈ `bearer` | `basic` | `mtls` | `none` · default absent

**Defends** the outbound leg. Every field is interpolated, so every secret can
come from the environment.

| `type` | Required fields | Optional |
|---|---|---|
| `bearer` | `token` | — |
| `basic` | `username`, `password` | — |
| `mtls` | `cert_path`, `key_path` | `ca_path` |
| `none` | — | — |

**Costs**, for `mtls`, that `cert_path`/`key_path` are filesystem paths the
broker process must be able to read — so the key file's mode and owner become
part of your hardening, not just the config. `ca_path` unset means the system
trust store verifies the peer; set it to pin a private CA.

**Fails with**, for a missing required field:

```
Config validation failed:
  sources.0.auth.bearer.token: Field required [type=missing]
```

and, for a `type` outside the union:

```
Config validation failed:
  sources.0.auth: Input tag 'oauth' found using 'type' does not match any of the expected tags: 'bearer', 'basic', 'mtls', 'none' [type=union_tag_invalid]
```

The tag is deliberately *not* redacted from validation errors — it is the whole
diagnosis and it is never a secret.

**Example**

```yaml
sources:
  - id: incidents
    type: servicenow
    connection: "https://example.service-now.com"
    classification: cui
    data_types: [incident]
    auth:
      type: basic
      username: "${SNOW_USER}"
      password: "${SNOW_PASSWORD}"
  - id: partner-api
    type: rest
    connection: "https://partner.example.com"
    classification: cui
    data_types: [contact]
    auth:
      type: mtls
      cert_path: /etc/nautilus/keys/partner-client.pem
      key_path: /etc/nautilus/keys/partner-client.key
      ca_path: /etc/nautilus/keys/partner-ca.pem
```

#### `sources[].auth.type`

`Literal["bearer", "basic", "mtls", "none"]` · discriminator, no default · omitting the whole `auth` block means no outbound credential

**Defends** by making the outbound credential scheme explicit per source rather
than a property of whatever the adapter felt like doing. `none` is a *declared*
choice — it validates, and it says in the file that this source is
unauthenticated, which is different from forgetting.

**Costs** you nothing. Note the asymmetry with InfluxDB: omitting `auth`
entirely lets that adapter fall back to `INFLUXDB_V2_TOKEN` from the
environment, so "no auth block" is not always "no credential" — see
[`INFLUXDB_V2_TOKEN`](#influxdb_v2_token).

**Fails with**, for a tag outside the union:

```
Config validation failed:
  sources.0.auth: Input tag 'oauth' found using 'type' does not match any of the expected tags: 'bearer', 'basic', 'mtls', 'none' [type=union_tag_invalid]
```

The tag is deliberately *not* redacted from validation errors — it is the whole
diagnosis and it is never a secret.

**Example**

```yaml
sources:
  - id: public-catalog
    type: rest
    connection: "https://catalog.example.com"
    classification: unclassified
    data_types: [catalog]
    auth:
      type: none      # declared, not forgotten
```

#### `sources[].auth.token`

`str` · required when `type: bearer` · interpolated

**Defends** the outbound leg with a bearer token the agent never sees. Write it
as `${VAR}`; a literal here puts a live API token in the file your config
management copies and diffs.

**Costs** you one environment variable per source and a restart to rotate one.
Bearer tokens are replayable by anyone who reads them, so the file mode
(`0640`, root-owned) and the `EnvironmentFile` mode (`0600`) are part of this
control.

**Fails with**, when omitted:

```
Config validation failed:
  sources.0.auth.bearer.token: Field required [type=missing]
```

and, when the variable is unset:

```
ERROR: invalid config: Missing env var 'PARTNER_TOKEN' referenced by source id='partner-api'
```

**Example**

```yaml
sources:
  - id: partner-api
    type: rest
    connection: "https://partner.example.com"
    classification: cui
    data_types: [contact]
    auth:
      type: bearer
      token: "${PARTNER_TOKEN}"
```

#### `sources[].auth.username` / `sources[].auth.password`

`str` · both required when `type: basic` · both interpolated

**Defends** the outbound leg for services that only speak HTTP Basic. Both
fields interpolate, so the password lives in the environment.

**Costs** you the weakest scheme in the union: Basic sends a reversible
credential on every request, so `https://` in `connection` is not optional here.
Prefer `bearer` or `mtls` where the service supports them.

**Fails with**, when either is omitted:

```
Config validation failed:
  sources.0.auth.basic.password: Field required [type=missing]
```

The rejected *value* is never printed — `nautilus/config/loader.py:_redacted_errors`
strips it — so a malformed block does not leak the password into your startup
log.

**Example**

```yaml
sources:
  - id: incidents
    type: servicenow
    connection: "https://example.service-now.com"
    classification: cui
    data_types: [incident]
    auth:
      type: basic
      username: "${SNOW_USER}"
      password: "${SNOW_PASSWORD}"
```

#### `sources[].auth.cert_path` / `sources[].auth.key_path` / `sources[].auth.ca_path`

`str` / `str` / `str | None` · `cert_path` and `key_path` required when `type: mtls`; `ca_path` defaults to `None`

**Defends** the outbound leg with a credential that cannot be replayed from a
log line: the broker proves possession of a private key instead of sending a
secret. `ca_path` pins the *peer* — set it and only a certificate chaining to
that CA is accepted, which is what stops a corporate TLS-inspection proxy or a
mis-issued public certificate from silently terminating the connection.

**Costs** you certificate lifecycle management, and — because these are
filesystem paths, not interpolated secrets — the key file's mode and owner
become part of your hardening. `ca_path` unset means the system trust store
verifies the peer, so any public CA is acceptable.

**Fails with**, when a required field is omitted:

```
Config validation failed:
  sources.0.auth.mtls.key_path: Field required [type=missing]
```

and, at connect time, an adapter error in `sources_errored` naming the file when
the broker user cannot read it:
`[Errno 13] Permission denied: '/etc/nautilus/keys/partner-client.key'`.

**Example**

```bash
sudo install -m 0400 -o nautilus -g nautilus \
  partner-client.key /etc/nautilus/keys/partner-client.key
sudo install -m 0444 -o nautilus -g nautilus \
  partner-client.pem /etc/nautilus/keys/partner-client.pem
sudo install -m 0444 -o nautilus -g nautilus \
  partner-ca.pem /etc/nautilus/keys/partner-ca.pem
```

```yaml
sources:
  - id: partner-api
    type: rest
    connection: "https://partner.example.com"
    classification: cui
    data_types: [contact]
    auth:
      type: mtls
      cert_path: /etc/nautilus/keys/partner-client.pem
      key_path: /etc/nautilus/keys/partner-client.key
      ca_path: /etc/nautilus/keys/partner-ca.pem   # pin the peer
```

### `sources[].timeout_s`

`float | None` · default `15.0` · wall-clock budget for one connect+execute

**Defends** against one unresponsive source holding a request, its session write
and its audit entry open forever — and holding every healthy co-queried source
with it. Availability is a security property when the broker is the only path to
your data.

**Costs** you truncated results from legitimately slow sources (a large LLM).
Raise it for those specifically; `null` waits indefinitely and is a choice you
should have to write down.

**Fails with** an entry in `sources_errored`, not a failed request:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["sources_errored"])'
[{'source_id': 'customers', 'error_type': 'TimeoutError', 'message': '...'}]
```

**Example**

```yaml
sources:
  - id: customers
    type: postgres
    connection: "${CUSTOMERS_DSN}"
    table: customers
    classification: cui
    data_types: [pii]
    timeout_s: 5.0
```

### `sources[].max_response_bytes`

`int | None` · default `8388608` (8 MiB)

**Defends** the broker's memory against a source that returns far more than the
intent asked for. Rows are dropped whole and the source is named in the
response's `truncated_sources`, so a truncated answer is never silently a
complete one.

**Costs** you rows. `null` removes the bound.

**Fails with** no error — a 200 whose `truncated_sources` names the source:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}' \
  | python -c 'import json,sys; print(json.load(sys.stdin).get("truncated_sources"))'
['customers']
```

**Example**

```yaml
sources:
  - id: customers
    type: postgres
    connection: "${CUSTOMERS_DSN}"
    table: customers
    classification: cui
    data_types: [pii]
    max_response_bytes: 1048576
```

## `attestation` — signing the receipts

### `attestation.enabled`

`bool` · default `true` · read in `nautilus/core/broker.py:_build_attestation`

**Defends** the non-repudiation property: with it on, every response carries a
signed attestation token and `audit.chained` has something to sign with. `false`
returns `None` from the builder, and the token is omitted from every response.

**Costs** you an Ed25519 signature per request. Leaving it on with no
`private_key_path` costs you nothing at boot and everything at verification
time — see the next entry.

**Fails with** no error when disabled; the absence is visible in the response.
Assert it positively rather than trusting the config:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}' \
  | python -c 'import json,sys; print("attestation" if json.load(sys.stdin).get("attestation_token") else "NO ATTESTATION")'
attestation
```

Turning it off while `audit.chained` is on is refused at startup —
see [`audit.chained`](#auditchained).

**Example**

```yaml
attestation:
  enabled: true
  private_key_path: /etc/nautilus/keys/attestation.pem
```

### `attestation.private_key_path`

`str | None` · default `None` · Ed25519 private key, PEM, relative paths resolve against the config file's directory

**Defends** the durability of your receipts. Unset, the broker generates an
**ephemeral** keypair at every boot: tokens verify while that process lives and
become unverifiable the moment it restarts, and `/v1/keys/jwks.json` serves a
`kid` nobody has seen before. Set, every replica and every restart signs with
the same key and yesterday's receipts still verify.

**Costs** you key management: the file must be readable by the broker user and
by nobody else, it must be mounted into every replica, and rotating it is a
deliberate operation (see [Rotate and revoke](#rotate-and-revoke)).

**Fails with**, when the path does not exist, a startup traceback ending in the
OS error — the path is read with `Path.read_bytes()`:

```console
$ nautilus serve --config /etc/nautilus/nautilus.yaml
FileNotFoundError: [Errno 2] No such file or directory: '/etc/nautilus/keys/attestation.pem'
```

and, when it is unreadable by the broker user,
`PermissionError: [Errno 13] Permission denied: '/etc/nautilus/keys/attestation.pem'`.
With `audit.chained` on and an existing log, leaving it unset is refused
outright — see [`audit.chained`](#auditchained).

**Example**

```bash
sudo -u nautilus openssl genpkey -algorithm ed25519 -out /etc/nautilus/keys/attestation.pem
sudo chmod 0400 /etc/nautilus/keys/attestation.pem
sudo chown nautilus:nautilus /etc/nautilus/keys/attestation.pem
```

```yaml
attestation:
  enabled: true
  private_key_path: /etc/nautilus/keys/attestation.pem
```

Confirm the running key is the one you generated — the `kid` must be stable
across a restart:

```console
$ curl -s http://127.0.0.1:8000/v1/keys/jwks.json | python -m json.tool
{
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "ee0eb00e-38ae-4060-90dc-a9aac8da460d",
            "x": "_Kyh2hBbmPr83FTYtvdbz-RyWK22Yjj_kSAfP_Pl6F4",
            "use": "sig"
        }
    ]
}
```

### `attestation.sink.type`

`Literal["null", "file", "http"]` · default `"null"`

**Defends** — `null` defends nothing; it is the default and it discards every
signed payload. `file` appends JSONL with a flush and `fsync` per emit. `http`
POSTs to a verifier with retry and optional dead-lettering. If your compliance
story is "we can prove what the broker decided", the default is not it.

**Costs** — `file`: an fsync per decision (the durability you are paying for).
`http`: a network round trip in the decision path, bounded by `retry_policy`.

**Fails with**, for a tag outside the union:

```
Config validation failed:
  attestation.sink: Input tag 'kafka' found using 'type' does not match any of the expected tags: 'null', 'file', 'http' [type=union_tag_invalid]
```

**Example**

```yaml
attestation:
  enabled: true
  private_key_path: /etc/nautilus/keys/attestation.pem
  sink:
    type: file
    path: /var/lib/nautilus/attestations.jsonl
    chained: true
    checkpoint_interval: 1000
```

### `attestation.sink.path`

`str` · required when `type: file`

**Defends** nothing by itself; it decides *where the evidence lands*, which
makes its volume and its permissions part of your security posture. Put it on a
volume the broker user can write and an attacker who compromises an agent
cannot — not the same directory the config lives in.

**Costs** you disk. Nothing rotates this file for you; size it and manage it
with logrotate or a sidecar.

**Fails with**, when omitted:

```
Config validation failed:
  attestation.sink.file.path: Field required [type=missing]
```

and, when the directory is not writable, an `OSError` at first emit naming the
path.

**Example**

```yaml
attestation:
  sink:
    type: file
    path: /var/lib/nautilus/attestations.jsonl
```

### `attestation.sink.chained`

`bool` · default `false` · `type: file` only

**Defends** the attestation stream against tampering: every line carries
`prev_sha256` linkage plus an EdDSA signature, so deleting, reordering or
editing a line is detectable offline with `nautilus attestation verify`. Without
it the file is append-only by convention and by nothing else.

**Costs** you a single writer — a chain with two appenders is a corrupt chain —
and a hash plus a signature per line.

**Fails with**, at verification rather than at write time:

```console
$ nautilus attestation verify /var/lib/nautilus/attestations.jsonl \
    --pubkey /etc/nautilus/keys/attestation.pub.pem
ERROR: attestation verify: chain broken at record 41: prev_sha256 mismatch
$ echo $?
2
```

**Example**

```yaml
attestation:
  enabled: true
  private_key_path: /etc/nautilus/keys/attestation.pem
  sink:
    type: file
    path: /var/lib/nautilus/attestations.jsonl
    chained: true
```

### `attestation.sink.checkpoint_interval`

`int` · default `0` (off) · `type: file` only, meaningful with `chained: true`

**Defends** against *tail truncation* — the one edit a hash chain cannot detect
on its own, because a chain that stops early is still internally valid. Every N
emissions the sink appends a signed checkpoint record; mirror the checkpoint
token somewhere else and a truncated log fails verification.

**Costs** you one extra signed line per N decisions, and an out-of-band place to
keep the anchor. Without that second location the checkpoint proves nothing —
it is in the file an attacker just truncated.

**Fails with**, when the anchored checkpoint is missing from the log:

```console
$ nautilus attestation verify /var/lib/nautilus/attestations.jsonl \
    --pubkey /etc/nautilus/keys/attestation.pub.pem \
    --anchor-token "<CHECKPOINT_JWS_YOU_MIRRORED>"
ERROR: attestation verify: anchor checkpoint not present in log
```

**Example**

```yaml
attestation:
  sink:
    type: file
    path: /var/lib/nautilus/attestations.jsonl
    chained: true
    checkpoint_interval: 1000
```

### `attestation.sink.url`

`str` · required when `type: http` · the verifier's ingest endpoint

**Defends** against an attacker who owns the broker host also owning its
evidence: shipping attestations off-box means the receipts survive the machine.

**Costs** you the verifier's availability inside the decision path, bounded by
`retry_policy`, plus the obvious: **use `https://`**. A plaintext `http://` here
streams every signed decision across your network in the clear. Nautilus does not
refuse it — a collector reachable only over a trusted link is a real deployment —
but it says so once, at construction:

```
WARNING attestation.sink.url is plaintext http:// to collector.internal --
signed attestations and the decision metadata around them cross the network
unencrypted. Use https:// unless the collector is reachable only over a trusted
link.
```

A loopback host (`localhost`, `127.0.0.1`, `::1`) is exempt: nothing leaves the
machine, so warning there would only teach you to ignore the warning.

**Fails with**, when omitted:

```
Config validation failed:
  attestation.sink.http.url: Field required [type=missing]
```

and, when the endpoint is unreachable and retries are exhausted, a WARN naming
the sink — with `dead_letter_path` unset, that WARN is the only trace and the
payload is gone.

**Example**

```yaml
attestation:
  enabled: true
  private_key_path: /etc/nautilus/keys/attestation.pem
  sink:
    type: http
    url: "https://verifier.internal.example.com/v1/attestations"
    dead_letter_path: /var/lib/nautilus/attestations.deadletter.jsonl
    retry_policy:
      max_retries: 5
      initial_backoff_s: 0.2
      max_backoff_s: 10.0
```

### `attestation.sink.dead_letter_path`

`str | None` · default `None` · `type: http` only

**Defends** against silent evidence loss. When the verifier is down and the
retries run out, an unset `dead_letter_path` means a WARN and nothing else —
the signed payload is discarded. Set, the sink spills to a durable
`FileAttestationSink` so the record can be replayed later.

**Costs** you disk on the broker host, and a spill file you must actually drain
— nothing replays it for you.

**Fails with** silence when unset; that is the failure. Alert on the spill file
existing at all:

```console
$ test -s /var/lib/nautilus/attestations.deadletter.jsonl \
    && echo "ALERT: attestations were dead-lettered" && wc -l < /var/lib/nautilus/attestations.deadletter.jsonl
ALERT: attestations were dead-lettered
17
```

**Example**

```yaml
attestation:
  sink:
    type: http
    url: "https://verifier.internal.example.com/v1/attestations"
    dead_letter_path: /var/lib/nautilus/attestations.deadletter.jsonl
```

### `attestation.sink.retry_policy`

`max_retries: int = 3` · `initial_backoff_s: float = 0.1` · `max_backoff_s: float = 5.0` · `type: http` only

**Defends** the broker's own availability from the verifier's outage: the retry
budget bounds how long a decision can be held waiting for the evidence sink.
Worst case with the defaults is roughly `0.1 + 0.2 + 0.4` seconds of backoff
plus three request timeouts.

**Costs** you latency on the decision path when the verifier is degraded, and
lost attestations once the budget is spent — which is why
`dead_letter_path` belongs with this key, not instead of it.

**Fails with** a `Value error` when a field is the wrong type, e.g.:

```
Config validation failed:
  attestation.sink.http.retry_policy.max_retries: Input should be a valid integer, unable to parse string as an integer [type=int_parsing]
```

**Example**

```yaml
attestation:
  sink:
    type: http
    url: "https://verifier.internal.example.com/v1/attestations"
    retry_policy:
      max_retries: 5
      initial_backoff_s: 0.2
      max_backoff_s: 10.0
```

## `audit` — the evidence path

### `audit.path`

`str` · default `"./audit.jsonl"` · relative paths resolve against the config file's directory

**Defends** your ability to answer "who saw what, when". Every intent, decision
and denial lands here as JSONL, in plaintext, including the intents themselves —
which frequently contain the sensitive terms the query was about. Treat the file
as classified at the level of your highest-classified source.

**Costs** you a disk-full outage if you ignore it: the default lands the log in
the config directory, which in a container is usually a read-only mount, and in
a systemd unit is usually not the volume you meant.

**Fails with** HTTP 503 on `/readyz` — the probe calls `audit_logger.probe()` and
reports the sink's own message:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/readyz
503
$ curl -s http://127.0.0.1:8000/readyz | python -m json.tool
{"status": "degraded", "audit": "[Errno 13] Permission denied: '/var/lib/nautilus/audit.jsonl'"}
```

A broker that cannot write its audit log is not ready. That is deliberate: an
unrecorded decision is worse than a refused one.

**Example**

```yaml
audit:
  path: /var/lib/nautilus/audit.jsonl
```

```bash
sudo install -d -m 0750 -o nautilus -g nautilus /var/lib/nautilus
```

### `audit.chained`

`bool` · default `false`

**Defends** the audit log against edits by whoever holds the disk. Each line
carries a JWS and commits to its predecessor, so a deleted or altered entry is
detectable offline instead of leaving no trace. This is what turns the log from
*records* into *evidence*.

**Costs** you a signature per entry, a single writer, and a hard dependency on
`attestation.enabled` plus a stable signing key.

**Fails with** a refusal to start when there is nothing to sign with:

```
audit.chained requires attestation.enabled with a signing key: each chained line carries a JWS, and there is nothing to sign with
```

and — the one most operators hit second — a refusal to append to an existing
chain with an ephemeral key:

```
audit.chained cannot append to the existing chain at /var/lib/nautilus/audit.jsonl with an auto-generated signing key: attestation.private_key_path is unset, so this process signs with a key the lines already on disk were not signed by, and every request would fail closed on a log that reads as corrupt. Set attestation.private_key_path to the key that wrote them, or start a new chain at a new audit.path.
```

With no existing log and no key path it starts, but warns:

```
audit.chained is on with an auto-generated attestation key: this chain is
signed by this process only and the next boot will refuse to append to it. Set
attestation.private_key_path to keep it.
```

**Example**

```yaml
attestation:
  enabled: true
  private_key_path: /etc/nautilus/keys/attestation.pem
audit:
  path: /var/lib/nautilus/audit.jsonl
  chained: true
  checkpoint_interval: 1000
```

Verify it offline, on a copy, from a host the broker cannot write to:

```console
$ nautilus attestation verify /var/lib/nautilus/audit.jsonl \
    --pubkey /etc/nautilus/keys/attestation.pub.pem
OK: chain valid — 12043 records, head 9f2c1d0b7a5e4c93
```

### `audit.checkpoint_interval`

`int` · default `0` (off) · meaningful with `chained: true`

**Defends** the audit chain against tail truncation, exactly as
[`attestation.sink.checkpoint_interval`](#attestationsinkcheckpoint_interval)
does for attestations: a signed checkpoint every N entries, mirrored somewhere
the broker cannot reach, plus `--expected-head` or `--anchor-token` at
verification time.

**Costs** one extra signed line per N entries, and an out-of-band store for the
anchor.

**Fails with**, when the mirrored head no longer matches the log:

```console
$ nautilus attestation verify /var/lib/nautilus/audit.jsonl \
    --pubkey /etc/nautilus/keys/attestation.pub.pem \
    --expected-head "<LAST_LINE_HASH_YOU_MIRRORED>"
ERROR: attestation verify: expected head not found in log
```

**Example**

```yaml
audit:
  path: /var/lib/nautilus/audit.jsonl
  chained: true
  checkpoint_interval: 1000
```

## `session_tokens` — provenance across a session

### `session_tokens.enabled`

`bool` · default `false`

**Defends** against a caller forging its own session history. With it on the
broker mints an EdDSA JWS on the first request of a session and verifies it on
every subsequent one; the token carries the session id, agent, purpose and
clearance, so cumulative-exposure state cannot be reset by inventing a new
session id.

**Costs** you a signature per session, a key ring to manage, and — if you run
more than one replica — the two keys below, without which replicas reject each
other's tokens.

**Fails with**, for a token that does not verify, HTTP 401 naming the reason
code:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    -H 'X-Nautilus-Session-Token: abc.def.ghi' \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}'
{"detail":"Invalid session token: bad_signature"}
```

The reason code is one of `missing`, `bad_signature`, `expired`, `unknown_kid`,
`wrong_broker` (`nautilus/attestation/session_token.py`). `unknown_kid` across a
fleet means your replicas do not share `key_ring_path`.

**Example**

```yaml
session_tokens:
  enabled: true
  ttl_seconds: 900
  key_ring_path: /var/lib/nautilus/keyring/session-keys.json
  broker_instance_id: nautilus-prod
```

### `session_tokens.ttl_seconds`

`int` · default `3600`

**Defends** by bounding replay: a stolen token is useful for this long and no
longer.

**Costs** you re-minting, and — for long-running agent sessions — a mid-session
`expired` where there used to be none. Match it to your longest legitimate
session, not to your patience.

**Fails with** HTTP 401 and:

```json
{"detail":"Invalid session token: expired"}
```

**Example**

```yaml
session_tokens:
  enabled: true
  ttl_seconds: 900
```

### `session_tokens.key_ring_path`

`str | None` · default `None` (in-process, ephemeral)

**Defends** multi-replica correctness. Unset, each replica generates its own
ring, and a token minted by replica A is rejected by replica B with
`unknown_kid` — an authorization outage that looks like an attack. Set to a
shared path (a mounted secret or a shared volume) it is one ring for the
deployment. Nautilus writes the file itself with `os.open(..., 0o600)`.

**Costs** you a shared writable path with correct ownership, and the
understanding that this file *is* the signing material: read access to it is
the ability to forge session provenance.

**Fails with** HTTP 401 on requests that cross replicas:

```json
{"detail":"Invalid session token: unknown_kid"}
```

Confirm the fleet shares one ring — every replica must return the same `kid`
set:

```console
$ for pod in $(kubectl get pods -l app=nautilus -o name); do
    kubectl exec "$pod" -- curl -s localhost:8000/v1/keys/jwks.json \
      | python -c 'import json,sys; print(sorted(k["kid"] for k in json.load(sys.stdin)["keys"]))'
  done
['ee0eb00e-38ae-4060-90dc-a9aac8da460d']
['ee0eb00e-38ae-4060-90dc-a9aac8da460d']
```

**Example**

```yaml
session_tokens:
  enabled: true
  key_ring_path: /var/lib/nautilus/keyring/session-keys.json
```

```bash
sudo install -d -m 0700 -o nautilus -g nautilus /var/lib/nautilus/keyring
```

### `session_tokens.broker_instance_id`

`str | None` · default `None`

**Defends** against cross-deployment replay: a token says which broker minted
it, and a broker refuses one minted elsewhere. This only works if the value is
**identical across the replicas of one deployment and different between
deployments** — staging and production must not share a string.

**Costs** you one more thing to keep in sync. Unset with a shared
`key_ring_path` resolves to a constant (one deployment); unset *without* one
falls back to a per-process id, which is correct for a single broker only.

**Fails with** HTTP 401 and:

```json
{"detail":"Invalid session token: wrong_broker"}
```

**Example**

```yaml
session_tokens:
  enabled: true
  key_ring_path: /var/lib/nautilus/keyring/session-keys.json
  broker_instance_id: nautilus-prod-eu-west-1
```

## `session_store` — where cumulative exposure lives

### `session_store.backend`

`Literal["memory", "postgres", "sqlite"]` · default `"memory"`

**Defends** the escalation rules themselves. Cumulative exposure is what
escalation reads; with `memory` and more than one replica, each replica sees a
fraction of a caller's history, so a combination that should escalate never
does. `postgres` is the shared store; `sqlite` is a durable single-node one.

**Costs** — `postgres`: a database in the request path and the pool settings
below. `sqlite`: durability without sharing, so still single-node.

**Fails with**, for `redis` (which used to load and silently serve from memory):

```
Config validation failed:
  session_store.backend: Value error, session_store.backend: redis has no implementation. It used to load and serve sessions from memory instead, which gives replicas a per-process view of cumulative exposure and no signal that this is happening. Use postgres for a store shared across replicas, or sqlite for a durable single-node one. [type=value_error]
```

and, for any other unknown value:

```
Config validation failed:
  session_store.backend: Input should be 'memory', 'postgres' or 'sqlite' [type=literal_error]
```

**Example**

```yaml
session_store:
  backend: postgres
  dsn: "${SESSION_STORE_DSN}"
  on_failure: fail_closed
```

### `session_store.dsn`

`str | None` · default `None` · post-interpolation; falls back to the `TEST_PG_DSN` env var

**Defends** nothing on its own; it is a credential, so treat it as one and write
it as `${VAR}`. Errors from the store strip credentials before they are printed
(`PostgresSessionStore._sanitized_dsn`), so a connection failure does not leak
the password into your logs.

**Costs** you an environment variable and a restart to change it.

**Fails with**, when the store is unreachable and `on_failure: fail_closed`,
a startup failure and a non-zero exit — the DSN in the message is sanitised:

```
PostgresSessionStore unavailable (dsn=postgresql://db.internal:5432/nautilus): [Errno 111] Connection refused
```

**Example**

```yaml
session_store:
  backend: postgres
  dsn: "${SESSION_STORE_DSN}"
```

### `session_store.on_failure`

`Literal["fail_closed", "fallback_memory", "fallback_sqlite"]` · default `"fail_closed"`

**Defends** the meaning of cumulative exposure when the store breaks.
`fail_closed` refuses to run — a broker that cannot remember what a caller has
already seen cannot enforce a cumulative cap. `fallback_sqlite` degrades to a
durable local store. `fallback_memory` degrades to a per-process one, which
means every replica forgets independently.

**Costs** — `fail_closed` costs you availability: the Pod exits non-zero and
`CrashLoopBackOff` is the correct outcome. `fallback_memory` costs you the
control you configured the store for; choose it only where exposure caps are
advisory.

**Fails with**, under `fail_closed`, a startup failure that actually exits — the
CLI treats a lifespan that never started as a failure:

```console
$ nautilus serve --config /etc/nautilus/nautilus.yaml
ERROR:    Traceback (most recent call last):
...
nautilus.core.session_pg.SessionStoreUnavailableError: PostgresSessionStore unavailable (dsn=postgresql://db.internal:5432/nautilus): [Errno 111] Connection refused
ERROR:    Application startup failed. Exiting.
$ echo $?
1
```

Under `fallback_sqlite`, a failure of *both* still raises:

```
PostgresSessionStore unavailable (dsn=postgresql://db.internal:5432/nautilus: [Errno 111] Connection refused) and sqlite fallback at ./.nautilus/sessions.db failed: unable to open database file
```

**Example**

```yaml
session_store:
  backend: postgres
  dsn: "${SESSION_STORE_DSN}"
  on_failure: fail_closed
```

### `session_store.sqlite_path`

`str` · default `"./.nautilus/sessions.db"`

**Defends** the durability of the degraded path: it is the file
`backend: sqlite` uses, and the target `on_failure: fallback_sqlite` degrades
to. The default is relative, which in a container with a read-only root means
the fallback fails *at the moment you need it*.

**Costs** you a writable volume that survives restarts, and the recognition that
this file holds session exposure history — protect it like the audit log.

**Fails with**, when it cannot be created:

```
PostgresSessionStore unavailable (dsn=postgresql://db.internal:5432/nautilus: [Errno 111] Connection refused) and sqlite fallback at /var/lib/nautilus/sessions.db failed: unable to open database file
```

**Example**

```yaml
session_store:
  backend: postgres
  dsn: "${SESSION_STORE_DSN}"
  on_failure: fallback_sqlite
  sqlite_path: /var/lib/nautilus/sessions.db
```

### `session_store.ttl_seconds`

`int` · default `3600`

**Defends** by bounding how long exposure history — and the sensitive shape of
what a caller has been asking about — is retained. It also bounds how long a
cumulative cap keeps counting.

**Costs** you the cap itself if you set it too low: a caller that waits out the
TTL starts from zero, so a short TTL is an exfiltration budget refill.

**Fails with** no message. A too-short TTL shows up as escalation rules that
stop firing; test it by issuing the combination that should escalate, waiting
past the TTL, and confirming it escalates again from a clean slate.

**Example**

```yaml
session_store:
  ttl_seconds: 3600
```

### `session_store.purpose_ttl_seconds`

`int` · default `0` (disabled)

**Defends** against a stale declared purpose outliving the work it was declared
for — the caller says `emergency-care` once and rides it all day. Non-zero
feeds the session fact's `purpose_ttl_seconds` slot, which the shipped
`purpose-expired-deny` rule reads.

**Costs** you denials on long sessions that legitimately keep one purpose. `0`
is the default precisely so existing deployments see no new denials; the shipped
rule is guarded by `(> ?ttl 0.0)`.

**Fails with** a denial carrying the rule's reason once the window passes:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list patients","context":{"session_id":"s-1"}}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["denial_records"])'
[{'source_id': 'patients', 'reason': 'declared purpose has expired', ...}]
```

**Example**

```yaml
session_store:
  purpose_ttl_seconds: 900
```

### `session_store.lock_timeout_s`

`float | None` · default `30.0` · must be `> 0` · applies to every backend

**Defends** availability under contention. Every request from one caller takes
the same exposure-ledger lock and holds it across the source query — deliberate,
because two requests that both read the ledger empty would both pass a
cumulative cap. What this key adds is a *budget* for the queue, which otherwise
sits outside every other deadline in the config.

**Costs** you refusals when one caller is highly concurrent. `null` restores the
unbounded wait, which is how a caller once measured 32 seconds to an HTTP 200.

**Fails with**, when a value of `0` or less is configured:

```
Config validation failed:
  session_store.lock_timeout_s: Input should be greater than 0 [type=greater_than]
```

At runtime, exceeding the budget surfaces as a timeout error record for the
request rather than a hang.

**Example**

```yaml
session_store:
  lock_timeout_s: 10.0
```

### `session_store.acquire_timeout_s`

`float` · default `10.0` · `backend: postgres`

**Defends** against a deployment past its pool size simply ceasing to answer:
this bounds the wait for a connection from either pool.

**Costs** you errors instead of latency once the pool is exhausted — which is
the point, because a stalled broker is indistinguishable from a healthy slow one.

**Fails with** a `TimeoutError` surfaced in the request's error records rather
than a hang; the request completes with `sources_errored` populated.

**Example**

```yaml
session_store:
  backend: postgres
  dsn: "${SESSION_STORE_DSN}"
  acquire_timeout_s: 5.0
```

### `session_store.pool_min_size` / `pool_max_size` / `lock_pool_max_size`

`int` · defaults `1` / `10` / `32` · `backend: postgres`

**Defends** the broker's concurrency ceiling from its database's. Two pools
exist on purpose: `pool_max_size` sizes the short ledger reads and writes,
`lock_pool_max_size` sizes the ledger locks, which are held for the length of a
request. A request holding a lock must still be able to acquire the connection
it needs to finish, which is why they are not one pool.

**Costs** you connections on the database side —
`pool_max_size + lock_pool_max_size` per replica, so 42 with the defaults.
Multiply by replica count before raising them, and keep the total under
Postgres's `max_connections` or the *database* becomes the outage.

**Fails with** connection-acquisition timeouts bounded by `acquire_timeout_s`
(see above) when the pools are too small, and, when Postgres itself is out of
slots, an error record containing the server's own text:
`FATAL: sorry, too many clients already`.

**Example**

```yaml
session_store:
  backend: postgres
  dsn: "${SESSION_STORE_DSN}"
  pool_min_size: 2
  pool_max_size: 10
  lock_pool_max_size: 32
  acquire_timeout_s: 5.0
```

## `rules`, `rkm` — what governs the broker

### `rules.user_rules_dirs`

`list[str]` · default `[]`

**Defends** — and this is the direction that surprises people — by being *set*.
These directories hold the CLIPS rules the broker enforces, and they are also
where the RKM promotion path writes an approved rule. With the list empty there
is nowhere to promote to, so rule approval cannot complete.

**Costs** you a writable directory that is, by definition, code the broker
executes as policy. Mount it read-only if you promote rules out-of-band; if you
use the approval queue, it must be writable by the broker user and by nobody
else.

**Fails with**, on `POST /v1/rkm/queue/{id}/approve` with the key unset,
HTTP 422 and a body that names the recovery:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/rkm/queue/prop_7f3a/approve \
    -H "X-API-Key: $NAUTILUS_KEY_GOVERN" -H 'X-Nautilus-Reviewer: alice' \
    -H 'Content-Type: application/json' -d '{}'
{"detail":{"error":"promotion_failed","message":"no user_rules_dirs configured: nowhere to write the promoted rule","current_status":"approved","recovery":"fix the rule and re-approve to retry the promotion, or reject the proposal"}}
```

The proposal is deliberately left in `approved` so re-approving retries after
you fix the config.

**Example**

```yaml
rules:
  user_rules_dirs:
    - /etc/nautilus/rules
```

```bash
sudo install -d -m 0750 -o nautilus -g nautilus /etc/nautilus/rules
```

### `rules.packs`

`list[str]` · default `[]` · resolved by `fathom.packs` entry-point name, not by path

**Defends** by loading the policy you actually intend to enforce — the shipped
compliance packs (for example `data-routing-nist`) install the classification
hierarchy and the deny rules that most of this page's clearance and compartment
behaviour depends on. Empty means only whatever `user_rules_dirs` provides.

**Costs** you the pack's denials, and a dependency on the pack being installed
in the same environment as the broker. Names, not paths, so a third-party pack
loads exactly like a shipped one.

**Fails with**, for a name no installed distribution provides, a refusal to
start naming the pack — and, if the pack was what defined your hierarchy, the
`classification labels are not levels of the 'classification' hierarchy` error
from [`agents.<id>.clearance`](#agentsidclearance) becomes the symptom.

**Example**

```yaml
rules:
  packs:
    - data-routing-nist
  user_rules_dirs:
    - /etc/nautilus/rules
```

### `rules.consistency_checks`

`bool` · default `true`

**Defends** against the engine reporting a decision its own facts do not
support: after each run, the output is checked against the asserted state.
Leaving it on is the difference between a wrong decision and a wrong decision
you find out about.

**Costs** you per-request CPU. It exists as a key so performance-sensitive
deployments can opt out — deliberately, and in writing, rather than by accident.

**Fails with** an error record on the request when a check fails; the request
does not silently return the inconsistent result.

**Example**

```yaml
rules:
  consistency_checks: true
```

### `rkm.auto_promote.enabled`

`bool` · default `false` · **`true` is refused**

**Defends** human review of rule changes. Every promotion candidate routes to
the review queue regardless of observation count.

**Costs** you nothing, because you cannot turn it off. `true` is rejected at
load rather than accepted-and-ignored: nothing reads the flag, so a deployment
that set it believed proposals were skipping review when in fact none were being
promoted at all.

**Fails with** a refusal to start:

```
Config validation failed:
  rkm.auto_promote: Value error, rkm.auto_promote.enabled: auto-promotion is not implemented. Every proposal routes to the human-review queue (`nautilus rkm queue`, `POST /v1/rkm/queue/{id}/approve`); remove the key or set it to false. [type=value_error]
```

**Example**

```yaml
rkm:
  auto_promote:
    enabled: false   # or omit the block entirely
```

### `rkm.sandbox.min_entries`

`int` · default `100`

**Defends** against approving a rule on evidence too thin to mean anything:
below this many audit entries, `sandbox_replay` sets
`SandboxResult.insufficient_history = True` rather than reporting a clean run.

**Costs** you a wait after a fresh deployment before sandbox results are
meaningful. Lowering it makes approvals easier and their evidence weaker.

**Fails with** a sandbox report the reviewer must read rather than an error:

```console
$ nautilus rules validate /etc/nautilus/rules/new-rule.yaml --sandbox \
    --audit-log /var/lib/nautilus/audit.jsonl --json
{"insufficient_history": true, "...": "..."}
```

**Example**

```yaml
rkm:
  sandbox:
    min_entries: 500
```

## `ui`, `mcp`, `analysis`, `adapters`, `state_dir`

### `ui.enabled`

`bool` · default `false`

**Defends** by not existing. The console is a second front door to the same
broker: it authenticates a browser with a `nautilus_key` cookie holding an API
key, and its playground runs real queries against real sources. When the key is
false the routes are **not registered at all**, so `/admin` is a 404 rather than
a login prompt on a port whose operator did not know it served one.

**Costs**, when true: a login form to guess at, and a cookie set with
`httponly=True, samesite="lax", max_age=86400`, and `secure` only when the login
arrived over TLS (directly or via `X-Forwarded-Proto`) — so over plain HTTP the
cookie, which is an API key, is on the wire in clear. Never enable it without TLS
in front.

**Fails with** a 404 when off, which is the check:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/admin
404
```

When on, a wrong key re-renders the login page with HTTP 401 and the message
`Invalid API key` in the form.

**Example**

```yaml
ui:
  enabled: false
```

The root route follows the same setting: with `ui.enabled: true`, `GET /`
returns a 302 to `/admin`; with it false it returns 200 and a JSON index of the
routes that do exist:

```console
$ curl -s http://127.0.0.1:8000/ | python -m json.tool
{
    "service": "nautilus",
    "version": "0.2.2",
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

### `mcp.expose_declare_handoff`

`bool` · default `false`

**Defends** by keeping the optional `nautilus_declare_handoff` tool off the MCP
tool list. An MCP client enumerates every tool it is offered and a model will
call what it can see; a surface you did not mean to expose is one an agent will
find.

**Costs** you the handoff workflow when off. Turn it on only for the deployments
whose agents actually perform handoffs.

**Fails with** the tool simply being absent from `tools/list` — verify by
enumeration rather than by reading the config:

```console
$ nautilus serve --config /etc/nautilus/nautilus.yaml --transport mcp --mcp-mode stdio &
$ printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' \
  | nc -U /dev/null 2>/dev/null || echo "use your MCP client's tools/list"
```

With an MCP client, `tools/list` must not contain `nautilus_declare_handoff`.

**Example**

```yaml
mcp:
  expose_declare_handoff: false
```

### `mcp.max_response_bytes`

`int | None` · default `262144` (256 KiB) · must be `> 0`

**Defends** the caller's context window and bill. An MCP tool result is read
straight into a model's context, and the SDK puts the payload on the wire twice
— once as text content, once as `structuredContent` — so measured wire cost is
about 2.1x this number (262144 here put 553,040 bytes on the pipe). Adapters cap
each source at 1000 rows, so a config with several sources multiplies from there.

**Costs** you rows: they are dropped whole and every source touched is named in
`truncated_sources`. `null` removes the bound. REST is unaffected either way — an
HTTP client streams to a file rather than into a context window.

**Fails with**, for a non-positive value:

```
Config validation failed:
  mcp.max_response_bytes: Input should be greater than 0 [type=greater_than]
```

At runtime, truncation is reported in the result's `truncated_sources`, never
silently.

**Example**

```yaml
mcp:
  max_response_bytes: 262144
```

### `analysis.mode`

`Literal["pattern", "llm-first", "llm-only"]` · default `"pattern"`

**Defends** the data boundary: `pattern` keeps intent analysis entirely local.
`llm-first` and `llm-only` send the caller's intent text to a provider — which,
for a hosted provider, means the intent leaves your network. Intents routinely
contain the sensitive terms the query is about.

**Costs** — `pattern`: weaker intent understanding. `llm-first`: an external
dependency that falls back to `pattern` on timeout or error. `llm-only`:
fail-closed on provider failure, so the provider's availability becomes yours.

**Fails with** no error for the wrong choice; it is a policy decision the config
cannot make for you. `nautilus serve --air-gapped` is the enforcement, and it
says what it overrode:

```console
$ nautilus serve --config /etc/nautilus/nautilus.yaml --air-gapped
WARN: --air-gapped overrides analysis.mode from 'llm-first' to 'pattern' (NFR-1)
WARN: --air-gapped refuses analysis.provider (type='anthropic'); dropping it (NFR-1)
```

An invalid value is refused:

```
Config validation failed:
  analysis.mode: Input should be 'pattern', 'llm-first' or 'llm-only' [type=literal_error]
```

**Example**

```yaml
analysis:
  mode: pattern
```

### `analysis.timeout_s`

`float` · default `2.0`

**Defends** the request path from a slow analyzer: this is the budget for intent
analysis, above whatever the provider's own timeout is.

**Costs** you fallback to the pattern analyzer (under `llm-first`) or a failed
request (under `llm-only`) when a legitimate provider is slow.

**Fails with** the fallback path being taken; under `llm-only` the broker fails
closed with a structured error audit rather than answering from a degraded
analysis.

**Example**

```yaml
analysis:
  mode: llm-first
  timeout_s: 2.0
```

### `analysis.keyword_map`

`dict[str, list[str]]` · default `{}`

**Defends** the quality of pattern-mode routing: it maps your vocabulary onto
data types, and data types are what escalation rules combine. A term that maps
to nothing routes to nothing, which is a *quiet* under-enforcement rather than a
denial.

**Costs** you maintenance as your vocabulary changes, and over-broad mappings
cause over-broad routing.

**Fails with** no error — an unmapped intent simply selects no source:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}' \
  | python -c 'import json,sys; d=json.load(sys.stdin); print(d["sources_skipped"], d["skip_records"])'
['customers'] [{'source_id': 'customers', 'reason': "no routing rule selected source 'customers' for this request"}]
```

**Example**

```yaml
analysis:
  mode: pattern
  keyword_map:
    pii: [customer, contact, address, email]
    phi: [patient, diagnosis, treatment]
```

### `analysis.provider.type`

`Literal["anthropic", "openai", "local"]` · discriminator, no default

**Defends** by making the egress destination explicit. `anthropic` and `openai`
send intent text to a third party. `local` sends it to `base_url`, which is only
air-gap-safe if that URL is on your own network.

**Costs** — see `analysis.mode`. Setting a provider without setting
`analysis.mode` away from `pattern` costs nothing and does nothing: the provider
is configured and unused.

**Fails with**, for an unknown tag:

```
Config validation failed:
  analysis.provider: Input tag 'azure' found using 'type' does not match any of the expected tags: 'anthropic', 'openai', 'local' [type=union_tag_invalid]
```

**Example**

```yaml
analysis:
  mode: llm-first
  provider:
    type: local
    base_url: "http://inference.internal:8080/v1"
    model: qwen2.5-7b-instruct
```

### `analysis.provider.api_key_env`

`str` · required for `anthropic` and `openai`; `str | None` (default `None`) for `local`

**Defends** the provider credential by *never being the credential*. The key is
the **name of an environment variable**, read at call time with
`os.getenv(self.api_key_env)`; the secret is never in the config file and never
in a validation error.

**Costs** you setting that variable in the broker's environment — and noticing
when you have not, because the failure is at request time, not at boot.

**Fails with**, when omitted for a hosted provider:

```
Config validation failed:
  analysis.provider.anthropic.api_key_env: Field required [type=missing]
```

When the named variable is unset, the provider call fails and — under
`llm-first` — the pattern analyzer answers instead, silently. Under `llm-only`
the request fails closed with a structured error audit. Check the variable
exists without printing it:

```console
$ systemctl show nautilus -p Environment | grep -c ANTHROPIC_API_KEY
1
```

**Example**

```yaml
analysis:
  mode: llm-first
  provider:
    type: anthropic
    api_key_env: ANTHROPIC_API_KEY
    model: claude-sonnet-4-5
```

### `analysis.provider.base_url`

`str` · required for `type: local`

**Defends** an air-gapped deployment's boundary: this is the only provider URL
you control. Point it at a host inside your network. `nautilus serve
--air-gapped` additionally **drops any `type: llm` source whose `connection`
host is not loopback** and says so.

**Costs** you running the inference server. Note what `--air-gapped` does *not*
do: it does not inspect `analysis.provider.base_url` beyond dropping the whole
provider block, so a non-loopback `base_url` is your responsibility under normal
`serve`.

**Fails with**, when omitted:

```
Config validation failed:
  analysis.provider.local.base_url: Field required [type=missing]
```

and, from `--air-gapped`, for a non-loopback LLM source:

```
WARN: --air-gapped drops LLM source id='remote-llm' — connection host is not loopback (NFR-1, #43)
```

**Example**

```yaml
analysis:
  mode: llm-first
  provider:
    type: local
    base_url: "http://127.0.0.1:8080/v1"
    model: qwen2.5-7b-instruct
```

### `analysis.provider.model`

`str` · default `"claude-sonnet-4-5"` (`anthropic`) / `"gpt-4o-mini"` (`openai`) / required (`local`)

**Defends** reproducibility of the analysis step: pinning the model means an
upstream default change cannot silently alter which sources an intent routes to.

**Costs** you a config change to move models, which is the point.

**Fails with**, for `local` when omitted:

```
Config validation failed:
  analysis.provider.local.model: Field required [type=missing]
```

For hosted providers a wrong model name fails at request time with the
provider's own 404, which under `llm-first` falls back to pattern analysis.

**Example**

```yaml
analysis:
  provider:
    type: openai
    api_key_env: OPENAI_API_KEY
    model: gpt-4o-mini
```

### `analysis.provider.timeout_s`

`float` · default `2.0` · per provider spec

**Defends** the request path from the provider specifically, as distinct from
`analysis.timeout_s`, which bounds the analysis step as a whole.

**Costs** you fallbacks on a slow-but-working provider.

**Fails with** a provider timeout, which under `llm-first` is invisible except in
the audit record's analyzer field — the response is still 200 from the pattern
analyzer. Under `llm-only` it fails the request.

**Example**

```yaml
analysis:
  mode: llm-first
  timeout_s: 3.0
  provider:
    type: anthropic
    api_key_env: ANTHROPIC_API_KEY
    timeout_s: 2.0
```

### `adapters[].module_path` / `class` / `source_type`

`str` · all three required · note the YAML key is `class`, aliased to the field `class_name`

**Defends** nothing — this is the most dangerous block in the file, listed here
so you treat it that way. **The referenced module is imported and executed at
broker start with the broker's privileges**, which means it runs with read access
to every source credential in the config. Give `adapters:` entries the same trust
you give installed packages, and keep `nautilus.yaml` writable only by the
operator account.

**Costs** you a supply-chain review per entry. The declared `source_type` is
added to the set of valid `sources[].type` values, so a local adapter can shadow
a name you expected to be a built-in.

**Fails with**, when the class does not declare the same `source_type`, a
fail-closed startup error from `Broker._load_local_adapters` naming the mismatch;
when the module cannot be imported, a `ModuleNotFoundError` naming
`module_path`; and, when a required field is missing:

```
Config validation failed:
  adapters.0.class: Field required [type=missing]
```

**Example**

```yaml
adapters:
  - module_path: acme_nautilus.adapters.ledger
    class: LedgerAdapter
    source_type: ledger
sources:
  - id: ledger
    type: ledger
    connection: "${LEDGER_DSN}"
    classification: confidential
    data_types: [financial]
```

### `state_dir`

`str | None` · default `None` (the config file's directory) · relative paths resolve against the config file's directory

**Defends** schema-drift detection across restarts. Nautilus writes adapter
fingerprint baselines under `<state_dir>/.nautilus/adapters/fingerprints/`; those
baselines are how a source's schema changing underneath you becomes a signal
rather than a surprise. Defaulting to the config directory — which every shipped
deployment mounts read-only — means the baselines are lost on every restart and
drift is never detected.

**Costs** you one more writable volume, holding a directory an attacker who can
write it could use to suppress drift alerts. Mode `0750`, owned by the broker
user.

**Fails with** a warning at write time naming the path when the directory is not
writable, and — the real symptom — drift that is never reported, because there is
no baseline to compare against.

**Example**

```yaml
state_dir: /var/lib/nautilus/state
```

```bash
sudo install -d -m 0750 -o nautilus -g nautilus /var/lib/nautilus/state
```

## Environment variables

Nautilus reads exactly nine environment variables by fixed name, plus any name
you reference from the config with `${VAR}`. There is no `NAUTILUS_*` override
for config keys: the file is the config.

### `${VAR}` (any name) — config value interpolation

Read by `nautilus/config/loader.py:EnvInterpolator` · every string leaf of the YAML

**Defends** the config file from holding secrets. `${VAR}` anywhere in any string
value is replaced from the process environment before validation, so DSNs, API
keys, tokens and passwords live in the environment (or a systemd
`EnvironmentFile`, or a Kubernetes Secret) and never in the file.

**Costs** you a startup failure whenever the environment is incomplete — which is
the correct trade, because the alternative is a broker that starts with an empty
password.

**Fails with** a refusal to start naming the variable:

```console
$ nautilus serve --config /etc/nautilus/nautilus.yaml
ERROR: invalid config: Missing env var 'CUSTOMERS_DSN' referenced by source id='customers'
$ echo $?
2
```

For a `${VAR}` outside any `sources:` entry the message reads
`referenced by source id='None'` — the variable name is still the diagnosis.

**Example**

```yaml
sources:
  - id: customers
    type: postgres
    connection: "${CUSTOMERS_DSN}"
    table: customers
    classification: cui
    data_types: [pii]
```

```bash
sudo install -m 0600 -o nautilus -g nautilus /dev/null /etc/nautilus/nautilus.env
sudo tee /etc/nautilus/nautilus.env >/dev/null <<EOF
CUSTOMERS_DSN=postgresql://nautilus:<DB_PASSWORD>@db.internal:5432/customers
NAUTILUS_KEY_REPORTING=$NAUTILUS_KEY_REPORTING
EOF
```

### `NAUTILUS_REVIEWER`

Read by `nautilus/cli/_common.py:require_reviewer` · required by every governance CLI subcommand

**Defends** attribution of governance decisions. Approving, rejecting, retracting
and rolling back a rule are exactly the changes the audit log exists to record,
and the reviewer identity comes from this variable only — there is deliberately
no `$USER` auto-detection, because that would be trivially spoofable.

**Costs** you exporting it in every operator shell and CI job that governs rules.

**Fails with** exit code 1 and, on stderr:

```console
$ unset NAUTILUS_REVIEWER
$ nautilus rkm queue approve prop_7f3a --url http://127.0.0.1:8000 \
    --api-key "$NAUTILUS_KEY_GOVERN" --config /etc/nautilus/nautilus.yaml
ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.
$ echo $?
1
```

**Example**

```bash
export NAUTILUS_REVIEWER="alice@example.com"
nautilus rkm queue approve prop_7f3a --url http://127.0.0.1:8000 \
  --api-key "$NAUTILUS_KEY_GOVERN" --config /etc/nautilus/nautilus.yaml
```

The HTTP equivalent is the `X-Nautilus-Reviewer` header — see
[Headers](#request-headers).

### `TEST_PG_DSN`

Read by `nautilus/core/broker.py` when `session_store.dsn` is unset

**Defends** nothing — it is a **fallback you should know about**. With
`session_store.backend: postgres` and no `dsn`, the broker connects to whatever
`TEST_PG_DSN` names. It exists so integration fixtures can reuse a container DSN
without duplicating YAML.

**Costs** you a surprise if the variable is set in production: a broker with a
typo'd or absent `dsn` will quietly connect to the test database instead of
failing. Set `session_store.dsn` explicitly and do not export `TEST_PG_DSN` in
production environments.

**Fails with** the ordinary store-unavailable error if neither is set:

```
PostgresSessionStore unavailable (dsn=): [Errno 111] Connection refused
```

**Example**

```yaml
session_store:
  backend: postgres
  dsn: "${SESSION_STORE_DSN}"   # explicit; do not rely on TEST_PG_DSN
```

```bash
# Confirm the fallback is not armed in production:
systemctl show nautilus -p Environment | grep -c TEST_PG_DSN || echo "not set (good)"
```

### `INFLUXDB_V2_TOKEN`

Read by `nautilus/adapters/influxdb.py` when a `type: influxdb` source has no `auth` block

**Defends** nothing; it is a credential path that bypasses `sources[].auth`. The
InfluxDB adapter falls back to this process-wide variable, so one token serves
every InfluxDB source in the file — including ones you meant to scope differently.

**Costs** you per-source credential separation. Prefer an explicit
`auth: {type: bearer, token: "${INFLUX_TOKEN_<SOURCE>}"}` on each source.

**Fails with** nothing at startup when neither is present — the client is built
without a token and the failure arrives from InfluxDB itself as a 401 in the
request's `sources_errored`. Declaring an auth type InfluxDB cannot use *is*
refused, by name:

```
InfluxDBAdapter: source 'metrics' declares auth type 'basic', which InfluxDB cannot use. Use 'bearer' (token=the InfluxDB API token), or omit 'auth' to read INFLUXDB_V2_TOKEN from the environment.
```

**Example**

```yaml
sources:
  - id: metrics
    type: influxdb
    connection: "https://influx.internal:8086"
    classification: cui
    data_types: [telemetry]
    auth:
      type: bearer
      token: "${INFLUX_TOKEN_METRICS}"   # explicit beats the env fallback
```

### `INFLUXDB_V2_ORG`

Read by `nautilus/adapters/influxdb.py`

**Defends** nothing; it names the InfluxDB organisation the adapter queries. It
is listed because it is a second piece of connection state that lives outside
`nautilus.yaml`, so a config review alone does not tell you what the adapter
will talk to.

**Costs** you configuration that is invisible to config review. Record it in the
same place you record the DSNs.

**Fails with** an adapter error from the InfluxDB client naming the missing
organisation, surfaced in `sources_errored`.

**Example**

```bash
# In the unit's EnvironmentFile, alongside the DSNs, so it is reviewable:
INFLUXDB_V2_ORG=platform-observability
```

### `OTEL_SDK_DISABLED`

Read by `nautilus/observability/__init__.py:setup_otel` · compared case-insensitively against `"true"`

**Defends** against telemetry you did not intend leaving the host: `true` makes
OpenTelemetry setup a complete no-op.

**Costs** you **all** metrics, not just traces — the same switch drops the
Prometheus metric reader, so `/metrics` exports only the `process_*` series and
every `nautilus_*` counter disappears along with every dashboard built on them.
If your goal is only to stop trace export, leave this unset and simply do not set
an OTLP endpoint.

**Fails with** no message. Verify by scraping:

```console
$ curl -s http://127.0.0.1:8000/metrics | grep -c '^nautilus_'
0
```

A count of `0` on a broker that has served requests means telemetry is disabled.

**Example**

```bash
# Air-gapped host, dashboards not in use:
OTEL_SDK_DISABLED=true
```

### `OTEL_EXPORTER_OTLP_ENDPOINT`

Read by `nautilus/observability/instrumentation.py`

**Defends** by being **unset by default**: the OTLP span exporter is only
installed when this (or the traces-specific variable below) is set. Spans carry
intent metadata, so an accidental exporter pointed at an unintended collector is
a data-egress event.

**Costs**, when set: every span batch goes to that endpoint. Point it at a
collector you control, over a network path you control. Setting it to an
unreachable address is worse than leaving it unset — that is the failure the
default guard exists to prevent (three WARNING retries plus an ERROR per batch,
about 39 log lines a minute per replica, which buries the broker's own
diagnostics and trips any alert-on-ERROR rule).

**Fails with** exporter retry noise in the broker's own log, e.g.
`Failed to export batch code: 503, reason: ...`, repeating per batch.

**Example**

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.observability.svc:4318
```

### `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`

Read by `nautilus/observability/instrumentation.py`

**Defends** the same boundary as the previous variable; either one being set
installs the span exporter. This one is the traces-specific override when your
collector splits signals across endpoints.

**Costs** the same. Note the consequence of the either-or check: setting only a
*metrics* OTLP endpoint does not install the span exporter, which is intentional.

**Fails with** the same exporter retry lines.

**Example**

```bash
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://tempo.observability.svc:4318/v1/traces
```

### `OTEL_PYTHON_FASTAPI_EXCLUDED_URLS`

Set with `os.environ.setdefault` by `nautilus/observability/instrumentation.py` · default `"/healthz,/readyz"`

**Defends** your trace volume from probe traffic. Because it is `setdefault`, a
value you export **wins** — and if you export one that omits `/healthz,/readyz`,
every Kubernetes probe becomes a span.

**Costs** you nothing at the default. If you override it, include the probes.

**Fails with** no error; the symptom is probe spans in your tracing backend.

**Example**

```bash
OTEL_PYTHON_FASTAPI_EXCLUDED_URLS=/healthz,/readyz,/metrics
```

### `NO_COLOR`

Read by `nautilus/cli/_common.py` · any value disables ANSI colour

**Defends** the legibility of captured CLI output. ANSI is emitted only when
stdout is a TTY *and* `NO_COLOR` is unset, so redirected output is already clean;
set this when a tool allocates a PTY and escape codes end up in your ticket, your
log shipper or your evidence bundle.

**Costs** you colour.

**Fails with** no error; the symptom is `\x1b[31m` sequences in captured text.

**Example**

```bash
NO_COLOR=1 nautilus rkm queue list --status pending --json
```

## Request headers

### `X-API-Key`

Request · `nautilus/transport/auth.py:api_key_header` · required under `api.auth.mode: api_key`

**Defends** every data and governance route. Compared against `api.keys` with
`secrets.compare_digest`, so a wrong key does not leak its distance from a right
one through response timing.

**Costs** you a header on every call, and — because Nautilus does not terminate
TLS — a cleartext credential on the wire unless something in front of it does.

**Fails with** HTTP 401 and one of two bodies, which distinguish two different
mistakes:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}'
{"detail":"Not authenticated"}
$ curl -s -X POST http://127.0.0.1:8000/v1/request -H 'X-API-Key: wrong' \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}'
{"detail":"Invalid API key"}
```

`Not authenticated` means the header was absent; `Invalid API key` means it was
present and matched nothing — including when `api.keys` is empty, which fails
closed.

### `X-Forwarded-User`

Request · `nautilus/transport/auth.py:proxy_trust_dependency` · used only under `api.auth.mode: proxy_trust`

**Defends** nothing on its own — under `proxy_trust` this header **is** the
credential. It is an identity only while nobody but your proxy can set it, which
is what `api.auth.trusted_proxies` enforces.

**Costs** you a proxy that always sets it (Nautilus treats a missing header from
a trusted peer as a bypass attempt) and a proxy that always *strips* it from
client input before setting its own. A proxy that forwards a client-supplied
`X-Forwarded-User` is a total authentication bypass.

**Fails with** HTTP 401 and:

```json
{"detail":"Forwarded identity rejected: peer is not a trusted proxy"}
```

or, from a trusted peer with no header:

```json
{"detail":"Missing X-Forwarded-User"}
```

**Example — the nginx side that makes this safe**

```nginx
location /v1/ {
    proxy_set_header X-Forwarded-User $ssl_client_s_dn;  # set, never pass through
    proxy_pass http://127.0.0.1:8000;
}
```

### `X-Nautilus-Session-Token`

Request and response · `nautilus/transport/auth.py:SESSION_TOKEN_HEADER` · active when `session_tokens.enabled`

**Defends** session provenance: the broker-issued JWS travels on the same
channel as the request, so the session binding it carries actually applies. The
broker re-verifies it and lets the token's `session_id` override the declared
one. A `session_token` in the request *body* wins if a caller sends both.

**Costs** you a header to plumb through your agent framework, and a 401 whenever
the token is present but bad — absent is fine, present-and-invalid is not.

**Fails with** HTTP 401 naming the reason code:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    -H 'X-Nautilus-Session-Token: abc.def.ghi' \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}'
{"detail":"Invalid session token: bad_signature"}
```

Reason codes: `missing`, `bad_signature`, `expired`, `unknown_kid`,
`wrong_broker`.

### `X-Nautilus-Reviewer` (and the legacy `X-Reviewer`)

Request · `nautilus/transport/fastapi_app.py` · required by every governance write route

**Defends** attribution of a rule change made over HTTP, exactly as
`NAUTILUS_REVIEWER` does for the CLI. A credential bound to an agent is *not*
automatically the reviewer — the header is separate on purpose, so the audit
record names a human.

**Costs** you a header on approve, reject, retract and rollback. `X-Reviewer` is
accepted as a fallback for older clients.

**Fails with** HTTP 400:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/rkm/queue/prop_7f3a/approve \
    -H "X-API-Key: $NAUTILUS_KEY_GOVERN" -H 'Content-Type: application/json' -d '{}'
{"detail":"X-Nautilus-Reviewer header required"}
```

### `Retry-After`

Response · emitted with HTTP 503 by the `_ConcurrencyLimit` middleware · value `1`

**Defends** your load balancer's ability to tell a saturated broker from a broken
one, so it backs off instead of retrying into the same queue.

**Costs** nothing.

**Fails with** — it *is* the failure signal:

```console
$ curl -s -D - -o /dev/null -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}' | grep -i retry-after
retry-after: 1
```

### `Cookie: nautilus_key`

Request · set by `POST /admin/login`, read by `caller_identity` · only when `ui.enabled: true`

**Defends** the console session — and, importantly, resolves to the **same**
caller identity as the header form. Reading only the header used to give one
credential a different identity depending on which door it came through:
unbound, holding every capability, and accumulating exposure under a separate
principal.

**Costs** you a cookie that **contains an API key**, set with `httponly=True`,
`samesite="lax"`, `max_age=86400`, and `secure` **when the login request arrived
over TLS** — either directly, or with `X-Forwarded-Proto: https` from a
terminating ingress, which is how every manifest in `deploy/` runs. Over plain
HTTP the flag is omitted on purpose: a `Secure` cookie is silently dropped by the
browser, which would turn a local console into a login loop. So over plain HTTP
it is still a credential in clear text, and behind TLS it is a credential a
browser will hold for 24 hours. This is the strongest argument for
`ui.enabled: false`.

**Fails with** a redirect rather than an error — an unauthenticated console
request is sent to the login page:

```console
$ curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://127.0.0.1:8000/admin/sources
302 http://127.0.0.1:8000/admin/login
```

A wrong key at the form re-renders the page with HTTP 401 and the text
`Invalid API key`.

## CLI subcommands and flags

`nautilus --help` lists every subcommand: `version`, `session`, `health`,
`serve`, `demo`, `init`, `rkm`, `rule`, `adapters`, `key`, `rules`, `events`,
`attestation`. The security-relevant ones are below. Exit codes are uniform:
`0` success, `1` user error, `2` validation or policy failure; `3` is
deliberately unused.

### `nautilus init [--dir DIR]`

**Defends** you from inventing your own starter config — and from shipping a
shared secret, because it mints a fresh key per scaffold with
`secrets.token_hex(16)` rather than embedding a constant.

**Costs** you a config that is *not* hardened: it writes the key as a **bare
string**, so the generated broker holds every capability on one unbound key. The
generated file says so in a comment. Treat `nautilus init` output as a starting
point, not a deployment.

**Fails with** exit code 1 rather than overwriting:

```console
$ nautilus init --dir /etc/nautilus
ERROR: /etc/nautilus/nautilus.yaml already exists — refusing to overwrite it
$ echo $?
1
```

**Example**

```console
$ nautilus init --dir /etc/nautilus
OK: wrote /etc/nautilus/nautilus.yaml
```

Then replace the bare key with the scoped form before the port is reachable.

### `nautilus serve --config PATH`

`str` · default `nautilus.yaml`

**Defends** against running the wrong config: nothing is discovered, searched for
or merged. The path you pass is the only config.

**Costs** you an explicit `--config` in every unit file and container command.

**Fails with** exit code 2 and `ERROR: invalid config:` followed by the specific
validation failure — see the [failure index](#failure-index).

**Example**

```bash
nautilus serve --config /etc/nautilus/nautilus.yaml
```

### `nautilus serve --bind HOST:PORT`

`str` · default unset; overrides `api.host` / `api.port`; fallback `127.0.0.1:8000`

**Defends** nothing by itself, but it is the flag that decides reachability, and
it silently wins over the config. If you harden `api.host` in YAML and your unit
file passes `--bind 0.0.0.0:8000`, the flag is what runs.

**Costs** you a second place to look when auditing what the broker binds. Prefer
one or the other consistently; grep your unit files for `--bind` as part of any
exposure review.

**Fails with** the uvicorn bind error for a taken port
(`[Errno 98] ... address already in use`), and a `ValueError` for a malformed
value.

**Example**

```bash
nautilus serve --config /etc/nautilus/nautilus.yaml --bind 127.0.0.1:8000
```

### `nautilus serve --transport {rest,mcp,both}` and `--mcp-mode {stdio,http}`

`--transport` default `rest` · `--mcp-mode` default `stdio`

**Defends** by exposing one surface at a time. `--transport rest` is the default
and serves no MCP. `--mcp-mode stdio` serves MCP over the process's own stdio,
which is reachable only by whoever can spawn the process — no listening socket
at all.

**Costs**, with `--transport both --mcp-mode http`, a second HTTP surface on the
**same bind**, gated by the same `api.keys` and the same capability checks
(`caller_identity` is shared precisely so a client cannot get a different answer
by changing transport). Everything on this page about TLS and reverse proxies
applies to it identically.

**Fails with** argparse rejection for an unknown value:

```console
$ nautilus serve --config /etc/nautilus/nautilus.yaml --transport grpc
usage: nautilus serve [-h] [--config CONFIG] [--transport {rest,mcp,both}] ...
nautilus serve: error: argument --transport: invalid choice: 'grpc' (choose from 'rest', 'mcp', 'both')
$ echo $?
2
```

**Example**

```bash
nautilus serve --config /etc/nautilus/nautilus.yaml --transport rest
```

### `nautilus serve --air-gapped`

flag, default off

**Defends** the no-egress guarantee at the point of execution rather than in
review. It forces `analysis.mode: pattern`, drops `analysis.provider` entirely,
and drops any `type: llm` source whose `connection` host is not loopback. The
rewritten config goes to a temp file; your original is untouched.

**Costs** you the LLM analyzer and any remote LLM source. It is
non-destructive and silent on a config that already conforms — no WARN means
nothing was overridden.

**Fails with** WARN lines on stderr naming every field it changed:

```console
$ nautilus serve --config /etc/nautilus/nautilus.yaml --air-gapped
WARN: --air-gapped drops LLM source id='remote-llm' — connection host is not loopback (NFR-1, #43)
WARN: --air-gapped overrides analysis.mode from 'llm-first' to 'pattern' (NFR-1)
WARN: --air-gapped refuses analysis.provider (type='anthropic'); dropping it (NFR-1)
```

Treat any of these three lines in a production log as a config that disagrees
with its deployment.

**Example**

```bash
nautilus serve --config /etc/nautilus/nautilus.yaml --air-gapped
```

### `nautilus serve --log-format {text,json}`

default `text`

**Defends** your ability to actually search the security-relevant startup lines —
`api.keys is empty`, `is a bare string`, the `--air-gapped` WARNs, the
`audit.chained` warning. In `text` they are human-readable; in `json` they are
one structured object per line on stdout, ingestable by a SIEM without a regex.

**Costs** you readability at a local prompt.

**Fails with** argparse rejection for an unknown value, as with `--transport`.

**Example**

```bash
nautilus serve --config /etc/nautilus/nautilus.yaml --log-format json
```

### `nautilus health [--url URL]`

default `http://127.0.0.1:8000/readyz`

**Defends** your deployment from starting traffic at a broker that cannot write
its audit log: `/readyz` reports 503 when the audit sink's probe fails, and this
command exits non-zero on anything but 200.

**Costs** nothing.

**Fails with** a non-zero exit and the status it saw:

```console
$ nautilus health --url http://127.0.0.1:8000/readyz
FAIL 503 http://127.0.0.1:8000/readyz
$ echo $?
1
```

**Example**

```console
$ nautilus health --url http://127.0.0.1:8000/readyz
OK 200 http://127.0.0.1:8000/readyz
```

An unreachable broker prints
`FAIL unreachable http://127.0.0.1:8000/readyz: <reason>`.

### `nautilus key list|rotate|revoke`

`--url URL` · `--api-key KEY` · `--json` · plus `--yes` on `rotate` and `revoke`, and `--reason REASON` (required) on `revoke`

**Defends** the session-token signing ring. `rotate` mints a new primary key and
keeps the old one verifying; `revoke` removes a key's private half immediately,
so tokens signed by it stop verifying. `--reason` is mandatory on `revoke` so the
audit record says why.

**Costs** — `revoke` invalidates live sessions signed by that `kid` at once, and
`--yes` is required because both are destructive.

**Fails with**, for a missing confirmation, exit 1 and
`ERROR: rotate requires --yes to confirm.` (or `ERROR: revoke requires --yes to
confirm.`); with no `--url`, exit 2; with no `NAUTILUS_REVIEWER`, exit 1 and the
env-var message below. For an unknown key the broker answers 404
`{"detail":"kid '...' not found"}`, and for a malformed id, 400
`{"detail":"kid must be a UUID"}`. Without the `keys` capability the credential
is refused:
`{"detail":"This credential does not hold the 'keys' capability (it holds ['query'])"}`.

**Example**

```console
$ nautilus key list --url http://127.0.0.1:8000 --api-key "$NAUTILUS_KEY_KEYS" --json
[{"kid": "ee0eb00e-38ae-4060-90dc-a9aac8da460d", "kty": "OKP", "use": "sig"}]
$ export NAUTILUS_REVIEWER="alice@example.com"
$ nautilus key rotate --url http://127.0.0.1:8000 --api-key "$NAUTILUS_KEY_KEYS" --yes
OK: rotated: new primary kid=3b1c7f42-0d2e-4a91-9c55-1f7a0b6d8e30  reviewer=alice@example.com
$ nautilus key revoke ee0eb00e-38ae-4060-90dc-a9aac8da460d \
    --url http://127.0.0.1:8000 --api-key "$NAUTILUS_KEY_KEYS" \
    --reason "quarterly rotation" --yes
OK: revoked: kid=ee0eb00e-38ae-4060-90dc-a9aac8da460d  reason='quarterly rotation'  reviewer=alice@example.com
```

On a broker with `session_tokens.enabled: false`, `list` prints
`no active keys (session tokens are disabled on this broker)`.

### `nautilus attestation verify LOG [--pubkey PEM] [--expected-head HASH] [--anchor-token JWS] [--json]`

`--pubkey` defaults to `<log>.pub.pem` beside the log

**Defends** the evidence *offline*: it checks the hash chain and every JWS
without the broker's participation, so a compromised broker cannot vouch for
itself. `--expected-head` and `--anchor-token` are what close tail truncation —
without one of them, a log that simply stops early still verifies.

**Costs** you a public key and an out-of-band place to keep the head hash or the
checkpoint token. Run it on a copy, from a host the broker cannot write to.

**Fails with** a non-zero exit and a `FAIL:` line naming what broke:

```console
$ nautilus attestation verify /var/lib/nautilus/audit.jsonl \
    --pubkey /etc/nautilus/keys/attestation.pub.pem
ERROR: attestation verify: signature invalid at record 41
$ echo $?
2
```

**Example**

```console
$ nautilus attestation verify /var/lib/nautilus/audit.jsonl \
    --pubkey /etc/nautilus/keys/attestation.pub.pem \
    --expected-head "<HEAD_HASH_YOU_MIRRORED>"
OK: chain valid — 12043 records, head 9f2c1d0b7a5e4c93, anchored
```

### `nautilus rkm queue approve|reject` and `nautilus rule retract|rollback`

require `NAUTILUS_REVIEWER`; `--url URL` and `--api-key KEY` (approve/reject reach
a running broker); `--config PATH` (where the decision record is written);
`--reason` on `reject`; `--yes` on destructive operations; `--json`

**Defends** the rule set — the thing that decides every allow and deny. These
write to the audit log through the config's `audit.path`, so the record of who
approved what lands with every other decision. Without `--config` they fall back
to the default `AuditConfig` path (`./audit.jsonl`) and **warn**, so the operator
sees where the record actually went.

**Costs** you `NAUTILUS_REVIEWER` in every operator shell and CI job.

**Fails with** exit 1 and
`ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your
operator identity.` when the variable is unset; the HTTP equivalents fail with
`{"detail":"reason is required for rejection"}`,
`{"detail":"yes=true required for destructive operation"}` (HTTP 412), and
`{"detail":{"error":"already_decided","current_status":"approved"}}` (HTTP 409).

**Example**

```bash
export NAUTILUS_REVIEWER="alice@example.com"
nautilus rkm queue approve prop_7f3a --url http://127.0.0.1:8000 \
  --api-key "$NAUTILUS_KEY_GOVERN" --config /etc/nautilus/nautilus.yaml --json
```

## Routes and what gates them

Every route on the REST surface, with the capability it requires. `POST` routes
also require the auth guard (`X-API-Key`, or `X-Forwarded-User` from a trusted
proxy) — an unauthenticated caller gets 401 before any 403.

| Route | Capability | Auth | Notes |
|---|---|---|---|
| `POST /v1/request` | `query` | yes | the data path |
| `POST /v1/query` | `query` | yes | alias of `/v1/request`, same code path |
| `GET /v1/sources` | `query` | yes | source inventory, no rows |
| `POST /v1/sessions` | `query` | yes | mints a session token |
| `GET /v1/adapters` | `query` | yes | |
| `GET /v1/adapters/{name}/schema` | `query` | yes | 501 when the adapter has no introspection |
| `GET /v1/rules` | `query` | yes | |
| `GET /v1/audit` | `audit_read` | yes | |
| `GET /v1/audit/{request_id}` | `audit_read` | yes | 404 `audit entry '<id>' not found` |
| `POST /v1/rkm/queue` | `govern` | yes | 201 on accept |
| `GET /v1/rkm/queue` | `govern` | yes | |
| `GET /v1/rkm/queue/{proposal_id}` | `govern` | yes | |
| `POST /v1/rkm/queue/{proposal_id}/approve` | `govern` | yes | + `X-Nautilus-Reviewer` |
| `POST /v1/rkm/queue/{proposal_id}/reject` | `govern` | yes | + `X-Nautilus-Reviewer` + `reason` |
| `GET /v1/rules/{rule_name}/lineage` | `govern` | yes | |
| `POST /v1/rules/{rule_name}/retract` | `govern` | yes | + reviewer + `yes=true` |
| `POST /v1/rules/{rule_name}/rollback` | `govern` | yes | + reviewer + `to_version` |
| `POST /v1/keys/rotate` | `keys` | yes | |
| `POST /v1/keys/{kid}/revoke` | `keys` | yes | + reviewer + reason |
| `GET /v1/keys/jwks.json` | **none** | **no** | public by design — verifiers need it |
| `GET /healthz` | none | no | liveness |
| `GET /readyz` | none | no | readiness; 503 when the audit sink fails its probe |
| `GET /metrics` | **none** | **no** | Prometheus; see below |
| `GET /` | none | no | 302 to `/admin` when `ui.enabled`, else 200 + JSON route index |
| `GET /docs`, `/redoc`, `/openapi.json` | none | no | schema, not data |

Admin console routes exist **only** when `ui.enabled: true`: `/admin/login`
(GET, POST), `/admin/logout`, `/admin/playground` and `/admin/sources`
(`query`), `/admin/decisions`, `/admin/decisions/{request_id}`, `/admin/audit`,
`/admin/attestation`, `POST /admin/attestation/verify` (`audit_read`),
`POST /admin/api/query`, and the `/admin/static` mount.

### `GET /metrics` — unauthenticated, always

No capability, no auth, and it cannot be turned off from the config. It is
exempt from the concurrency limiter too, deliberately, so saturation does not
take a Pod out of rotation.

**Defends** your dashboards. **Costs** you disclosure: the series expose source
ids, agent ids, decision outcomes and request volumes — enough to profile what
your broker holds and who queries it.

**Fails with** nothing; there is no refusal to observe. The control is at the
proxy:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/metrics
200
$ curl -s -o /dev/null -w '%{http_code}\n' https://nautilus.example.com/metrics
403
```

The 403 is nginx's, from the block in
[the reverse-proxy configuration](#keep-the-private-surface-off-the-public-listener).

### `GET /v1/keys/jwks.json` — unauthenticated, by design

Verifiers need the public half to check a token they were handed. It exposes
only public key material (`kty`, `crv`, `kid`, `x`, `use`). Do not "fix" this by
authenticating it — you would break offline verification, which is the point of
the receipts.

## Transport: TLS, Nautilus does not do it

There is no TLS config key, so there is no entry above for one. Two supported
answers:

### Option A — run uvicorn yourself, with certificates

`nautilus serve` does not pass TLS options through, so terminate in uvicorn
directly against the same ASGI app.

```bash
# 1. A certificate. Use your CA in production; this is the local-test shape.
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout /etc/nautilus/tls/key.pem -out /etc/nautilus/tls/cert.pem \
  -subj "/CN=nautilus.example.com"
sudo chown nautilus:nautilus /etc/nautilus/tls/*.pem
sudo chmod 0400 /etc/nautilus/tls/key.pem

# 2. An app module uvicorn can import.
sudo tee /etc/nautilus/asgi.py >/dev/null <<'PY'
from nautilus.transport.fastapi_app import create_app

app = create_app(config_path="/etc/nautilus/nautilus.yaml")
PY

# 3. Start it. --ssl-keyfile / --ssl-certfile are uvicorn's, not Nautilus's.
PYTHONPATH=/etc/nautilus uvicorn asgi:app \
  --host 0.0.0.0 --port 8443 \
  --ssl-keyfile /etc/nautilus/tls/key.pem \
  --ssl-certfile /etc/nautilus/tls/cert.pem
```

Verify the credential is no longer in clear:

```console
$ curl -sv https://nautilus.example.com:8443/healthz 2>&1 | grep -i 'SSL connection'
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
```

### Option B — terminate in front, and tell Nautilus who did it

Keep `nautilus serve` on loopback and put nginx (or your mesh) in front. This is
also how you scope `/metrics` and `/admin`.

```nginx
# /etc/nginx/conf.d/nautilus.conf
server {
    listen 443 ssl;
    server_name nautilus.example.com;

    ssl_certificate     /etc/nginx/tls/nautilus.crt;
    ssl_certificate_key /etc/nginx/tls/nautilus.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # The data surface.
    location /v1/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # proxy_trust only: set it, never pass a client-supplied value through.
        proxy_set_header X-Forwarded-User $ssl_client_s_dn;
    }

    location = /healthz { proxy_pass http://127.0.0.1:8000; }
    location = /readyz  { proxy_pass http://127.0.0.1:8000; }

    # Scrapes come from the monitoring subnet and nowhere else.
    location = /metrics {
        allow 10.20.0.0/16;
        deny all;
        proxy_pass http://127.0.0.1:8000;
    }

    # The console, if you enable it at all.
    location /admin/ {
        allow 10.30.0.0/16;
        deny all;
        proxy_pass http://127.0.0.1:8000;
    }
}
```

```yaml
api:
  host: 127.0.0.1        # nginx is the only client
  port: 8000
  auth:
    mode: proxy_trust
    trusted_proxies: ["127.0.0.1/32"]
```

### TLS on the way out, to your sources

Outbound TLS is per-source and lives in `sources[].connection` and
`sources[].auth`. For Postgres, put the mode in the DSN:

```yaml
sources:
  - id: customers
    type: postgres
    connection: "${CUSTOMERS_DSN}"   # ...?sslmode=verify-full&sslrootcert=/etc/nautilus/keys/db-ca.pem
    table: customers
    classification: cui
    data_types: [pii]
```

For HTTP-based adapters, use `https://` in `connection` and
[`sources[].auth`](#sourcesauth) `type: mtls` with `ca_path` to pin a private CA.

## Keep the private surface off the public listener

Three surfaces share one port and one bind: the data API, `/metrics`, and — when
`ui.enabled` — the console. Nautilus offers no per-route listener, so separation
is the proxy's job. The nginx block in
[Option B](#option-b-terminate-in-front-and-tell-nautilus-who-did-it) is the
complete answer:

- `/v1/` — public to your agents, over TLS, authenticated by Nautilus;
- `/metrics` — monitoring subnet only, 403 to everyone else;
- `/admin/` — operator subnet only, and preferably not enabled at all;
- `/healthz`, `/readyz` — reachable by your orchestrator.

## Rotate and revoke

### The session-token signing ring

```console
$ export NAUTILUS_REVIEWER="alice@example.com"
$ nautilus key rotate --url https://nautilus.example.com --api-key "$NAUTILUS_KEY_KEYS" --yes
OK: rotated: new primary kid=3b1c7f42-0d2e-4a91-9c55-1f7a0b6d8e30  reviewer=alice@example.com
$ nautilus key list --url https://nautilus.example.com --api-key "$NAUTILUS_KEY_KEYS" --json
[{"kid": "3b1c7f42-...", "kty": "OKP", "use": "sig"}, {"kid": "ee0eb00e-...", "kty": "OKP", "use": "sig"}]
# Old tokens keep verifying until the old kid is revoked:
$ nautilus key revoke ee0eb00e-38ae-4060-90dc-a9aac8da460d \
    --url https://nautilus.example.com --api-key "$NAUTILUS_KEY_KEYS" \
    --reason "quarterly rotation" --yes
OK: revoked: kid=ee0eb00e-38ae-4060-90dc-a9aac8da460d  reason='quarterly rotation'  reviewer=alice@example.com
```

After revocation, tokens signed by the old `kid` fail with
`{"detail":"Invalid session token: unknown_kid"}`.

### The API keys

Two restarts, no outage:

```bash
# 1. Mint the replacement.
export NAUTILUS_KEY_REPORTING_NEW="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
# 2. Add it alongside the old one and restart — both are now valid.
#    api:
#      keys:
#        - {key: "${NAUTILUS_KEY_REPORTING}",     agent_id: reporting, capabilities: [query]}
#        - {key: "${NAUTILUS_KEY_REPORTING_NEW}", agent_id: reporting, capabilities: [query]}
sudo systemctl restart nautilus
# 3. Move callers to the new value, confirm the old one is unused in your logs.
# 4. Remove the old entry and restart again.
sudo systemctl restart nautilus
# 5. Confirm the old key is dead.
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://nautilus.example.com/v1/request \
  -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
  -d '{"agent_id":"reporting","intent":"list customers","context":{}}'
# expect: 401
```

### The attestation key

Rotating it means new receipts verify with a new public key and old ones still
need the old. Keep every retired public key for as long as you keep the logs it
signed, and if `audit.chained` is on, **start a new chain at a new `audit.path`**
— appending to an existing chain with a different key is refused, by design.

## A hardened configuration, end to end

```yaml
# /etc/nautilus/nautilus.yaml — hardened.
# Every secret is ${VAR}; values come from /etc/nautilus/nautilus.env (0600).

api:
  host: 127.0.0.1              # nginx terminates TLS and is the only client
  port: 8000
  max_request_bytes: 262144
  max_concurrent_requests: 64
  auth:
    mode: api_key
  keys:
    - key: "${NAUTILUS_KEY_REPORTING}"
      agent_id: reporting
      capabilities: [query]
    - key: "${NAUTILUS_KEY_ONCALL}"
      agent_id: incident-response
      capabilities: [query, audit_read]
    - key: "${NAUTILUS_KEY_GOVERN}"
      agent_id: platform
      capabilities: [govern, keys]

agents:
  reporting:
    id: reporting
    clearance: cui
    default_purpose: quarterly-reporting
    allowed_purposes: [quarterly-reporting, audit-response]
  incident-response:
    id: incident-response
    clearance: secret
    compartments: [phi]
    allowed_purposes: [incident-response]
  platform:
    id: platform
    clearance: cui
    allowed_purposes: [platform-operations]

sources:
  - id: customers
    type: postgres
    connection: "${CUSTOMERS_DSN}"    # ...?sslmode=verify-full&sslrootcert=/etc/nautilus/keys/db-ca.pem
    table: customers
    classification: cui
    data_types: [pii, contact]
    timeout_s: 5.0
    max_response_bytes: 1048576
  - id: patients
    type: postgres
    connection: "${PATIENTS_DSN}"
    table: patients
    classification: secret
    compartments: "phi"
    data_types: [phi, pii]
    allowed_purposes: [incident-response]
    timeout_s: 5.0

attestation:
  enabled: true
  private_key_path: /etc/nautilus/keys/attestation.pem
  sink:
    type: file
    path: /var/lib/nautilus/attestations.jsonl
    chained: true
    checkpoint_interval: 1000

audit:
  path: /var/lib/nautilus/audit.jsonl
  chained: true
  checkpoint_interval: 1000

session_tokens:
  enabled: true
  ttl_seconds: 900
  key_ring_path: /var/lib/nautilus/keyring/session-keys.json
  broker_instance_id: nautilus-prod-eu-west-1

session_store:
  backend: postgres
  dsn: "${SESSION_STORE_DSN}"
  on_failure: fail_closed          # a broker that cannot remember cannot enforce
  ttl_seconds: 3600
  purpose_ttl_seconds: 900
  lock_timeout_s: 10.0
  acquire_timeout_s: 5.0
  pool_min_size: 2
  pool_max_size: 10
  lock_pool_max_size: 32

rules:
  packs: [data-routing-nist]
  user_rules_dirs: [/etc/nautilus/rules]
  consistency_checks: true

rkm:
  sandbox:
    min_entries: 500

analysis:
  mode: pattern                    # no intent text leaves the host

mcp:
  expose_declare_handoff: false
  max_response_bytes: 262144

ui:
  enabled: false                   # second front door; cookie has no `secure` flag

state_dir: /var/lib/nautilus/state
```

### Lay down the filesystem

```bash
sudo useradd --system --home /var/lib/nautilus --shell /usr/sbin/nologin nautilus
sudo install -d -m 0750 -o nautilus -g nautilus /var/lib/nautilus
sudo install -d -m 0700 -o nautilus -g nautilus /var/lib/nautilus/keyring
sudo install -d -m 0750 -o nautilus -g nautilus /var/lib/nautilus/state
sudo install -d -m 0750 -o root     -g nautilus /etc/nautilus
sudo install -d -m 0700 -o nautilus -g nautilus /etc/nautilus/keys
sudo install -d -m 0750 -o nautilus -g nautilus /etc/nautilus/rules
sudo chmod 0640 /etc/nautilus/nautilus.yaml
sudo chmod 0600 /etc/nautilus/nautilus.env
```

### Validate before you ship

Loading the config is the validation; there is no separate `validate`
subcommand, and every check on this page runs here.

```console
$ python -c "from nautilus.config.loader import load_config; load_config('/etc/nautilus/nautilus.yaml'); print('OK')"
OK
```

Run it with the same environment the service will have, or every `${VAR}` will
fail:

```bash
sudo -u nautilus env $(sudo cat /etc/nautilus/nautilus.env | xargs) \
  python -c "from nautilus.config.loader import load_config; load_config('/etc/nautilus/nautilus.yaml'); print('OK')"
```

### Start it

```ini
# /etc/systemd/system/nautilus.service
[Unit]
Description=Nautilus broker
After=network-online.target

[Service]
User=nautilus
Group=nautilus
# Secrets arrive by file, not by command line: EnvironmentFile is 0600 and
# never appears in `ps`.
EnvironmentFile=/etc/nautilus/nautilus.env
ExecStart=/usr/local/bin/nautilus serve \
  --config /etc/nautilus/nautilus.yaml \
  --bind 127.0.0.1:8000 \
  --log-format json
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/nautilus
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nautilus
sudo systemctl status nautilus
```

### Confirm the gate is closed

Run this after every config change. Each line asserts one control from this page.

```bash
#!/usr/bin/env bash
# verify-hardening.sh — every check is a control documented above.
set -u
BASE="${BASE:-https://nautilus.example.com}"
KEY="${NAUTILUS_KEY_REPORTING:?export the reporting key first}"
fail=0
chk() { # chk <label> <expected> <actual>
  if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected $2, got $3"; fail=1; fi
}
code() { curl -sk -o /dev/null -w '%{http_code}' "$@"; }

chk "no credential -> 401" 401 \
  "$(code -X POST "$BASE/v1/request" -H 'Content-Type: application/json' \
       -d '{"agent_id":"reporting","intent":"x","context":{}}')"
chk "wrong credential -> 401" 401 \
  "$(code -X POST "$BASE/v1/request" -H 'X-API-Key: wrong' -H 'Content-Type: application/json' \
       -d '{"agent_id":"reporting","intent":"x","context":{}}')"
chk "bound key cannot ask as another agent -> 403" 403 \
  "$(code -X POST "$BASE/v1/request" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
       -d '{"agent_id":"incident-response","intent":"x","context":{}}')"
chk "query key cannot read the audit log -> 403" 403 \
  "$(code "$BASE/v1/audit" -H "X-API-Key: $KEY")"
chk "query key cannot rotate signing keys -> 403" 403 \
  "$(code -X POST "$BASE/v1/keys/rotate" -H "X-API-Key: $KEY" \
       -H 'X-Nautilus-Reviewer: verify' -H 'Content-Type: application/json' -d '{"reviewer":"verify"}')"
chk "console is off -> 404" 404 "$(code "$BASE/admin")"
chk "metrics blocked at the proxy -> 403" 403 "$(code "$BASE/metrics")"
chk "readiness is green -> 200" 200 "$(code "$BASE/readyz")"
chk "oversized body -> 413" 413 \
  "$(code -X POST "$BASE/v1/request" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
       --data-binary "@<(head -c 2000000 /dev/zero | tr '\0' 'x')" 2>/dev/null || echo 413)"
chk "invalid session token -> 401" 401 \
  "$(code -X POST "$BASE/v1/request" -H "X-API-Key: $KEY" \
       -H 'X-Nautilus-Session-Token: abc.def.ghi' -H 'Content-Type: application/json' \
       -d '{"agent_id":"reporting","intent":"x","context":{}}')"

echo "--- startup lines that must NOT be present:"
journalctl -u nautilus --since "-1h" \
  | grep -E "is a bare string|api\.keys is empty|--air-gapped (overrides|refuses|drops)|auto-generated attestation key" \
  && fail=1 || echo "ok   none found"

exit "$fail"
```

## Failure index

Every string below is emitted verbatim by Nautilus. Search your logs for the
left column.

| Exact string | Cause | Do this |
|---|---|---|
| `ERROR: invalid config: Config validation failed:` | any Pydantic failure; the next line names the key | fix the named key; exit code is 2 |
| `Extra inputs are not permitted [type=extra_forbidden]` | a typo'd or unknown config key | the location prefix is the typo; correct the spelling |
| `Missing env var 'X' referenced by source id='...'` | a `${X}` with no value in the environment | export `X` or add it to the `EnvironmentFile` |
| `api.auth.mode 'proxy_trust' requires api.auth.trusted_proxies.` | `proxy_trust` with no peer restriction | add the ingress CIDR to `api.auth.trusted_proxies` |
| `api.auth.trusted_proxies entry '...' is not an address or CIDR block` | malformed CIDR | fix the block; `10.42.0.0/16` shape |
| `api.keys entry declares unknown capabilities [...]` | a capability outside `query, audit_read, govern, keys` | use one of the four |
| `session_store.backend: redis has no implementation.` | `backend: redis` | use `postgres` (shared) or `sqlite` (single node) |
| `rkm.auto_promote.enabled: auto-promotion is not implemented.` | `auto_promote.enabled: true` | remove the key or set it `false` |
| `classification labels are not levels of the 'classification' hierarchy (...)` | a `classification` or `clearance` outside the loaded hierarchy | use a listed level, or install the pack that defines yours |
| `Duplicate source id='...'` | two sources share an id | rename one |
| `Unsupported source type='...' for id='...' (supported: [...])` | unknown adapter type | use a listed type or declare an `adapters:` entry |
| `Source id='...' is missing the required key 'type' (one of: [...])` | no `type` on a source | add it |
| `source '...' has type '...' but no 'connection'.` | a dialling adapter with no target | set `connection` |
| `audit.chained requires attestation.enabled with a signing key` | chaining with attestation off | enable attestation and set `private_key_path` |
| `audit.chained cannot append to the existing chain at ... with an auto-generated signing key` | chaining an existing log with no stable key | set `private_key_path` to the original key, or start a new `audit.path` |
| `audit.chained is on with an auto-generated attestation key` (WARN) | chaining with an ephemeral key | set `private_key_path` before the next restart |
| `api.keys is empty, so every data and governance route will answer 401` (WARN) | no keys configured | add a scoped key entry |
| `api.keys[0] is a bare string: bound to no agent_id` (WARN) | root-equivalent key | convert to `{key, agent_id, capabilities}` |
| `WARN: --air-gapped overrides analysis.mode from '...' to 'pattern' (NFR-1)` | config disagrees with the air-gap flag | reconcile the config to `pattern` |
| `WARN: --air-gapped refuses analysis.provider (type='...'); dropping it (NFR-1)` | provider configured on an air-gapped broker | remove the provider block |
| `WARN: --air-gapped drops LLM source id='...' — connection host is not loopback (NFR-1, #43)` | remote LLM source on an air-gapped broker | move the model on-host or drop the source |
| `PostgresSessionStore unavailable (dsn=...): ...` | store unreachable | fix the DSN/network; `fail_closed` exits 1 |
| `... and sqlite fallback at ... failed: ...` | both the store and its fallback failed | make `sqlite_path` writable |
| `session database carries schema version N; this build understands version M.` | mixed-version rollout against one store | finish or roll back the rollout; do not run both builds |
| `{"detail":"Not authenticated"}` (401) | no `X-API-Key` header | send the header |
| `{"detail":"Invalid API key"}` (401) | key matched nothing, or `api.keys` is empty | check the key and the allow-list |
| `{"detail":"Forwarded identity rejected: peer is not a trusted proxy"}` (401) | peer outside `trusted_proxies` | add the CIDR, or route through the proxy |
| `{"detail":"Missing X-Forwarded-User"}` (401) | trusted peer, no header | make the proxy set it |
| `{"detail":"This credential is bound to agent_id='X', so it cannot ask as 'Y'"}` (403) | body disagrees with `api.keys[].agent_id` | use the right key, or fix the body |
| `{"detail":"This credential does not hold the 'X' capability (it holds [...])"}` (403) | missing capability | grant it in `api.keys[].capabilities`, or use another key |
| `{"detail":"Invalid session token: bad_signature"}` (401) | tampered or foreign token | re-mint; check `key_ring_path` |
| `{"detail":"Invalid session token: expired"}` (401) | past `session_tokens.ttl_seconds` | re-mint, or raise the TTL |
| `{"detail":"Invalid session token: unknown_kid"}` (401) | replicas do not share a key ring, or the kid was revoked | share `key_ring_path`; re-mint after a revoke |
| `{"detail":"Invalid session token: wrong_broker"}` (401) | token minted by a different `broker_instance_id` | align the id across the deployment's replicas |
| `{"detail": "Request body is N bytes; this broker accepts at most M (api.max_request_bytes)."}` (413) | oversized body | shrink it, or raise the key |
| `{"detail": "Broker busy: N requests are already in flight (api.max_concurrent_requests). Retry."}` (503) | saturation | honour `Retry-After`; raise the limit or add replicas |
| `{"detail":"X-Nautilus-Reviewer header required"}` (400) | governance write with no reviewer | send the header |
| `{"detail":"reason is required for rejection"}` (400) | reject with no reason | supply `reason` |
| `{"detail":"yes=true required for destructive operation"}` (412) | retract/rollback without confirmation | send `yes: true` |
| `{"detail":{"error":"already_decided","current_status":"..."}}` (409) | proposal already approved or rejected | read `current_status`; no action needed |
| `{"detail":{"error":"promotion_failed",...,"recovery":"fix the rule and re-approve to retry the promotion, or reject the proposal"}}` (422) | approved rule did not compile, or `rules.user_rules_dirs` is unset | fix the rule or set `user_rules_dirs`, then re-approve |
| `{"detail":"audit entry '...' not found"}` (404) | unknown `request_id` | check the id |
| `{"detail":"Adapter '...' does not support schema introspection"}` (501) | adapter has no schema surface | not an error; nothing to do |
| `{"detail":"Broker not ready"}` (503) | request arrived before lifespan finished | wait for `/readyz` |
| `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.` | governance CLI with no reviewer | `export NAUTILUS_REVIEWER=you@example.com` |
| `ERROR: ... already exists — refusing to overwrite it` | `nautilus init` over an existing config | choose another `--dir` |
| `Unknown agent id='...'` | request names an agent absent from `agents:` | register the agent |

## What this does not give you

Named so you do not assume otherwise:

- **No TLS.** There is no `api.tls` key and `nautilus serve` passes no TLS
  options. Terminate it yourself.
- **No rate limiting.** `api.max_concurrent_requests` bounds *concurrency*, not
  rate. A single caller can issue unlimited sequential requests.
- **No per-key rate or quota.** The exposure ledger accumulates by caller, but
  the ceiling is a policy rule you write, not a config key.
- **No secret manager integration.** `${VAR}` reads the process environment.
  Vault, KMS and CSI drivers all work — as long as they land the value in the
  environment before the broker starts.
- **No key expiry for API keys.** `api.keys` entries never expire; rotation is
  the two-restart procedure above.
- **No `secure` flag on the console cookie.** `ui.enabled: true` without TLS
  puts an API key on the wire in clear.
- **No config hot-reload.** Every key on this page is read at startup. Changing
  one means a restart.
- **No authentication on `/metrics` or `/v1/keys/jwks.json`.** Both are
  deliberate; scope `/metrics` at the proxy and leave JWKS public.

## See also

- [Operator Guide](operator-guide.md) — day-two operation.
- [Configure attestation](configure-attestation.md) — the signing path in depth.
- [Verify a token](verify-a-token.md) — checking a receipt offline.
- [REST API reference](../reference/rest-api.md) — every route and schema.
- [CLI reference](../reference/cli.md) — every subcommand and flag.
- [Errors reference](../reference/errors/index.md) — error codes and meanings.
- [The Trust Boundary](../concepts/trust-boundary.md) — why the broker holds the
  credentials.
