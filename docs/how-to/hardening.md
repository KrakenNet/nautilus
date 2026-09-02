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

Three sections are deliberately **not** key entries, because the questions they
answer belong to no single key:
[Sessions](#sessions-lifetime-parallelism-and-termination) — how many a
credential may hold, what ends them, how to see them;
[What the deployment discloses without being asked](#what-the-deployment-discloses-without-being-asked)
— what a scanner gets from a stock install; and
[Four controls Nautilus does not implement](#four-controls-nautilus-does-not-implement)
— four things a security questionnaire will ask for that have no key, because
the software does not do them. All three carry their own runnable config and
their own transcripts.

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
keys. **Every leaf key has its own entry below**, including the 18 query-shape
keys that decide which rows an adapter fetches rather than who may fetch them:
a bound on what a source returns is a bound on what leaves the broker, and a
key documented only as a table row is a key nobody can reason about.

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

The **`SIGHUP`** column in every index below says whether a running broker can
adopt that key without a restart, because the two are different security
properties. **`live`** means the value can change under a serving process, so
the posture it sets is only as durable as write access to the config file and
the ability to signal the process — but also that tightening it costs no
downtime. **`restart`** means the value is captured in an object built at
startup (a sink holding an exclusive `flock`, an already-minting key ring, an
ASGI middleware, a bound socket), so it cannot drift under a running process at
all, and a file that changes one is refused whole rather than half-applied. The
per-key reasons are in
[Which keys reload, and which need a restart](operator-guide.md#which-keys-reload-and-which-need-a-restart).

### Index — `api`

| Key | Type | Default | `SIGHUP` | Documented in |
|---|---|---|---|---|
| `api.host` | `str` | `"127.0.0.1"` | restart | [`api.host`](#apihost) |
| `api.port` | `int` | `8000` | restart | [`api.port`](#apiport) |
| `api.keys` | `list[str \| ApiKeyEntry]` | `[]` | live | [`api.keys`](#apikeys) |
| `api.keys[].key` | `str` | required | live | [`api.keys[].key`](#apikeyskey) |
| `api.keys[].agent_id` | `str \| None` | `None` | live | [`api.keys[].agent_id`](#apikeysagent_id) |
| `api.keys[].principal` | `str \| None` | `None` | live | [`api.keys[].principal`](#apikeysprincipal) |
| `api.keys[].capabilities` | `list[str]` | `["query"]` | live | [`api.keys[].capabilities`](#apikeyscapabilities) |
| `api.auth.mode` | `"api_key" \| "proxy_trust"` | `"api_key"` | restart | [`api.auth.mode`](#apiauthmode) |
| `api.auth.trusted_proxies` | `list[str]` | `[]` | restart | [`api.auth.trusted_proxies`](#apiauthtrusted_proxies) |
| `api.max_request_bytes` | `int \| None` | `1048576` | restart | [`api.max_request_bytes`](#apimax_request_bytes) |
| `api.max_concurrent_requests` | `int \| None` | `64` | restart | [`api.max_concurrent_requests`](#apimax_concurrent_requests) |

### Index — `agents`

| Key | Type | Default | `SIGHUP` | Documented in |
|---|---|---|---|---|
| `agents.<id>.id` | `str` | required | restart | [`agents.<id>.id`](#agentsidid) |
| `agents.<id>.clearance` | `str` | required | restart | [`agents.<id>.clearance`](#agentsidclearance) |
| `agents.<id>.compartments` | `list[str]` | `[]` | restart | [`agents.<id>.compartments`](#agentsidcompartments) |
| `agents.<id>.subject` | `str \| None` | `None` | restart | [`agents.<id>.subject`](#agentsidsubject) |
| `agents.<id>.default_purpose` | `str \| None` | `None` | restart | [`agents.<id>.default_purpose`](#agentsiddefault_purpose) |
| `agents.<id>.allowed_purposes` | `list[str]` | `[]` | restart | [`agents.<id>.allowed_purposes`](#agentsidallowed_purposes) |

### Index — `sources`

| Key | Type | Default | `SIGHUP` | Documented in |
|---|---|---|---|---|
| `sources[].id` | `str`, `^[A-Za-z0-9][A-Za-z0-9._-]*$` | required | live | [`sources[].id`](#sourcesid) |
| `sources[].type` | `str` | required | live | [`sources[].type`](#sourcestype) |
| `sources[].classification` | `str` | required | live | [`sources[].classification`](#sourcesclassification) |
| `sources[].compartments` | `str` | `""` | live | [`sources[].compartments`](#sourcescompartments) |
| `sources[].data_types` | `list[str]` | required | live | [`sources[].data_types`](#sourcesdata_types) |
| `sources[].allowed_purposes` | `list[str] \| None` | `None` | live | [`sources[].allowed_purposes`](#sourcesallowed_purposes) |
| `sources[].purpose_field` | `str` | `""` | live | [`sources[].purpose_field`](#sourcespurpose_field) |
| `sources[].connection` | `str` | `""` | live | [`sources[].connection`](#sourcesconnection) |
| `sources[].auth.type` | `"bearer" \| "basic" \| "mtls" \| "none"` | discriminator | live | [`sources[].auth.type`](#sourcesauthtype) |
| `sources[].auth.token` | `str` | required for `bearer` | live | [`sources[].auth.token`](#sourcesauthtoken) |
| `sources[].auth.username` | `str` | required for `basic` | live | [`sources[].auth.username`](#sourcesauthusername-sourcesauthpassword) |
| `sources[].auth.password` | `str` | required for `basic` | live | [`sources[].auth.password`](#sourcesauthusername-sourcesauthpassword) |
| `sources[].auth.cert_path` | `str` | required for `mtls` | live | [`sources[].auth.cert_path`](#sourcesauthcert_path-sourcesauthkey_path-sourcesauthca_path) |
| `sources[].auth.key_path` | `str` | required for `mtls` | live | [`sources[].auth.key_path`](#sourcesauthcert_path-sourcesauthkey_path-sourcesauthca_path) |
| `sources[].auth.ca_path` | `str \| None` | `None` | live | [`sources[].auth.ca_path`](#sourcesauthcert_path-sourcesauthkey_path-sourcesauthca_path) |
| `sources[].timeout_s` | `float \| None` | `15.0` | live | [`sources[].timeout_s`](#sourcestimeout_s) |
| `sources[].max_response_bytes` | `int \| None` | `8388608` | live | [`sources[].max_response_bytes`](#sourcesmax_response_bytes) |
| `sources[].description` | `str` | `""` | live | [`sources[].description`](#sourcesdescription) |
| `sources[].label` | `str \| None` | `None` | live | [`sources[].label`](#sourceslabel) |
| `sources[].sub_category` | `str` | `""` | live | [`sources[].sub_category`](#sourcessub_category) |
| `sources[].table` | `str \| None` | `None` | live | [`sources[].table`](#sourcestable) |
| `sources[].index` | `str \| None` | `None` | live | [`sources[].index`](#sourcesindex) |
| `sources[].model` | `str \| None` | `None` | live | [`sources[].model`](#sourcesmodel) |
| `sources[].rows` | `list[dict[str, Any]]` | `[]` | live | [`sources[].rows`](#sourcesrows) |
| `sources[].top_k` | `int` | `10` | live | [`sources[].top_k`](#sourcestop_k) |
| `sources[].embedder` | `"default" \| None` | `None` | live | [`sources[].embedder`](#sourcesembedder) |
| `sources[].embedding_column` | `str \| None` | `None` | live | [`sources[].embedding_column`](#sourcesembedding_column) |
| `sources[].metadata_column` | `str \| None` | `None` | live | [`sources[].metadata_column`](#sourcesmetadata_column) |
| `sources[].distance_operator` | `"<=>" \| "<->" \| "<#>" \| None` | `"<=>"` | live | [`sources[].distance_operator`](#sourcesdistance_operator) |
| `sources[].like_style` | `"starts_with" \| "regex"` | `"starts_with"` | live | [`sources[].like_style`](#sourceslike_style) |
| `sources[].endpoints[].path` | `str` | required | live | [`sources[].endpoints[].path`](#sourcesendpointspath) |
| `sources[].endpoints[].method` | `"GET" \| "POST" \| "PUT" \| "PATCH" \| "DELETE"` | `"GET"` | live | [`sources[].endpoints[].method`](#sourcesendpointsmethod) |
| `sources[].endpoints[].path_params` | `list[str]` | `[]` | live | [`sources[].endpoints[].path_params`](#sourcesendpointspath_params) |
| `sources[].endpoints[].query_params` | `list[str]` | `[]` | live | [`sources[].endpoints[].query_params`](#sourcesendpointsquery_params) |
| `sources[].endpoints[].operator_templates` | `dict[str, str]` | `{}` | live | [`sources[].endpoints[].operator_templates`](#sourcesendpointsoperator_templates) |

### Index — `attestation` and `audit`

| Key | Type | Default | `SIGHUP` | Documented in |
|---|---|---|---|---|
| `attestation.enabled` | `bool` | `true` | restart | [`attestation.enabled`](#attestationenabled) |
| `attestation.private_key_path` | `str \| None` | `None` | restart | [`attestation.private_key_path`](#attestationprivate_key_path) |
| `attestation.sink.type` | `"null" \| "file" \| "http"` | `"null"` | restart | [`attestation.sink.type`](#attestationsinktype) |
| `attestation.sink.path` | `str` | required for `file` | restart | [`attestation.sink.path`](#attestationsinkpath) |
| `attestation.sink.chained` | `bool` | `false` | restart | [`attestation.sink.chained`](#attestationsinkchained) |
| `attestation.sink.checkpoint_interval` | `int` | `0` | restart | [`attestation.sink.checkpoint_interval`](#attestationsinkcheckpoint_interval) |
| `attestation.sink.url` | `str` | required for `http` | restart | [`attestation.sink.url`](#attestationsinkurl) |
| `attestation.sink.dead_letter_path` | `str \| None` | `None` | restart | [`attestation.sink.dead_letter_path`](#attestationsinkdead_letter_path) |
| `attestation.sink.retry_policy.max_retries` | `int` | `3` | restart | [`attestation.sink.retry_policy`](#attestationsinkretry_policy) |
| `attestation.sink.retry_policy.initial_backoff_s` | `float` | `0.1` | restart | [`attestation.sink.retry_policy`](#attestationsinkretry_policy) |
| `attestation.sink.retry_policy.max_backoff_s` | `float` | `5.0` | restart | [`attestation.sink.retry_policy`](#attestationsinkretry_policy) |
| `audit.path` | `str` | `"./audit.jsonl"` | restart | [`audit.path`](#auditpath) |
| `audit.chained` | `bool` | `false` | restart | [`audit.chained`](#auditchained) |
| `audit.checkpoint_interval` | `int` | `0` | restart | [`audit.checkpoint_interval`](#auditcheckpoint_interval) |

### Index — sessions

| Key | Type | Default | `SIGHUP` | Documented in |
|---|---|---|---|---|
| `session_tokens.enabled` | `bool` | `false` | restart | [`session_tokens.enabled`](#session_tokensenabled) |
| `session_tokens.ttl_seconds` | `int` | `3600` | restart | [`session_tokens.ttl_seconds`](#session_tokensttl_seconds) |
| `session_tokens.key_ring_path` | `str \| None` | `None` | restart | [`session_tokens.key_ring_path`](#session_tokenskey_ring_path) |
| `session_tokens.broker_instance_id` | `str \| None` | `None` | restart | [`session_tokens.broker_instance_id`](#session_tokensbroker_instance_id) |
| `session_store.backend` | `"memory" \| "postgres" \| "sqlite"` | `"memory"` | restart | [`session_store.backend`](#session_storebackend) |
| `session_store.dsn` | `str \| None` | `None` | restart | [`session_store.dsn`](#session_storedsn) |
| `session_store.on_failure` | `"fail_closed" \| "fallback_memory" \| "fallback_sqlite"` | `"fail_closed"` | restart | [`session_store.on_failure`](#session_storeon_failure) |
| `session_store.sqlite_path` | `str` | `"./.nautilus/sessions.db"` | restart | [`session_store.sqlite_path`](#session_storesqlite_path) |
| `session_store.ttl_seconds` | `int` | `3600` | restart | [`session_store.ttl_seconds`](#session_storettl_seconds) |
| `session_store.purpose_ttl_seconds` | `int` | `0` | live | [`session_store.purpose_ttl_seconds`](#session_storepurpose_ttl_seconds) |
| `session_store.lock_timeout_s` | `float \| None` | `30.0` | live | [`session_store.lock_timeout_s`](#session_storelock_timeout_s) |
| `session_store.acquire_timeout_s` | `float` | `10.0` | restart | [`session_store.acquire_timeout_s`](#session_storeacquire_timeout_s) |
| `session_store.pool_min_size` | `int` | `1` | restart | [`session_store` pool sizes](#session_storepool_min_size-pool_max_size-lock_pool_max_size) |
| `session_store.pool_max_size` | `int` | `10` | restart | [`session_store` pool sizes](#session_storepool_min_size-pool_max_size-lock_pool_max_size) |
| `session_store.lock_pool_max_size` | `int` | `32` | restart | [`session_store` pool sizes](#session_storepool_min_size-pool_max_size-lock_pool_max_size) |

The two `ttl_seconds` above measure different clocks and must be ordered against
each other; that, the absent session limit, and the absent termination endpoint
are in [Sessions](#sessions-lifetime-parallelism-and-termination).

### Index — governance, transports and analysis

| Key | Type | Default | `SIGHUP` | Documented in |
|---|---|---|---|---|
| `rules.user_rules_dirs` | `list[str]` | `[]` | live | [`rules.user_rules_dirs`](#rulesuser_rules_dirs) |
| `rules.packs` | `list[str]` | `[]` | live | [`rules.packs`](#rulespacks) |
| `rules.consistency_checks` | `bool` | `true` | live | [`rules.consistency_checks`](#rulesconsistency_checks) |
| `rkm.auto_promote.enabled` | `bool` | `false` | restart | [`rkm.auto_promote.enabled`](#rkmauto_promoteenabled) |
| `rkm.sandbox.min_entries` | `int` | `100` | restart | [`rkm.sandbox.min_entries`](#rkmsandboxmin_entries) |
| `ui.enabled` | `bool` | `false` | restart | [`ui.enabled`](#uienabled) |
| `mcp.expose_declare_handoff` | `bool` | `false` | restart | [`mcp.expose_declare_handoff`](#mcpexpose_declare_handoff) |
| `mcp.max_response_bytes` | `int \| None` | `262144` | restart | [`mcp.max_response_bytes`](#mcpmax_response_bytes) |
| `analysis.mode` | `"pattern" \| "llm-first" \| "llm-only"` | `"pattern"` | restart | [`analysis.mode`](#analysismode) |
| `analysis.timeout_s` | `float` | `2.0` | restart | [`analysis.timeout_s`](#analysistimeout_s) |
| `analysis.keyword_map` | `dict[str, list[str]]` | `{}` | restart | [`analysis.keyword_map`](#analysiskeyword_map) |
| `analysis.provider.type` | `"anthropic" \| "openai" \| "local"` | discriminator | restart | [`analysis.provider.type`](#analysisprovidertype) |
| `analysis.provider.api_key_env` | `str` (`str \| None` for `local`) | required / `None` | restart | [`analysis.provider.api_key_env`](#analysisproviderapi_key_env) |
| `analysis.provider.base_url` | `str` | required for `local` | restart | [`analysis.provider.base_url`](#analysisproviderbase_url) |
| `analysis.provider.model` | `str` | `"claude-sonnet-4-5"` / `"gpt-4o-mini"` / required | restart | [`analysis.provider.model`](#analysisprovidermodel) |
| `analysis.provider.timeout_s` | `float` | `2.0` | restart | [`analysis.provider.timeout_s`](#analysisprovidertimeout_s) |
| `adapters[].module_path` | `str` | required | restart | [`adapters[]`](#adaptersmodule_path-class-source_type) |
| `adapters[].class` | `str` | required | restart | [`adapters[]`](#adaptersmodule_path-class-source_type) |
| `adapters[].source_type` | `str` | required | restart | [`adapters[]`](#adaptersmodule_path-class-source_type) |
| `state_dir` | `str \| None` | `None` | restart | [`state_dir`](#state_dir) |

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

The list is the one part of `api` a running broker adopts on `SIGHUP` — the
guard resolves it per request, so a rotation takes effect on the next one. What
that costs the exposure ledger is [`api.keys[].principal`](#apikeysprincipal);
the runbook is [The API keys](#the-api-keys).

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

**Costs** you one environment variable per caller. Adding or removing one is a
`SIGHUP`, not a restart: the guard resolves `app.state.api_keys` per request,
and an adopted reload replaces it. Changing this value is what "rotating a
credential" means, and by itself it also changes who the broker thinks is
asking — see [`api.keys[].principal`](#apikeysprincipal).

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

### `api.keys[].principal`

`str | None` · default `None` · read in `nautilus/transport/auth.py:caller_identity`

**Defends** the cumulative-exposure ledger across a rotation. Exposure —
`sources_visited`, `data_types_seen`, `pii_sources_accessed_list` — accumulates
under an internal `principal:<hash>` derived from the caller's authenticated
identity, and a session belongs to the principal that opened it. With no
`principal` set, that identity *is* the secret in
[`api.keys[].key`](#apikeyskey): replace the secret and the same caller is a
different principal, so it resumes on an empty escalation budget and its own
live sessions answer `403 session_not_yours`. Naming a principal makes the
identity the thing that did not change. Rotating `key` under a fixed
`principal` carries the ledger and the sessions across the rotation.

Two entries may share one `principal` — that is what makes a rotation overlap
window work: old and new credential, one caller, one ledger, both accepted
until you drop the old entry.

It is not a second `agent_id`. `agent_id` says which agent the credential may
ask as and is enforced against the request body; `principal` says which
*caller* the broker is accumulating against and is never seen by the caller at
all. Two keys bound to the same agent are still two callers unless they also
share a `principal`.

**Costs** you a name in the config, and a decision you have to make before your
first rotation rather than during it: an entry that names no principal keeps
the old derivation, so its ledger does not survive a key change and never will.
Nothing migrates an existing ledger onto a newly-added `principal` — the ledger
keyed by the old secret stays where it is and ages out under
[`session_store.ttl_seconds`](#session_storettl_seconds); the credential starts
accumulating under the new key from the next request. Add `principal` when the
ledger is cold if that matters to you.

**Fails with**, when it is present and empty:

```
Config validation failed:
  api.keys.0.function-after[_known_capabilities(), ApiKeyEntry].principal: String should have at least 1 character [type=string_too_short]
```

Any reload that leaves a ledger with no surviving entry to accumulate under is
called out by position, because clearing an exposure budget is not something a
routine operation should do quietly. That covers rotating a key that named no
principal — and equally adding a principal to an entry that had none, which is
step 0 of [the procedure](#the-api-keys):

```text
WARNING:nautilus.core.broker:Reload left 1 credential(s) with no surviving api.keys[].principal to accumulate under: api.keys[0] (principal=None, agent_id='reporting'). Their cumulative exposure (sources_visited, data_types_seen, pii_sources_accessed_list) does NOT carry -- each caller resumes on an empty escalation budget, and requests naming a session it opened are refused session_not_yours. Rotate the key value under a stable api.keys[].principal to keep the ledger; nothing migrates one onto a principal added later.
```

**Example**

```yaml
api:
  keys:
    - key: "${NAUTILUS_KEY_REPORTING}"      # rotate this value
      principal: reporting-service          # not this one
      agent_id: reporting
      capabilities: [query]
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

Neither mode is more than one factor. If your control set requires two, the
factors have to live in an ingress under `proxy_trust`, and Nautilus cannot tell
whether they did — see
[V6.3.3](#v633-multi-factor-authentication) and
[V6.8.1](#v681-restricting-which-identity-provider-may-assert-an-identity).

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

`str` · required · unique across the file · `^[A-Za-z0-9][A-Za-z0-9._-]*$`

**Defends** the integrity of every rule and every audit record: rules select by
`source_id`, denial records name it, and the exposure ledger records visits
under it — `sources_visited` is a list of these ids. (What the ledger is
*keyed* by is the caller, not the source; see
[`api.keys[].principal`](#apikeysprincipal).) Two sources with one id would
silently merge policy.

The pattern defends the places the id is *reproduced*. It is interpolated into
application log lines, it becomes the OpenTelemetry span name `adapter.<id>`,
and it is the `{name}` segment of `GET /v1/adapters/{name}/schema`. Bounding it
here bounds all three, and everything added later, instead of each consumer
having to escape it — see
[Log injection](#log-injection-what-the-two-log-formats-escape).

**Costs** you the exotic id. Letters, digits, `.`, `_` and `-`, starting with a
letter or a digit. Every id in every shipped example already conforms; a config
that does not will refuse to start rather than load and misbehave later.

**Fails with** a refusal to start:

```
ERROR: invalid config: Duplicate source id='customers'
```

when the key is absent, `Each source entry must have a string 'id'`, and when
the value is outside the pattern:

```
ERROR: invalid config: Config validation failed:
  sources.0.id: String should match pattern '^[A-Za-z0-9][A-Za-z0-9._-]*$' [type=string_pattern_mismatch]
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

### `sources[].description`

`str` · default `""`

**Defends** nothing — this field is *disclosed*, and that is the only reason it
belongs in a hardening guide. The string is returned verbatim by
`GET /v1/sources` and by the MCP `list_sources` tool — both gated on the
`query` capability, but only the REST route filters by clearance
(`Broker.sources_visible_to`); the MCP tool iterates `broker.sources` and shows
every source to any caller holding the capability. `Broker._source_info` copies
the same string into the `source_info` block of every decision receipt. Write
it as if every agent that can reach an MCP session will read it, because it
can.

**Costs** you nothing to set and a disclosure to set badly: a hostname, a
schema name or an internal ticket reference here reaches callers who are
allowed to see that the source exists and nothing more.

**Fails with** no error at any layer — it is free text and always validates.
The leak is silent, so check it rather than waiting for it:

```console
$ curl -s http://127.0.0.1:8000/v1/sources -H "X-API-Key: $NAUTILUS_KEY_REPORTING"
{"sources":[{"id":"customers","type":"postgres","description":"Billing contacts, EU region","classification":"cui","data_types":["pii"],"allowed_purposes":[]}]}
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
    description: "Billing contacts, EU region"   # visible to every caller who may list it
```

### `sources[].label`

`str | None` · default `None` · required for `type: neo4j`

**Defends** the one identifier the Neo4j adapter interpolates into Cypher.
Every scope *value* is bound as a `$pN` parameter; the node label is not, so
`Neo4jAdapter.connect` runs it through `_validate_label` against
`^[A-Z][A-Za-z0-9_]*$` and backticks it before it reaches
`MATCH (n:Person)`, with the label backticked. Validation runs before the
driver is built, so a malformed label never opens a connection.

**Costs** you one node label per source: the adapter matches exactly this
label, so a second label means a second source block with its own
classification.

**Fails with**, when the field is missing entirely, a startup error:

```console
$ nautilus serve --config nautilus.yaml
ERROR: invalid config: Config validation failed:
  sources.0: Value error, source 'graph' has type 'neo4j' but no 'label'. The neo4j adapter requires it, so every request to this source would fail at runtime. [type=value_error]
$ echo $?
2
```

and, when it is present but malformed, a `ScopeEnforcementError` at connect
that lands in `sources_errored`:
`Invalid Neo4j label 'person-node': must match ^[A-Z][A-Za-z0-9_]*$`.

**Example**

```yaml
sources:
  - id: graph
    type: neo4j
    connection: "${GRAPH_URI}"
    label: Person
    classification: cui
    data_types: [pii]
```

### `sources[].sub_category`

`str` · default `""`

**Defends** nothing today, and the reason matters if you are writing policy.
No module under `nautilus/` reads `SourceConfig.sub_category`. The `source`
rule template in `nautilus/rules/templates/nautilus.yaml` does declare a
`sub_category` slot, but `FathomRouter` asserts a source fact built from `id`,
`type`, `classification`, `data_types`, `allowed_purposes`, `compartments` and
`purpose_field` only — so a rule branching on `?src-sub` always sees the
template default `""`, whatever the YAML says.

**Costs** you a false sense of segmentation. Use
[`sources[].compartments`](#sourcescompartments) for isolation that the engine
actually enforces.

**Fails with** no error — it validates, it is stored on the model, and it
changes no decision. Nothing prints it, so the check is the negative one:

```console
$ curl -s http://127.0.0.1:8000/v1/sources -H "X-API-Key: $NAUTILUS_KEY_REPORTING"
{"sources":[{"id":"customers","type":"postgres","description":"Billing contacts, EU region","classification":"cui","data_types":["pii"],"allowed_purposes":[]}]}
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
    compartments: "billing"      # enforced
    sub_category: billing        # documentation only
```

### `sources[].table`

`str | None` · default `None` · required for `type: postgres`, `pgvector` and `servicenow`

**Defends** which table the query actually reads. The Postgres and pgvector
adapters render it through `quote_table` (`nautilus/adapters/base.py`), which
splits on `.`, passes each segment through `quote_identifier` → `validate_field`
(`^[A-Za-z_][A-Za-z0-9_]*$` per segment) and re-joins them quoted: a source
declaring `table: restricted.customers` emits
`SELECT * FROM "restricted"."customers"`, not a bare `"customers"` that
`search_path` could resolve to a different table. More than one qualifier is
refused. ServiceNow validates its own table name against `^[a-z][a-z0-9_]*$` at
connect, before the HTTP client exists.

**Costs** you one table per source block, which is the point: the
classification, data types and compartments attached to the source are only
true of one table.

**Fails with**, when the adapter's type requires it and it is absent:

```console
$ nautilus serve --config nautilus.yaml
ERROR: invalid config: Config validation failed:
  sources.0: Value error, source 'customers' has type 'postgres' but no 'table'. The postgres adapter requires it, so every request to this source would fail at runtime. [type=value_error]
$ echo $?
2
```

and, for a ServiceNow table that does not match the regex, a
`ScopeEnforcementError` at connect:
`ServiceNowAdapter source 'incidents' has invalid table 'Incident' (expected regex '^[a-z][a-z0-9_]*$')`.

**Example**

```yaml
sources:
  - id: customers
    type: postgres
    connection: "${CUSTOMERS_DSN}"
    table: restricted.customers   # schema-qualified; both segments are quoted
    classification: cui
    data_types: [pii]
```

### `sources[].index`

`str | None` · default `None` · required for `type: elasticsearch`

**Defends** the index the search is issued against. `_validate_index` checks it
against `^[a-z0-9][a-z0-9._-]*$` at connect, before the
`AsyncElasticsearch` client is constructed, so a name carrying a wildcard or a
comma — either of which would widen one source into many indices — is refused
rather than sent.

**Costs** you one index per source; alias or wildcard fan-out has to be
declared as separate source blocks with their own classifications.

**Fails with**, when absent:

```console
$ nautilus serve --config nautilus.yaml
ERROR: invalid config: Config validation failed:
  sources.0: Value error, source 'logs' has type 'elasticsearch' but no 'index'. The elasticsearch adapter requires it, so every request to this source would fail at runtime. [type=value_error]
$ echo $?
2
```

and, when malformed, a `ScopeEnforcementError` in `sources_errored`:
`Invalid Elasticsearch index 'Logs-2024': must match ^[a-z0-9][a-z0-9._-]*$`.

**Example**

```yaml
sources:
  - id: logs
    type: elasticsearch
    connection: "${ES_URL}"
    index: app-logs-2026
    classification: cui
    data_types: [pii]
```

### `sources[].model`

`str | None` · default `None` · required for `type: llm`

**Defends** the choice of model the prompt reaches. `LLMAdapter.connect`
refuses an empty value and then sends this exact string as the `"model"` field
of every request body to the OpenAI-compatible endpoint at
[`sources[].connection`](#sourcesconnection) — so the source's classification
and data types are a statement about *this* model at *that* endpoint, and
changing either is a config change with a restart, not a runtime negotiation.

**Costs** you a restart to move a source to another model, and it does not
bound what the model does with the rows: everything sent is out of the trust
boundary. Classify the source accordingly.

**Fails with**, when absent:

```console
$ nautilus serve --config nautilus.yaml
ERROR: invalid config: Config validation failed:
  sources.0: Value error, source 'summariser' has type 'llm' but no 'model'. The llm adapter requires it, so every request to this source would fail at runtime. [type=value_error]
$ echo $?
2
```

**Example**

```yaml
sources:
  - id: summariser
    type: llm
    connection: "${LLM_BASE_URL}"    # OpenAI-compatible /v1 endpoint
    model: llama-3.1-8b-instruct
    classification: public
    data_types: [derived]
```

### `sources[].rows`

`list[dict[str, Any]]` · default `[]` · required for `type: static`

**Defends** nothing on its own — it *is* the data. A `static` source has no
connection and no credential: `StaticAdapter.connect` copies these rows into
the process and `execute` filters the copy by the scope the engine produced.
Everything you put here inherits the file permissions of `nautilus.yaml`, not a
database's access control, and it is read by anyone who can read the config,
including whatever backs it up.

**Costs** you memory proportional to the rows and a restart to change one. Keep
it to fixtures, lookup tables and reference data; anything you would have put
behind a grant belongs in a real source.

**Fails with**, when a `static` source declares none:

```console
$ nautilus serve --config nautilus.yaml
ERROR: invalid config: Config validation failed:
  sources.0: Value error, source 'regions' has type 'static' but no 'rows'. The static adapter requires it, so every request to this source would fail at runtime. [type=value_error]
$ echo $?
2
```

**Example**

```yaml
sources:
  - id: regions
    type: static
    classification: public
    data_types: [reference]
    rows:
      - { code: eu, name: "Europe" }
      - { code: na, name: "North America" }
```

### `sources[].top_k`

`int` · default `10`

**Defends** the size of a similarity answer: `PgVectorAdapter._build_vector_sql`
binds it as the `LIMIT $L` parameter of the `ORDER BY … LIMIT` tail, so it caps
how many neighbours one request can pull out of the index. It is a row bound,
not a byte bound — [`sources[].max_response_bytes`](#sourcesmax_response_bytes)
is the one that bounds memory.

**Costs** you recall: too low and a legitimate question misses the row that
answers it, with no signal that it did.

**Fails with** no config-time error for a nonsensical value — the field carries
no bound, so `top_k: -5` validates and is passed straight through to the
`LIMIT` parameter. If you want a ceiling, it has to be a review of the config,
not a startup check.

**Example**

```yaml
sources:
  - id: docs
    type: pgvector
    connection: "${DOCS_DSN}"
    table: doc_chunks
    classification: cui
    data_types: [pii]
    top_k: 5
```

### `sources[].embedder`

`"default" | None` · default `None`

**Defends** against a silent misconfiguration rather than an attacker. `default`
is the only accepted value: there is no embedder registry, so any other name
used to load cleanly and then fail every request with
`EmbeddingUnavailableError` at query time. The `Literal` moves that to startup.
Setting `default` and leaving it unset behave identically today — `Broker`
constructs the pgvector adapter with `broker_default_embedder` only and passes
no per-source embedder.

**Costs** you nothing, and buys you nothing either: with the shipped
`NoopEmbedder(strict=True)`, a pgvector request that carries no
`context["embedding"]` fails with
`NoopEmbedder(strict=True) cannot produce embeddings. …` whichever way this key
is set.

**Fails with**, for any other value:

```console
$ nautilus serve --config nautilus.yaml
ERROR: invalid config: Config validation failed:
  sources.0.embedder: Input should be 'default' [type=literal_error]
$ echo $?
2
```

**Example**

```yaml
sources:
  - id: docs
    type: pgvector
    connection: "${DOCS_DSN}"
    table: doc_chunks
    classification: cui
    data_types: [pii]
    embedder: default
```

### `sources[].embedding_column`

`str | None` · default `None` (the adapter then uses `embedding`)

**Defends** the identifier spliced into the `SELECT` list and the
`ORDER BY <col> <op> $E` tail of the pgvector query. It is not a bound
parameter, so `PgVectorAdapter.execute` routes it through `quote_identifier`,
which calls `validate_field` first: anything outside
`^[A-Za-z_][A-Za-z0-9_]*$` (a leading digit, an embedded quote) is rejected
before the SQL is built.

**Costs** you nothing beyond naming the column correctly; leave it unset and
the adapter reads `embedding`.

**Fails with** no config-time error — the value is a free string until the
adapter uses it — and then a `ScopeEnforcementError` in `sources_errored`
naming the identifier: `Invalid field identifier '1bad'`.

**Example**

```yaml
sources:
  - id: docs
    type: pgvector
    connection: "${DOCS_DSN}"
    table: doc_chunks
    classification: cui
    data_types: [pii]
    embedding_column: chunk_vector
```

### `sources[].metadata_column`

`str | None` · default `None` (the adapter then uses `metadata`)

**Defends** the second interpolated identifier in the same query: pgvector
selects `id`, this column and the embedding column, so this is the column whose
contents are returned to the agent as the row payload. Point it at a column
that carries more than you classified the source for and the classification is
no longer true of what comes back. Same guard as the embedding column —
`quote_identifier` → `validate_field` before the SQL exists.

**Costs** you nothing to set; unset it reads `metadata`.

**Fails with** no config-time error and then, at query time, a
`ScopeEnforcementError` in `sources_errored`: `Invalid field identifier '1bad'`.

**Example**

```yaml
sources:
  - id: docs
    type: pgvector
    connection: "${DOCS_DSN}"
    table: doc_chunks
    classification: cui
    data_types: [pii]
    metadata_column: chunk_meta
```

### `sources[].distance_operator`

`"<=>" | "<->" | "<#>" | None` · default `"<=>"` (`None` also resolves to `"<=>"`)

**Defends** the one operator that reaches SQL as a literal rather than a
parameter, which is why it is guarded twice: the `Literal` on `SourceConfig`
rejects anything else at startup, and `PgVectorAdapter._build_vector_sql`
re-checks against `_ALLOWED_DISTANCE_OPERATORS` before interpolating, so a
hand-constructed config cannot smuggle one past the loader.

**Costs** you a correctness choice, not a security one, once it is inside the
allowlist: `<=>` is cosine distance, `<->` L2, `<#>` negative inner product, and
the wrong one returns confidently ranked nonsense.

**Fails with**, at startup:

```console
$ nautilus serve --config nautilus.yaml
ERROR: invalid config: Config validation failed:
  sources.0.distance_operator: Input should be '<=>', '<->' or '<#>' [type=literal_error]
$ echo $?
2
```

and, from the adapter's second check, an `AdapterError`:
`distance_operator '<%>' not in allowlist: ['<#>', '<->', '<=>']`.

**Example**

```yaml
sources:
  - id: docs
    type: pgvector
    connection: "${DOCS_DSN}"
    table: doc_chunks
    classification: cui
    data_types: [pii]
    distance_operator: "<=>"
```

### `sources[].like_style`

`"starts_with" | "regex"` · default `"starts_with"` · Neo4j only

**Defends** against ReDoS on a graph source. It decides how the Neo4j adapter
renders a scope constraint whose operator is `LIKE`: the default emits
`n.prop STARTS WITH $pN`, which is bounded; `regex` emits
`n.prop =~ $pN`, whose evaluation is not. The value still arrives as a
bound parameter either way — the exposure is the cost of matching it, not
injection.

**Costs** you prefix-only matching. Turning on `regex` buys expressiveness and
hands anything that can influence a scope value an unbounded matcher on the
database's CPU.

**Fails with** no failure when you opt in — it succeeds, loudly. `connect()`
logs at WARN:

```
CONFIG WARN: Neo4j source 'graph' uses like_style='regex'; regex evaluation is unbounded and may enable ReDoS. Prefer 'starts_with' unless explicitly required (AC-10.3).
```

An unrecognised value is a startup error:

```console
$ nautilus serve --config nautilus.yaml
ERROR: invalid config: Config validation failed:
  sources.0.like_style: Input should be 'starts_with' or 'regex' [type=literal_error]
$ echo $?
2
```

**Example**

```yaml
sources:
  - id: graph
    type: neo4j
    connection: "${GRAPH_URI}"
    label: Person
    classification: cui
    data_types: [pii]
    like_style: starts_with
```

### `sources[].endpoints[].path`

`str` · required within an `endpoints` entry (the `endpoints` list itself is optional)

**Defends** the URL the REST adapter is allowed to call. `RestAdapter.connect`
takes `config.endpoints[0]` as the single call target and `execute` issues the
request against exactly this path relative to
[`sources[].connection`](#sourcesconnection); nothing derived from an intent or
a scope value contributes to it. Omit `endpoints` entirely and the adapter
falls back to the base URL with an empty path — which is a wider target, not a
narrower one.

**Costs** you one endpoint per source: entries after the first are validated and
never called.

**Fails with**, when an entry omits it:

```console
$ nautilus serve --config nautilus.yaml
ERROR: invalid config: Config validation failed:
  sources.0.endpoints.0.path: Field required [type=missing]
$ echo $?
2
```

and, when the list is present but empty, a `ScopeEnforcementError` at connect:
`RestAdapter source 'tickets' declares endpoints=[] (must list at least one EndpointSpec or omit the field)`.

**Example**

```yaml
sources:
  - id: tickets
    type: rest
    connection: "${TICKETS_BASE_URL}"
    classification: cui
    data_types: [pii]
    endpoints:
      - path: /api/v1/tickets
```

### `sources[].endpoints[].method`

`"GET" | "POST" | "PUT" | "PATCH" | "DELETE"` · default `"GET"`

**Defends** the verb the adapter may use. `execute` passes this string to
`httpx.AsyncClient.stream(method, path, …)` and nothing else can change it, so
a source that should only read stays read-only by declaration. The default is
`GET`; the `Literal` means a typo is a startup failure rather than a fallback.

**Costs** you nothing for read sources. Anything other than `GET` makes the
source a write path with the broker's credential behind it — the scope
constraints the engine produced are sent as query parameters, not as a body, so
a non-`GET` verb here changes state without carrying the policy's filter.

**Fails with**, for an unlisted verb:

```console
$ nautilus serve --config nautilus.yaml
ERROR: invalid config: Config validation failed:
  sources.0.endpoints.0.method: Input should be 'GET', 'POST', 'PUT', 'PATCH' or 'DELETE' [type=literal_error]
$ echo $?
2
```

**Example**

```yaml
sources:
  - id: tickets
    type: rest
    connection: "${TICKETS_BASE_URL}"
    classification: cui
    data_types: [pii]
    endpoints:
      - path: /api/v1/tickets
        method: GET
```

### `sources[].endpoints[].path_params`

`list[str]` · default `[]`

**Defends** nothing, and you should know that before you rely on it. The field
is declared on `EndpointSpec`, validated as a list of strings and stored — and
no module under `nautilus/` reads it. `RestAdapter.execute` sends
[`path`](#sourcesendpointspath) as written; there is no path templating, so
declaring names here neither permits nor forbids anything.

**Costs** you a wrong assumption if you treat it as an allowlist. The real
constraint on what reaches the source is the scope the engine produced plus
[`operator_templates`](#sourcesendpointsoperator_templates).

**Fails with** no error in either direction: a declared name is not required to
appear, and an undeclared one is not rejected, because nothing consumes the
list.

**Example**

```yaml
sources:
  - id: tickets
    type: rest
    connection: "${TICKETS_BASE_URL}"
    classification: cui
    data_types: [pii]
    endpoints:
      - path: /api/v1/tickets
        path_params: []          # inert; documented so it is not mistaken for a guard
```

### `sources[].endpoints[].query_params`

`list[str]` · default `[]`

**Defends** nothing, for the same reason as `path_params`: declared, validated,
stored, and read by no module under `nautilus/`. The query string the REST
adapter sends is built entirely by `_build_params` from the scope constraints
the engine produced — every key comes from a `ScopeConstraint.field` that has
passed `validate_field`, and this list neither adds to that set nor restricts
it.

**Costs** you the same wrong assumption. If you need a parameter to be sent,
it has to come from a rule that puts it in scope.

**Fails with** no error in either direction; nothing consumes the list.

**Example**

```yaml
sources:
  - id: tickets
    type: rest
    connection: "${TICKETS_BASE_URL}"
    classification: cui
    data_types: [pii]
    endpoints:
      - path: /api/v1/tickets
        query_params: []         # inert; the scope decides the query string
```

### `sources[].endpoints[].operator_templates`

`dict[str, str]` · default `{}`

**Defends** the one operator the REST adapter refuses by default. Its *keys* are
an opt-in allowlist marker, checked at `connect()` against the adapter's
`_OPERATOR_ALLOWLIST` so a typo fails at startup rather than at query time. The
only key that changes behaviour is `NOT IN`: without it, a scope constraint
using that operator is refused, because there is no safe default rendering for a
negated set in a query string. The *values* are deliberately never consumed —
the encoder builds every parameter from its own builders, so no string from YAML
is interpolated into a request.

**Costs** you a widened source when you declare `NOT IN`: the constraint is
emitted as a repeated `{field}__nin` key and enforcement moves to the upstream
service, which is outside the trust boundary. Leave it empty unless the upstream
is known to honour it.

**Fails with**, for a key outside the allowlist, a `ScopeEnforcementError` at
connect:
`EndpointSpec.operator_templates declares unknown operator 'REGEX' for source 'tickets'`,

and, when a rule produces `NOT IN` without the declaration, a
`ScopeEnforcementError` in `sources_errored`:
`Operator 'NOT IN' is not supported by the REST adapter unless explicitly declared in EndpointSpec.operator_templates (AC-9.3).`

**Example**

```yaml
sources:
  - id: tickets
    type: rest
    connection: "${TICKETS_BASE_URL}"
    classification: cui
    data_types: [pii]
    endpoints:
      - path: /api/v1/tickets
        operator_templates:
          "NOT IN": "{field}__nin"   # presence opts in; the string is not consumed
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

The reason code is one of `missing`, `bad_signature`, `expired`, `unknown_kid`
and `broker_instance_mismatch` (`nautilus/attestation/session_token.py`), plus
`agent_mismatch` from the broker (`nautilus/core/broker.py`) when a valid token
is presented by an agent it was not minted for. The first five are refused in the
transport dependency and read `Invalid session token: <code>`; `agent_mismatch`
is refused inside the broker and reads
`Invalid session token (<code>): <message>`. `unknown_kid` across a fleet means
your replicas do not share `key_ring_path`.

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
set. There is no `curl` in the runtime image, so the fetch and the parse are the
same interpreter; two replicas started with the same `key_ring_path`:

```console
$ for c in nautilus-a nautilus-b; do
    docker exec "$c" python -c 'import json,urllib.request; print(sorted(k["kid"] for k in json.load(urllib.request.urlopen("http://127.0.0.1:8000/v1/keys/jwks.json"))["keys"]))'
  done
['834e7ee1-b86d-4d6d-b34a-1c3e4372a640']
['834e7ee1-b86d-4d6d-b34a-1c3e4372a640']
```

Identical lists is the assertion; a replica with its own ring prints a `kid`
none of the others have. On Kubernetes the loop is
`for pod in $(kubectl get pods -l app=nautilus -o name)` with
`kubectl exec "$pod" --` in place of `docker exec "$c"` — the argv after it does
not change. Why it cannot be `curl`, and what else the distroless image does and
does not let you run, is in
`deploy/README.md` §11, *Working inside a distroless container*.

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

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    -H "X-Nautilus-Session-Token: <A_TOKEN_MINTED_BY_THE_OTHER_DEPLOYMENT>" \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}'
{"detail":"Invalid session token: broker_instance_mismatch"}
```

`<A_TOKEN_MINTED_BY_THE_OTHER_DEPLOYMENT>` is a compact JWS from a broker with a
different `broker_instance_id` and the same ring; the two-broker version of this
check is in
[Ending one session](#ending-one-session-and-ending-every-session-after-a-credential-change).

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
it as `${VAR}`. Errors from the store never print the DSN
(`PostgresSessionStore._sanitized_dsn`): they print the `scheme://host[:port]`
that `redact_connection` copies out of it, so a connection failure cannot leak
the password into your logs.

**Costs** you an environment variable and a restart to change it.

**Fails with**, when the store is unreachable and `on_failure: fail_closed`,
a startup failure and a non-zero exit — the `dsn=` in the message is the host
alone, without the database name, the path or any query parameter:

```
PostgresSessionStore unavailable (dsn=postgresql://db.internal:5432): [Errno 111] Connection refused
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
nautilus.core.session_pg.SessionStoreUnavailableError: PostgresSessionStore unavailable (dsn=postgresql://db.internal:5432): [Errno 111] Connection refused
ERROR:    Application startup failed. Exiting.
$ echo $?
1
```

Under `fallback_sqlite`, a failure of *both* still raises:

```
PostgresSessionStore unavailable (dsn=postgresql://db.internal:5432: [Errno 111] Connection refused) and sqlite fallback at ./.nautilus/sessions.db failed: unable to open database file
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
PostgresSessionStore unavailable (dsn=postgresql://db.internal:5432: [Errno 111] Connection refused) and sqlite fallback at /var/lib/nautilus/sessions.db failed: unable to open database file
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

## Sessions: lifetime, parallelism and termination

Every entry above documents one key. A *session* is the one thing on this page
that several keys decide jointly, and the joint answer is not what any of them
says on its own. This section answers, with the transcript for each: how many
sessions one credential may hold, what ends one, what ends all of them at once,
how to see the ones that are open, and what changes when an identity provider —
not Nautilus — authenticated the caller.

Every block below runs against this config, which needs no database:

```yaml
# /tmp/session-lab.yaml — a broker that needs no database, for the checks below.
api:
  host: 127.0.0.1
  port: 8000
  keys:
    - key: "${NAUTILUS_KEY_REPORTING}"
      agent_id: reporting
      capabilities: [query, audit_read, keys]
    - key: "${NAUTILUS_KEY_ONCALL}"
      agent_id: incident-response
      capabilities: [query]
agents:
  reporting:
    id: reporting
    clearance: unclassified
    default_purpose: quarterly-reporting
    allowed_purposes: [quarterly-reporting, audit-response]
  incident-response:
    id: incident-response
    clearance: unclassified
    default_purpose: incident-response
    allowed_purposes: [incident-response]
sources:
  - id: customers
    type: static
    classification: unclassified
    data_types: [contact]
    allowed_purposes: [quarterly-reporting, incident-response]
    rows:
      - {customer_id: 1, email: "a@example.com"}
  - id: tickets
    type: static
    classification: unclassified
    data_types: [tickets]
    allowed_purposes: [quarterly-reporting, incident-response]
    rows:
      - {ticket_id: 9, status: open}
audit:
  path: /tmp/session-lab/audit.jsonl
attestation:
  enabled: false
session_tokens:
  enabled: true
  ttl_seconds: 900
  key_ring_path: /tmp/session-lab/session-keys.json
  broker_instance_id: nautilus-prod-eu-west-1
session_store:
  backend: sqlite
  sqlite_path: /tmp/session-lab/sessions.db
  ttl_seconds: 3600
ui:
  enabled: true
analysis:
  mode: pattern
  keyword_map:
    contact: [customer, customers, contact]
    tickets: [ticket, tickets]
state_dir: /tmp/session-lab/state
```

```bash
export NAUTILUS_KEY_REPORTING=$(python -c 'import secrets; print(secrets.token_hex(32))')
export NAUTILUS_KEY_ONCALL=$(python -c 'import secrets; print(secrets.token_hex(32))')
mkdir -p /tmp/session-lab
nautilus serve --config /tmp/session-lab.yaml &
```

Two things in the outputs below will differ on your machine and nothing else
will: the epoch seconds in `issued_at` / `expires_at`, and the
`principal:<digest>` — that digest is a truncated SHA-256 over the agent id and
the credential the transport authenticated, so it is a function of the keys you
just generated.

### How many sessions one credential may hold at once

**Nothing limits it.** There is no `max_sessions` key, no per-agent session
counter, and no code path that refuses to mint because an earlier session for
the same agent is still valid. Two mints seconds apart both succeed and both
stay valid for the full `session_tokens.ttl_seconds`:

```console
$ for s in sess-c sess-d; do
    curl -s -X POST http://127.0.0.1:8000/v1/sessions \
      -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
      -d "{\"session_id\":\"$s\",\"agent_id\":\"reporting\",\"purpose\":\"quarterly-reporting\"}" \
    | python -c 'import json, sys; d = json.load(sys.stdin); print(d["session_id"], d["issued_at"], d["expires_at"])'
  done
sess-c 1788259326 1788260226
sess-d 1788259326 1788260226
```

**What is bounded is the exposure, not the count**, and that is the reason the
missing limit is not the hole it looks like. Cumulative exposure accumulates
twice: once under the declared `session_id`, and once under a
`principal:<sha256-prefix>` key derived in `nautilus/core/principal.py` from the
`agent_id` plus the credential the transport authenticated (the API key, or
`X-Forwarded-User` under `proxy_trust`). Neither input is settable from the
request body, so opening a second session does not open a second budget. Two
sessions, one credential, one source each:

```console
$ curl -s -o /dev/null -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{"session_id":"sess-a"}}'
$ curl -s -o /dev/null -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list tickets","context":{"session_id":"sess-b"}}'
$ python - <<'PY'
import json, sqlite3
db = sqlite3.connect("/tmp/session-lab/sessions.db")
for sid, state in db.execute(
    "SELECT session_id, state FROM nautilus_session_state ORDER BY session_id"
):
    print(sid, "->", json.loads(state)["sources_visited"])
PY
principal:be1035fc289982777f312b24dc279964 -> ['customers', 'tickets']
sess-a -> ['customers']
sess-b -> ['tickets']
```

The union is what the rules see. `sess-b` had visited nothing of its own when it
ran, and the `session` fact it was judged against already carried `customers`,
which only `sess-a` had touched:

```console
$ curl -s "http://127.0.0.1:8000/v1/audit?limit=200" -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
  | python -c 'import json, sys
for e in json.load(sys.stdin)["entries"]:
    if e["session_id"] == "sess-b" and e["event_type"] == "request":
        for f in e["input_facts"]:
            if f["template"] == "session":
                print(json.dumps(f["slots"], indent=2))
        break'
{
  "id": "sess-b",
  "pii_sources_accessed": 0,
  "purpose_start_ts": 0.0,
  "purpose_ttl_seconds": 0.0,
  "data_types_seen": "contact",
  "sources_visited": "customers",
  "pii_sources_accessed_list": ""
}
```

So a caller that wants a clean escalation ledger cannot get one by opening a new
session. It gets one by presenting a **different credential**, which is why one
key per caller ([`api.keys[].key`](#apikeyskey)) is the control that actually
bounds this, and why a shared key is a shared budget.

### A session id is not a credential

A `session_id` is a string the caller picks, so the first principal to touch one
owns it and no other principal may write to it. A second agent naming an open
session id is refused with HTTP 403 before any source is queried:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_ONCALL" -H 'Content-Type: application/json' \
    -d '{"agent_id":"incident-response","intent":"list tickets","context":{"session_id":"sess-a"}}'
{"detail":"session_not_yours: session 'sess-a' belongs to another principal. A session id is not a credential — either use your own, or have its owner declare a handoff to agent_id='incident-response' in it first."}
```

Presenting the *token* instead of the id is refused too, with a different code —
a signed token names the agent it was minted for, and verifying the signature is
not the same as being that agent:

```console
$ TOKEN=$(curl -s -X POST http://127.0.0.1:8000/v1/sessions \
      -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
      -d '{"session_id":"sess-a","agent_id":"reporting","purpose":"quarterly-reporting"}' \
    | python -c 'import json, sys; print(json.load(sys.stdin)["token"])')
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_ONCALL" \
    -H "X-Nautilus-Session-Token: $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"incident-response","intent":"list tickets","context":{}}'
{"detail":"Invalid session token (agent_mismatch): session token was minted for agent 'reporting', presented by 'incident-response'"}
```

The supported way a session spans two agents is a declared handoff, which writes
the joining agent into the session's own `handoff_agents` list; see
[`mcp.expose_declare_handoff`](#mcpexpose_declare_handoff).

### The two clocks, and the order they must be in

Two keys carry `ttl_seconds` and they measure different things. Getting the
relationship wrong is silent.

| Key | Clock | Starts at | Reset by activity | What it ends |
|---|---|---|---|---|
| [`session_tokens.ttl_seconds`](#session_tokensttl_seconds) | **absolute** | the mint | no | the credential — the token stops verifying |
| [`session_store.ttl_seconds`](#session_storettl_seconds) | **idle** | the last write | yes | the ledger — accumulated exposure is dropped |

**There is no inactivity timeout on the credential.** A session token issued to
an agent that then goes quiet for the whole TTL is still accepted on its last
second. The only bound is `expires_at`, written at mint time from
`session_tokens.ttl_seconds`, and the only way to shorten it is to lower that key
and restart — it is read once at startup like every other key on this page.

`session_store.ttl_seconds` *is* an idle timeout, but on the exposure ledger, not
on the token: each backend restricts reads to rows whose `updated_at` is inside
the window (`AND updated_at > datetime('now', '-N seconds')` for sqlite,
`AND updated_at > now() - interval 'N seconds'` for Postgres) and deletes the
rest on the next write. **The consequence is worth spelling out: a session idle
for longer than `session_store.ttl_seconds` keeps a valid token and gets a fresh
exposure budget.** Set `session_store.ttl_seconds: 5` in `/tmp/session-lab.yaml`
and restart — neither key is re-read while the broker runs — leaving the token's
own `ttl_seconds: 900` alone:

```console
$ T=$(curl -s -X POST http://127.0.0.1:8000/v1/request \
      -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
      -d '{"agent_id":"reporting","intent":"list customers","context":{"session_id":"idle-1"}}' \
    | python -c 'import json, sys; print(json.load(sys.stdin)["session_token"])')
$ curl -s -o /dev/null -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H "X-Nautilus-Session-Token: $T" \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list tickets","context":{}}'
$ python - <<'PY'
import json, sqlite3
db = sqlite3.connect("/tmp/session-lab/sessions.db")
for sid, state in db.execute(
    "SELECT session_id, state FROM nautilus_session_state WHERE session_id = 'idle-1'"
):
    print(sid, "->", json.loads(state)["sources_visited"])
PY
idle-1 -> ['customers', 'tickets']
$ sleep 8
$ curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H "X-Nautilus-Session-Token: $T" \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list tickets","context":{}}'
HTTP 200
```

The same token, still accepted, and the ledger it accumulates into has been
emptied:

```console
$ python - <<'PY'
import json, sqlite3
db = sqlite3.connect("/tmp/session-lab/sessions.db")
for sid, state in db.execute(
    "SELECT session_id, state FROM nautilus_session_state WHERE session_id = 'idle-1'"
):
    print(sid, "->", json.loads(state)["sources_visited"])
PY
idle-1 -> ['tickets']
```

**Set `session_store.ttl_seconds` greater than or equal to
`session_tokens.ttl_seconds`.** Anything else hands a paused agent an escalation
reset that no rule can see, because by the time the rules run the history is
already gone. The shipped defaults (`3600` and `3600`) satisfy this; the
[hardened configuration](#a-hardened-configuration-end-to-end) below uses
`ttl_seconds: 900` for the token against `3600` for the store, which also does.

### A new token is minted per session, not per authentication

Nautilus has no login step on the data path — an API key is a static bearer
credential presented on every request — so "regenerate the session identifier at
authentication" has no event to hang on. What happens instead, exactly:

**A request carrying no token mints a fresh session.** Two authenticated requests
with no `session_id` and no token get two unrelated sessions, never a shared or
predictable one:

```console
$ for i in 1 2; do
    curl -s -X POST http://127.0.0.1:8000/v1/request -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
      -H 'Content-Type: application/json' -d '{"agent_id":"reporting","intent":"list customers","context":{}}' \
    | python -c 'import base64, json, sys
claims = sys.stdin.read()
payload = json.loads(claims)["session_token"].split(".")[1]
print(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["session_id"])'
  done
fd3defc9-4085-4d14-b04d-88dfdce17afe
88d71187-b56d-4cab-b27c-ed963fe35871
```

**A request carrying a token keeps that session**, and the token's `session_id`
claim overrides any `session_id` in the body. That is the whole point of the
token: exposure cannot be reset by declaring a new id.

**The broker re-signs a token in place** when the signing key has rotated under
it, or when the request's purpose or clearance no longer matches what the token
asserts. The re-signed token carries the **original** `expires_at`, so neither a
key rotation nor a purpose change extends a session's life. Take the
`session_token` from each response; it is the one that will still verify after
the next rotation.

**The console does not issue a session identifier at all.** `POST /admin/login`
verifies the submitted key against `api.keys` and then sets the cookie *to that
key*. There is nothing new minted, so there is nothing to regenerate:

```console
$ curl -s -D - -o /dev/null -X POST http://127.0.0.1:8000/admin/login \
    -d "api_key=$NAUTILUS_KEY_REPORTING" \
  | grep -iE '^(HTTP/|location:|set-cookie:)' \
  | sed "s/$NAUTILUS_KEY_REPORTING/<the key you typed>/"
HTTP/1.1 302 Found
location: /admin/sources
set-cookie: nautilus_key=<the key you typed>; HttpOnly; Max-Age=86400; Path=/; SameSite=lax
```

Log in again over TLS and the value is identical; only the `Secure` attribute
changes, and it is conditioned on the scheme (see
[`Cookie: nautilus_key`](#cookie-nautilus_key)):

```console
$ curl -s -D - -o /dev/null -X POST http://127.0.0.1:8000/admin/login \
    -H 'X-Forwarded-Proto: https' -d "api_key=$NAUTILUS_KEY_REPORTING" \
  | grep -i '^set-cookie:' | sed "s/$NAUTILUS_KEY_REPORTING/<the key you typed>/"
set-cookie: nautilus_key=<the key you typed>; HttpOnly; Max-Age=86400; Path=/; SameSite=lax; Secure
```

So the remedy for a console session you believe is compromised is **not** a
logout; it is [rotating the API key](#the-api-keys). `GET /admin/logout` clears
the browser's copy and nothing else — the key it held is still live:

```console
$ curl -s -D - -o /dev/null http://127.0.0.1:8000/admin/logout \
  | grep -iE '^(HTTP/|location:|set-cookie:)'
HTTP/1.1 302 Found
location: /admin/login
set-cookie: nautilus_key=""; expires=Tue, 01 Sep 2026 10:50:02 GMT; Max-Age=0; Path=/; SameSite=lax
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/v1/sources \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING"
200
```

### Ending one session, and ending every session after a credential change

There is **no session-termination endpoint**. Nothing in the REST surface, the
CLI or the console deletes a session or invalidates one token. A session token
stops being accepted in exactly four ways, and only the bottom two are things an
operator can make happen:

| What ends it | Scope | Refusal the caller then sees |
|---|---|---|
| `expires_at` passes | that token | `{"detail":"Invalid session token: expired"}` (401) |
| the token is presented to a broker with a different `broker_instance_id` | that deployment boundary | `{"detail":"Invalid session token: broker_instance_mismatch"}` (401) |
| `nautilus key revoke <kid>` | **every** token that kid signed | `{"detail":"Invalid session token: unknown_kid"}` (401) |
| the key ring is lost or replaced (unset `key_ring_path`, restart) | every token the process ever signed | `{"detail":"Invalid session token: unknown_kid"}` (401) |

The third row is the one to use after a credential change, and it is the closest
thing to "terminate all other sessions". Rotate first — the current primary
cannot be revoked, because revoking it would make the ring silently mint an
unaudited replacement:

```console
$ export NAUTILUS_REVIEWER=ops@example.com
$ nautilus key list --url http://127.0.0.1:8000 --api-key "$NAUTILUS_KEY_REPORTING"
  fb240484-af2b-416a-8d5d-92f8a2a0c5b4  kty=OKP  use=sig
$ nautilus key rotate --yes --url http://127.0.0.1:8000 --api-key "$NAUTILUS_KEY_REPORTING"
OK: rotated: new primary kid=fef88529-c16b-4f61-883c-63494a032030  reviewer=ops@example.com
$ nautilus key revoke fef88529-c16b-4f61-883c-63494a032030 --reason "x" --yes \
    --url http://127.0.0.1:8000 --api-key "$NAUTILUS_KEY_REPORTING"
ERROR: key revoke: server returned 409: {"detail":"kid 'fef88529-c16b-4f61-883c-63494a032030' is the current primary; rotate first, then revoke"}
$ nautilus key revoke fb240484-af2b-416a-8d5d-92f8a2a0c5b4 --reason "credential change" --yes \
    --url http://127.0.0.1:8000 --api-key "$NAUTILUS_KEY_REPORTING"
OK: revoked: kid=fb240484-af2b-416a-8d5d-92f8a2a0c5b4  reason='credential change'  reviewer=ops@example.com
$ curl -s -X POST http://127.0.0.1:8000/v1/request -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    -H "X-Nautilus-Session-Token: $TOKEN" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}'
{"detail":"Invalid session token: unknown_kid"}
```

**Rotate and revoke back to back, or the sweep is incomplete.** Between the two
commands the rotated-out key is in its grace window: it still verifies, and any
agent that makes a request in that window is handed a token re-signed with the
*new* primary, which the revoke will not touch. That is deliberate — it is how
agents converge on a new key with no push channel — but it means a session that
was active during the window survives a revoke aimed at it. Repeat the pair to
catch it.

Both commands are audited, with the reviewer and the kid linkage, so the sweep is
provable after the fact:

```console
$ python - <<'PY'
import json
for line in open("/tmp/session-lab/audit.jsonl"):
    entry = json.loads(json.loads(line)["metadata"]["nautilus_audit_entry"])
    if entry.get("event_type", "").startswith("signing_key"):
        print(entry["event_type"], entry["rule_trace"])
PY
signing_key_rotated ['reviewer=ops@example.com', 'previous_kid=fb240484-af2b-416a-8d5d-92f8a2a0c5b4', 'new_kid=fef88529-c16b-4f61-883c-63494a032030']
signing_key_revoked ['reviewer=ops@example.com', 'kid=fb240484-af2b-416a-8d5d-92f8a2a0c5b4', 'reason=credential change']
```

Revoking the ring does **not** revoke the API key, and rotating the API key does
not end the session tokens minted under it. A full credential change is both:
the [API-key procedure](#the-api-keys), then `rotate` + `revoke` here.

### Listing the sessions a broker is holding

There is **no endpoint and no CLI subcommand that lists sessions**, and no page
in the console that shows them: `nautilus session version` reads the store's
schema stamp and nothing else. What exists is the store itself, and its schema is
stable and documented — one table, `nautilus_session_state`, with `session_id`,
`state` and `updated_at` (`nautilus/core/session_sqlite.py`,
`nautilus/core/session_pg.py`). Query it directly:

```console
$ python - <<'PY'
import json, sqlite3
db = sqlite3.connect("/tmp/session-lab/sessions.db")
for sid, updated, state in db.execute(
    "SELECT session_id, updated_at, state FROM nautilus_session_state ORDER BY updated_at DESC"
):
    s = json.loads(state)
    print(f"{updated}  {sid:48}  {s.get('owner_principal', '')}  {s.get('sources_visited')}")
PY
2026-09-01 10:43:21  sess-a                                            principal:be1035fc289982777f312b24dc279964  ['customers']
2026-09-01 10:43:21  principal:be1035fc289982777f312b24dc279964          ['customers', 'tickets']
2026-09-01 10:42:21  fd3defc9-4085-4d14-b04d-88dfdce17afe              principal:be1035fc289982777f312b24dc279964  ['customers']
2026-09-01 10:42:21  88d71187-b56d-4cab-b27c-ed963fe35871              principal:be1035fc289982777f312b24dc279964  ['customers']
2026-09-01 10:42:06  sess-b                                            principal:be1035fc289982777f312b24dc279964  ['tickets']
```

The same query against Postgres is `SELECT session_id, updated_at, state FROM
nautilus_session_state ORDER BY updated_at DESC;`. Three things to know before
you read the output as a session list:

- Rows keyed `principal:<hash>` are the per-*caller* exposure ledgers, not
  sessions. Filter them out with `WHERE session_id NOT LIKE 'principal:%'`. The
  hash covers `agent_id` plus the authenticated identity — the credential's
  [`api.keys[].principal`](#apikeysprincipal), or the secret itself when the
  entry names none, which is why a rotation without one starts a new row.
- A token minted by `POST /v1/sessions` has no row until its first request; the
  mint writes a signature, not state.
- `session_store.backend: memory` (the default) has nothing to query at all. The
  state lives in one process's heap, dies with it, and is invisible to every
  other replica. If you need to see sessions, you need `sqlite` or `postgres`.

For what a session *did*, the audit log is the record, and it carries the session
id on both the mint and the request:

```console
$ curl -s "http://127.0.0.1:8000/v1/audit?limit=200" -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
  | python -c 'import json, sys
for e in json.load(sys.stdin)["entries"]:
    if e["session_id"] == "audit-demo":
        print(e["timestamp"], e["event_type"], e["agent_id"], e["sources_queried"])'
2026-09-01T10:45:14.906144Z request reporting ['customers']
2026-09-01T10:45:14.888466Z session_token_issued reporting []
```

Refused presentations are recorded too, under
`session_token_verification_failed`, with the reason code in `error_records`.
Note the empty `agent_id` on three of them: a token rejected for signature,
expiry, kid or broker id is rejected in the transport dependency, before the
broker knows who was asking.

```console
$ curl -s "http://127.0.0.1:8000/v1/audit?limit=200" -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
  | python -c 'import json, sys
for e in json.load(sys.stdin)["entries"]:
    if e["event_type"] == "session_token_verification_failed":
        print(e["timestamp"], repr(e["agent_id"]), [r["error_type"] for r in e["error_records"]])'
2026-09-01T10:45:14.911402Z 'incident-response' ['agent_mismatch']
2026-09-01T10:44:33.185137Z 'incident-response' ['agent_mismatch']
2026-09-01T10:43:31.674228Z '' ['unknown_kid']
2026-09-01T10:43:13.794928Z '' ['expired']
2026-09-01T10:43:09.787313Z '' ['broker_instance_mismatch']
```

### Sessions under a federated identity provider

Under [`api.auth.mode: proxy_trust`](#apiauthmode) Nautilus is a relying party:
the ingress ran the OIDC, SPIFFE or mTLS exchange and asserts the result in
`X-Forwarded-User`, which `agents.<id>.subject` maps to an agent. Add to
`/tmp/session-lab.yaml`:

```yaml
api:
  auth:
    mode: proxy_trust
    trusted_proxies: ["127.0.0.1/32"]
agents:
  reporting:
    subject: "spiffe://cluster.local/ns/agents/sa/reporting"
  incident-response:
    subject: "spiffe://cluster.local/ns/agents/sa/oncall"
session_tokens:
  broker_instance_id: nautilus-fed
```

Four properties follow, and the fourth is the one to plan around. Mint a token
under an asserted identity first — the claim set it hands back is itself the
evidence for the fourth:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/sessions \
    -H "X-Forwarded-User: spiffe://cluster.local/ns/agents/sa/reporting" \
    -H 'Content-Type: application/json' \
    -d '{"session_id":"fed-1","agent_id":"reporting","purpose":"quarterly-reporting"}' \
  | python -c 'import json, sys; d = json.load(sys.stdin); del d["token"]; print(json.dumps(d, indent=2))'
{
  "session_id": "fed-1",
  "agent_id": "reporting",
  "purpose": "quarterly-reporting",
  "clearance": "unclassified",
  "issued_at": 1788259854,
  "expires_at": 1788260754,
  "broker_instance_id": "nautilus-fed",
  "kid": "fef88529-c16b-4f61-883c-63494a032030"
}
```

**The forwarded identity is re-checked on every request.** It is a per-request
dependency, not a session established at first contact, so the moment your proxy
stops forwarding a subject the caller is anonymous again — even holding a valid
Nautilus session token:

```console
$ T=$(curl -s -X POST http://127.0.0.1:8000/v1/sessions \
      -H "X-Forwarded-User: spiffe://cluster.local/ns/agents/sa/reporting" \
      -H 'Content-Type: application/json' \
      -d '{"session_id":"fed-1","agent_id":"reporting","purpose":"quarterly-reporting"}' \
    | python -c 'import json, sys; print(json.load(sys.stdin)["token"])')
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-Nautilus-Session-Token: $T" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}'
{"detail":"Missing X-Forwarded-User"}
```

**A token does not travel between subjects.** It names the agent it was minted
for, and the forwarded subject resolves to an agent, so the two must agree:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-Forwarded-User: spiffe://cluster.local/ns/agents/sa/oncall" \
    -H "X-Nautilus-Session-Token: $T" -H 'Content-Type: application/json' \
    -d '{"agent_id":"incident-response","intent":"list tickets","context":{}}'
{"detail":"Invalid session token (agent_mismatch): session token was minted for agent 'reporting', presented by 'incident-response'"}
```

**A subject no agent claims is refused, not admitted unbound:**

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H "X-Forwarded-User: spiffe://cluster.local/ns/agents/sa/ghost" \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list customers","context":{}}'
{"detail":"Forwarded identity rejected: no agent is bound to this subject. Add it as agents.<id>.subject, or the caller would run unbound with every capability."}
```

**There is no back-channel logout and no awareness of the provider's session
lifetime.** Look again at the claim set above: eight fields, and not one of them
names the identity provider, the subject or the upstream session. Nothing in the
token can be invalidated by the provider, and Nautilus registers no
front-channel or back-channel logout endpoint for a provider to call.

Two consequences, both operational:

1. **Terminating a user at the provider does not terminate the Nautilus session
   token it minted.** What it does terminate is the caller's ability to present
   a subject — which is enough, because every request needs one. The token alone
   buys nothing. Confirm that your proxy actually stops forwarding, rather than
   caching the assertion.
2. **Set `session_tokens.ttl_seconds` no longer than the provider's session
   lifetime.** Nautilus cannot read that number and will not shorten itself to
   match. `900` against a 1-hour IdP session is fine; `86400` is a token that
   outlives twenty-three hours of an identity that no longer exists.

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
you reference from the config with `${VAR}` or name in
[`analysis.provider.api_key_env`](#analysisproviderapi_key_env). There is no
`NAUTILUS_*` override for config keys: the file is the config.

The list below is maintained by hand. Every read of the environment anywhere in
the package is not, so check the list against it rather than trusting this page:

```console
$ grep -rn 'os\.environ\|os\.getenv' nautilus/ --include='*.py'
nautilus/cli/_common.py:34:    reviewer = os.environ.get("NAUTILUS_REVIEWER", "").strip()
nautilus/cli/_common.py:247:    return os.environ.get(API_KEY_ENV, "").strip() or None
nautilus/analysis/llm/local_provider.py:70:        if not os.getenv(self.api_key_env):
nautilus/analysis/llm/local_provider.py:81:            api_key = os.getenv(self.api_key_env) or self._api_key_literal
nautilus/analysis/llm/anthropic_provider.py:93:        key = os.getenv(self.api_key_env)
nautilus/analysis/llm/anthropic_provider.py:115:            api_key=os.getenv(self.api_key_env),
nautilus/analysis/llm/openai_provider.py:92:        key = os.getenv(self.api_key_env)
nautilus/analysis/llm/openai_provider.py:107:            api_key=os.getenv(self.api_key_env),
nautilus/config/loader.py:68:        self._env = env if env is not None else dict(os.environ)
nautilus/core/broker.py:1309:                dsn = os.environ.get("TEST_PG_DSN")
nautilus/adapters/influxdb.py:224:            token = _auth_token(config) or os.environ.get("INFLUXDB_V2_TOKEN")
nautilus/adapters/influxdb.py:225:            org = os.environ.get("INFLUXDB_V2_ORG")
nautilus/observability/__init__.py:16:    if os.environ.get("OTEL_SDK_DISABLED", "").lower() == "true":
nautilus/observability/instrumentation.py:32:    os.environ.setdefault(
nautilus/observability/instrumentation.py:50:    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or os.environ.get(
```

Three classes, and only the first is a fixed name. **Nine fixed names** across
eight call sites — the two OTLP endpoints share one `if`, and `API_KEY_ENV` is
the module constant `"NAUTILUS_API_KEY"` (`nautilus/cli/_common.py:197`). **Six
reads of whatever you named** in `analysis.provider.api_key_env`. **One copy of
the whole environment**, in the loader: that is the `${VAR}` interpolator, and it
is why a variable can be referenced from the config under any name at all.

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

### `NAUTILUS_API_KEY`

Read by `nautilus/cli/_common.py:resolve_api_key` · the `X-API-Key` every CLI subcommand that is pointed at a running broker sends · overridden by an explicit `--api-key`

**Defends** the credential from `argv`. Three subcommands reach a live broker —
`adapters list --url`, `key list|rotate|revoke`, `rkm queue approve` — and until
this variable existed each of them took its key only as `--api-key KEY`. A
command line is not a private place. It is in `/proc/<pid>/cmdline`, which is
mode `444`, for the whole life of the process, and an interactive shell writes
it to history as well. Measure it rather than believe it — start a command
against an address that will not answer, so the process is still alive while you
look:

```console
$ nautilus adapters list --url http://10.255.255.1:1 --api-key "$NAUTILUS_KEY_REPORTING" &
[1] 4081656
$ ps -eo args | grep -- '--api-key' | grep -v grep
.../nautilus adapters list --url http://10.255.255.1:1 --api-key lencVaozhCmnWcCcnRTAqns5l7p1Y6FZpVxt_g6qyiA
$ ls -l /proc/4081656/cmdline /proc/4081656/environ
-r--r--r-- 1 nautilus nautilus 0 Sep  1 15:13 /proc/4081656/cmdline
-r-------- 1 nautilus nautilus 0 Sep  1 15:13 /proc/4081656/environ
```

`444` against `400` is the entire size of what this variable buys: **every**
account on the host can read the flag, and only the process's own user and root
can read the environment. Repeat the first two commands with the key in the
variable instead and `grep` finds nothing:

```console
$ NAUTILUS_API_KEY="$NAUTILUS_KEY_REPORTING" nautilus adapters list --url http://10.255.255.1:1 &
[1] 4081702
$ ps -eo args | grep -- '--api-key' | grep -v grep | wc -l
0
$ tr '\0' ' ' < /proc/4081702/cmdline
.../nautilus adapters list --url http://10.255.255.1:1
```

**Costs** you nothing on the flag: `--api-key` is unchanged, still supported, and
still **wins** when it is passed, so no existing script changes behaviour. What
it costs is the shell hygiene the variable now needs — an exported variable is
inherited by every child of that shell, so export it in the operator's session
(or a systemd `EnvironmentFile`, or a Kubernetes Secret) rather than in a shared
profile, and remember that `/proc/<pid>/environ` is readable by *you* and by
root. This is a smaller exposure than `argv`, not no exposure. If your threat
model includes root or a same-uid process, neither mechanism helps and the
answer is a short-lived credential, which Nautilus does not have — see
[What this does not give you](#what-this-does-not-give-you).

Precedence is decided in one place, `resolve_api_key`, so every subcommand — and
every subcommand added later — answers the same way:

| `--api-key` | `NAUTILUS_API_KEY` | What is sent |
|---|---|---|
| passed | anything | the flag |
| `--api-key ''` | set | **nothing** — an empty flag is a choice, not a fallback |
| absent | set | the variable, stripped of surrounding whitespace |
| absent | unset or blank | no `X-API-Key` header at all |

The strip matters: a value produced by `$(cat /etc/nautilus/key)` or read out of
an `EnvironmentFile` arrives with a trailing newline, and an `X-API-Key` header
carrying one matches no configured key, which reads as a wrong secret rather
than a malformed one. `NAUTILUS_REVIEWER` is stripped for the same reason.

**Fails with** the ordinary refusals of whichever subcommand you ran — the
variable adds no message of its own. With neither the flag nor the variable set:

```console
$ unset NAUTILUS_API_KEY
$ nautilus adapters list --url http://127.0.0.1:8000
ERROR: http://127.0.0.1:8000 refused the credential (401). Pass a valid --api-key.
$ echo $?
1
```

```console
$ nautilus rkm queue approve prop_7f3a --url http://127.0.0.1:8000
ERROR: rkm queue approve: server returned 401: {"detail":"Not authenticated"}
$ echo $?
2
```

**Example**

```console
$ export NAUTILUS_API_KEY="$NAUTILUS_KEY_KEYS"
$ export NAUTILUS_REVIEWER="alice@example.com"
$ nautilus key rotate --url http://127.0.0.1:8000 --yes
OK: rotated: new primary kid=6155cb85-9248-463c-8a93-361ead451422  reviewer=alice@example.com
$ nautilus adapters list --url http://127.0.0.1:8000 --json
[{"id": "orders", "type": "static", "status": "active"}]
```

For a unit file, put it beside the DSNs where it is reviewable and the file is
`0600` — the same place [`${VAR}`](#var-any-name-config-value-interpolation)
secrets live:

```bash
# /etc/nautilus/nautilus.env, 0600, root:nautilus
NAUTILUS_API_KEY=<THE_KEY_THIS_OPERATOR_USES>
NAUTILUS_REVIEWER=alice@example.com
```

One name, two directions. On the broker host the same variable is what
`deploy/configmap.yaml` interpolates into `api.keys` — the key the *server*
accepts — and what the CLI now sends. That is deliberate: a host that already
holds the value for the server does not need a second name for the operator
shell. On a workstation it is only ever the sending half.

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

### `NO_COLOR` — not read, and this page used to say it was

**Nautilus does not read `NO_COLOR`.** This entry previously described it as
"read by `nautilus/cli/_common.py`", with a *Defends* clause about ANSI being
emitted only on a TTY. None of that was true, and the module's own docstring
(`nautilus/cli/_common.py:9-11`) says why the claim was removed from the code:
the CLI emits no ANSI colour at all, so there is nothing for `NO_COLOR` to
disable. The entry is kept rather than deleted because an operator who read the
old one and set the variable deserves to find out what happened to it.

Verify in one line — the grep above is the whole environment surface, and this is
the whole colour surface:

```console
$ grep -rn 'NO_COLOR' nautilus/ --include='*.py'
nautilus/cli/_common.py:9:The CLI emits no ANSI colour at all, so it needs no ``NO_COLOR`` handling. This
nautilus/cli/_common.py:11:exporting ``NO_COLOR`` and concluding the tool is broken.
$ grep -rc $'\x1b\[' nautilus/ --include='*.py' | grep -v ':0$' | wc -l
0
```

Two comments and zero escape sequences. Captured CLI output is already plain,
whether or not the capture allocated a PTY, so nothing needs setting.

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
`broker_instance_mismatch`, `agent_mismatch`. The last one is raised by the
broker rather than the transport dependency, so its body carries the message
too — see
[A session id is not a credential](#a-session-id-is-not-a-credential).

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

Wherever `--api-key KEY` appears below it is optional, and passing it is the
worse of the two ways: prefer
[`NAUTILUS_API_KEY`](#nautilus_api_key), which keeps the credential out of `ps`
and out of shell history. The flag still wins when both are set.

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
nautilus serve: error: argument --transport: invalid choice: 'grpc' (choose from rest, mcp, both)
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

`--url URL` · `--api-key KEY` (or [`NAUTILUS_API_KEY`](#nautilus_api_key)) · `--json` · plus `--yes` on `rotate` and `revoke`, and `--reason REASON` (required) on `revoke`

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

require `NAUTILUS_REVIEWER`; `--url URL` and `--api-key KEY` — or
[`NAUTILUS_API_KEY`](#nautilus_api_key) — (approve/reject reach a running
broker); `--config PATH` (where the decision record is written);
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

## Response headers, byte for byte

The section above says which routes exist and what gates them. This one is the
other axis: what comes back on the wire, header by header, on every response
shape the broker produces. It is measured, not derived from the
middleware — `create_app` installs exactly three
(`grep -c add_middleware nautilus/transport/fastapi_app.py` → `3`):
[`api.max_request_bytes`](#apimax_request_bytes) and
[`api.max_concurrent_requests`](#apimax_concurrent_requests), each of which
writes headers only on its *own* refusal (`content-type: application/json` plus
`content-length`, and `retry-after: 1` on the 503); and `_CacheControl`, which
is unconditional and is the only one that touches a response it lets through.
It sets `Cache-Control` and nothing else — see
[`Cache-Control`](#cache-control-set-on-every-response-except-the-console-assets)
below. Everything else in the table is whatever FastAPI, Starlette and uvicorn
emit. Reproduce the whole table against your own build with the
[`session-lab` config](#sessions-lifetime-parallelism-and-termination):

```bash
hdr() {   # hdr <label> <curl args...>
  printf '%-32s' "$1"; shift
  curl -s -D- -o /dev/null "$@" | tr -d '\r' \
    | awk 'BEGIN{ct="-";cc="-"} /^HTTP\//{st=substr($0,index($0," ")+1)}
           tolower($1)=="content-type:"{$1="";sub(/^ /,"");ct=$0}
           tolower($1)=="cache-control:"{$1="";sub(/^ /,"");cc=$0}
           END{printf "|%-26s|%-40s|%s\n", st, ct, cc}'
}
B=http://127.0.0.1:8000
hdr 'GET /healthz'  $B/healthz
hdr 'GET /v1/audit' -H "X-API-Key: $NAUTILUS_KEY_REPORTING" $B/v1/audit
hdr 'GET /metrics'  $B/metrics
```

Every row below is that command's output. `-` means the header was absent, not
empty.

| Response | Status | `Content-Type` | `Cache-Control` |
|---|---|---|---|
| `GET /healthz` | `200 OK` | `application/json` | `no-cache` |
| `GET /readyz` | `200 OK` | `application/json` | `no-cache` |
| `GET /metrics` | `200 OK` | `text/plain; version=1.0.0; charset=utf-8` | `no-cache` |
| `GET /` | `302 Found` | - *(no body)* | `no-store` |
| `GET /openapi.json` | `200 OK` | `application/json` | `no-store` |
| `GET /docs` | `200 OK` | `text/html; charset=utf-8` | `no-store` |
| `POST /v1/request` | `200 OK` | `application/json` | `no-store` |
| `POST /v1/request` (no key) | `401 Unauthorized` | `application/json` | `no-store` |
| `POST /v1/request` (malformed body) | `422 Unprocessable Content` | `application/json` | `no-store` |
| `GET /v1/audit` | `200 OK` | `application/json` | `no-store` |
| `GET /v1/sources` | `200 OK` | `application/json` | `no-store` |
| `GET /v1/keys/jwks.json` | `200 OK` | `application/json` | `no-store` |
| `GET /v1/nope` | `404 Not Found` | `application/json` | `no-store` |
| `DELETE /healthz` | `405 Method Not Allowed` | `application/json` | `no-cache` |
| `GET /admin/login` | `200 OK` | `text/html; charset=utf-8` | `no-store` |
| `POST /admin/login` | `302 Found` | - *(no body)* | `no-store` |
| `GET /admin/playground` | `200 OK` | `text/html; charset=utf-8` | `no-store` |
| `GET /admin/audit` | `200 OK` | `text/html; charset=utf-8` | `no-store` |
| `GET /admin/decisions` | `200 OK` | `text/html; charset=utf-8` | `no-store` |
| `GET /admin/static/htmx.min.js` | `200 OK` | `text/javascript; charset=utf-8` | - |
| `GET /admin/static/styles.css` | `200 OK` | `text/css; charset=utf-8` | - |
| `GET /admin/sources/events` | `200 OK` | `text/event-stream; charset=utf-8` | `no-store` |
| `POST /v1/request` (1.1 MB body) | `413 Content Too Large` | `application/json` | `no-store` |
| `POST /v1/request` (over `max_concurrent_requests`) | `503 Service Unavailable` | `application/json` | `no-store` |
| malformed framing (see [Message framing](#message-framing-every-hop-must-count-the-body-the-same-way)) | `400 Bad Request` | `text/plain; charset=utf-8` | - |

The last row is the one exception you cannot change from the config: uvicorn's
HTTP parser rejects the framing before the request becomes an ASGI scope, so no
middleware — Nautilus's or anyone's — ever sees it. Everything above it is the
application's answer.

Four controls read straight off that table. Each gets its own entry below.
`Cache-Control` is now Nautilus's own; the other three are still *Nautilus does
not set this and cannot be configured to*, and an operator needs the stanza that
does.

### `Content-Type` on every body, and the character set

**Every response with a body carries a `Content-Type` that matches the bytes,
and every one of them is UTF-8.** There is no row in the table above with a
missing type, no `application/octet-stream` fallback, and no type that
disagrees with its body. That is a property of how each response is built, not
a middleware: JSON routes return Pydantic models that FastAPI renders through
`JSONResponse`, the console returns `HTMLResponse` from Jinja templates,
`/metrics` returns `Response(content=data, media_type=CONTENT_TYPE_LATEST)`
with the constant `prometheus_client` publishes, and `/admin/static` is
Starlette's `StaticFiles`, which types by extension.

The two rows worth reading twice:

- **`text/html`, `text/css`, `text/javascript`, `text/event-stream` and
  `text/plain` all carry `charset=utf-8` explicitly.** They are `text/*`, whose
  default charset is US-ASCII, so the parameter has to be there and it is.
- **`application/json` carries no `charset` parameter, and must not.** RFC 8259
  §11 defines no charset parameter for that media type; UTF-8 is mandatory and
  a `charset=` on it is at best ignored and at worst treated as a parse error.
  So "no charset on the JSON routes" is the correct behaviour, and the question
  that actually matters is whether the bytes really are UTF-8.

They are, and you can see it rather than trust it. Ask for an audit entry whose
id is non-ASCII; the id is echoed back in the error, so the wire bytes are
yours to inspect:

```console
$ curl -s 'http://127.0.0.1:8000/v1/audit/r%C3%A9porting-%CE%A9' \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -o /tmp/naut-ct.bin -D- | grep -i content-type
content-type: application/json
$ xxd /tmp/naut-ct.bin | head -3
00000000: 7b22 6465 7461 696c 223a 2261 7564 6974  {"detail":"audit
00000010: 2065 6e74 7279 2027 72c3 a970 6f72 7469   entry 'r..porti
00000020: 6e67 2dce a927 206e 6f74 2066 6f75 6e64  ng-..' not found
$ python - <<'PY'
b = open("/tmp/naut-ct.bin", "rb").read()
print("as utf-8  :", b.decode("utf-8"))
print("as latin-1:", b.decode("latin-1"))
PY
as utf-8  : {"detail":"audit entry 'réporting-Ω' not found"}
as latin-1: {"detail":"audit entry 'rÃ©porting-Î©' not found"}
```

`c3 a9` and `ce a9` are `é` and `Ω` in UTF-8 — two bytes each, not one — and
the two decodings differ, which is the whole point: had the body been Latin-1
the first line would have failed to decode at all. Nothing here needs a proxy.

The one gap the table does leave is **sniffing**: none of these responses
carries `X-Content-Type-Options: nosniff`, so a browser that dislikes a
declared type may still guess. Nautilus sends no such header on any route and
has no key for it. Add it at the proxy — the stanza is in
[Option B](#option-b-terminate-in-front-and-tell-nautilus-who-did-it) — and
confirm it took:

```console
$ curl -sk -D- -o /dev/null https://nautilus.example.com:8443/v1/audit \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" | grep -i x-content-type
x-content-type-options: nosniff
```

### `Cache-Control` — set on every response except the console assets

**Nautilus sets it, deny-by-default, in `_CacheControl`
(`nautilus/transport/fastapi_app.py`), and there is no key to turn it off.**
A response with no `Cache-Control` and a `200` status is *heuristically
cacheable* (RFC 9111 §4.2.2): a shared cache is permitted to store it and serve
it to somebody else. That is not a theoretical reading. Put an nginx cache in
front of the broker with a deliberately key-blind cache key — which is what a
CDN, a corporate forward proxy or a sidecar cache is:

```nginx
# The shared cache, for the demonstration. Do not deploy this.
proxy_cache_path /var/cache/naut levels=1:2 keys_zone=naut:1m max_size=64m inactive=10m;
server {
    listen 8082;
    location / {
        proxy_pass        http://127.0.0.1:8000;
        proxy_cache       naut;
        proxy_cache_valid 200 10m;
        proxy_cache_key   "$request_uri";
        add_header        X-Cache-Status $upstream_cache_status always;
    }
}
```

Against a build with no `Cache-Control` on the response — which is what every
release before this one shipped — that cache stores the audit trail on the
first authenticated request and hands it to the next caller regardless of who
they are:

```console
$ curl -s -D- -o/dev/null -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    http://127.0.0.1:8082/v1/audit | grep -i x-cache-status
X-Cache-Status: MISS
$ curl -s -D- -o/dev/null -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    http://127.0.0.1:8082/v1/audit | grep -i x-cache-status
X-Cache-Status: HIT

$ # now with no credential at all:
$ curl -s -D- -o/dev/null http://127.0.0.1:8082/v1/audit | grep -iE '^HTTP|x-cache'
HTTP/1.1 200 OK
X-Cache-Status: HIT
$ curl -s http://127.0.0.1:8082/v1/audit | wc -c
94838
```

Ninety-four kilobytes of the decision trail, to a caller holding nothing. The
broker refused that caller correctly; the cache in front of it did not, because
nothing in the response told it not to.

Same cache, same requests, against this release:

```console
$ curl -s -D- -o/dev/null -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    http://127.0.0.1:8082/v1/audit | grep -iE 'cache-control|x-cache-status'
cache-control: no-store
X-Cache-Status: MISS
$ curl -s -D- -o/dev/null -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    http://127.0.0.1:8082/v1/audit | grep -iE 'cache-control|x-cache-status'
cache-control: no-store
X-Cache-Status: MISS

$ # and with no credential:
$ curl -s -D- -o/dev/null http://127.0.0.1:8082/v1/audit | grep -iE '^HTTP|x-cache-status'
HTTP/1.1 401 Unauthorized
X-Cache-Status: MISS
$ curl -s http://127.0.0.1:8082/v1/audit
{"detail":"Not authenticated"}
```

`MISS` on the second request is the assertion: the cache was offered the
response and declined to store it. Thirty bytes instead of 94 838.

#### What is set where, and why it is not one directive everywhere

The default is `no-store` and it is a *default*, not a route list — a route
added next release is covered without anyone remembering to add it. Two
exemptions, each of which had to earn itself:

| Responses | `Cache-Control` | Why |
|---|---|---|
| `/admin/static/**` | *(nothing — the mount is left alone)* | Public bytes with no caller in them, served by Starlette's `StaticFiles`, which already emits `etag` and `last-modified`. A shared cache stores them and revalidates correctly on its own. This is the only place on the surface where caching is a win. |
| `/healthz`, `/readyz`, `/metrics` | `no-cache` | They carry nothing about a caller, so forbidding *storage* would be over-broad. But each answers a question about a live process, and a cached `readyz: ok` from a draining pod, or a flat-lined scrape, is a wrong answer rather than a stale one. `no-cache` permits the copy and forbids serving it without revalidating. |
| everything else | `no-store` | `/v1/audit` and `/v1/audit/{id}` are the audit trail; `/v1/request` and `/v1/query` carry brokered rows; `/v1/sources` and `/v1/adapters` enumerate what you connect to; every `/admin/` page renders one of those into a browser, where the back button, the disk cache and a shared proxy are three separate ways for the next person at that terminal to read them. `/v1/keys/jwks.json` is public key material and would be safe to cache anywhere else, but this broker can revoke a `kid` — a cached key set is a revoked key still verifying. |

The exemption is real, and the same cache shows it:

```console
$ for i in 1 2 3; do
    curl -s -D- -o/dev/null http://127.0.0.1:8082/admin/static/styles.css \
    | grep -i x-cache-status
  done
X-Cache-Status: MISS
X-Cache-Status: HIT
X-Cache-Status: HIT
```

`MISS` then `HIT` then `HIT` on the stylesheet, while `/v1/audit` above stayed
`MISS` forever, through one cache in one run.

Two more things the middleware deliberately does *not* do:

- **It sets `Cache-Control` and nothing else.** `Pragma: no-cache` is an
  HTTP/1.0 *request* header (RFC 9111 §5.4) that no 1.1 cache reads off a
  response, `Expires: 0` is overridden by `Cache-Control` wherever both appear,
  and `Vary` has nothing to key on once the response may not be stored. A
  longer header list here would be decoration.
- **A handler that set the header itself wins.** `/admin/sources/events` says
  `no-store` because `sse_starlette.EventSourceResponse` does
  `_headers.setdefault("Cache-Control", "no-store")` in its own constructor, and
  the middleware leaves it alone. A handler that thought about caching knows
  more than a path prefix does.

One caveat worth stating plainly: **`no-store` is an instruction, not an
enforcement.** It binds a cache that implements RFC 9111 — nginx, Varnish,
Squid, every browser — and it does nothing about a proxy configured with
`proxy_ignore_headers Cache-Control`, or about an appliance that logs response
bodies. If your tier does either, that is a tier setting to change; the
`add_header Cache-Control "no-store" always;` lines in
[Option B](#option-b-terminate-in-front-and-tell-nautilus-who-did-it) are now
belt-and-braces rather than the only thing standing between the audit trail and
a shared cache, and they are kept because a proxy that rewrites or strips
upstream headers is a real deployment.

### `Access-Control-*` — there is no CORS layer, and that is the control

**Nautilus never sends an `Access-Control-Allow-Origin`, on any route, under any
configuration.** `CORSMiddleware` is not imported anywhere in the tree and there
is no config key that would add it:

```console
$ grep -rn 'CORSMiddleware\|Access-Control' nautilus/ --include='*.py' | wc -l
0
$ for p in /healthz /readyz /metrics /v1/audit /v1/sources /admin/playground /openapi.json; do
    curl -s -D- -o/dev/null -H 'Origin: https://evil.example' \
      -H "X-API-Key: $NAUTILUS_KEY_REPORTING" "http://127.0.0.1:8000$p" \
    | tr -d '\r' | grep -i 'access-control'
  done
$ echo "exit $?"
exit 1
```

No output, on any of the seven. The preflight has no handler either — `OPTIONS`
is not a declared method on `/v1/request`, so it gets the router's 405:

```console
$ curl -s -D- -o/dev/null -X OPTIONS http://127.0.0.1:8000/v1/request \
    -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: POST' \
    | grep -iE '^HTTP|^allow'
HTTP/1.1 405 Method Not Allowed
allow: POST
```

That is the safe answer and it is the answer you want to keep. A page on
`https://evil.example` can still *send* a cross-origin `POST /v1/request` — the
browser will not block a simple request from leaving — but it cannot read the
reply, and it cannot attach a credential: `X-API-Key` and
`X-Nautilus-Session-Token` are not CORS-safelisted request headers, so adding
either turns the request into a preflighted one, and the preflight gets a 405.

The console cookie is the exception worth naming, because a cookie *is* sent
cross-origin by the browser without any header being set. `nautilus_key` is
issued `SameSite=lax`, which is what stops a cross-site `POST` from carrying it:

```console
$ # the cookie value is the API key itself -- asserted without printing it:
$ curl -s -D- -o/dev/null -X POST -d "api_key=$NAUTILUS_KEY_REPORTING" \
    http://127.0.0.1:8000/admin/login \
  | grep -c "nautilus_key=$NAUTILUS_KEY_REPORTING"
1
$ curl -s -D- -o/dev/null -X POST -d "api_key=$NAUTILUS_KEY_REPORTING" \
    http://127.0.0.1:8000/admin/login | tr -d '\r' | grep -i set-cookie \
  | sed "s/$NAUTILUS_KEY_REPORTING/<REDACTED>/"
set-cookie: nautilus_key=<REDACTED>; HttpOnly; Max-Age=86400; Path=/; SameSite=lax
```

`grep -c` returning `1` is the assertion: the console does not mint a session
identifier, it stores the credential. `HttpOnly` keeps script off it and
`SameSite=lax` keeps a cross-site `POST` from carrying it, but anything that
reads that cookie holds a working API key — which is why every `/admin/`
response, the login form and its `401` included, carries `no-store` and why
that is not configurable.

If you put a CORS layer in front of Nautilus yourself, do not answer
`Access-Control-Allow-Origin: *` together with
`Access-Control-Allow-Credentials: true` — browsers reject that pair, and the
version of it that browsers *accept*, reflecting the request's `Origin` back,
is the one that turns every authenticated console session into a
cross-origin read. If the console must be reachable from another origin, name
that origin literally.

### `Strict-Transport-Security` — not sent, and it cannot be

Nautilus does not terminate TLS
([Transport](#transport-tls-nautilus-does-not-do-it)), so it is not the right
component to declare a TLS policy, and it does not:

```console
$ grep -rn 'Strict-Transport' nautilus/ --include='*.py' | wc -l
0
```

It belongs on the tier that holds the certificate. The stanza is in
[Option B](#option-b-terminate-in-front-and-tell-nautilus-who-did-it); confirm
it is on the response and not just in the file:

```console
$ curl -sk -D- -o /dev/null https://nautilus.example.com:8443/v1/audit \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" | grep -i strict-transport
strict-transport-security: max-age=63072000; includeSubDomains
```

Two caveats specific to this deployment shape. `includeSubDomains` binds every
sibling name under the registered domain, including hosts you do not operate —
check that before you ship it, because a browser will honour it for two years.
And `preload` is deliberately absent above: submitting to the preload list is
irreversible on a human timescale, and a broker that a customer might later want
to reach over plain HTTP on an internal name is the wrong candidate for it.

## What the deployment discloses without being asked

The routes above are what Nautilus serves on purpose. This section is the other
half: what a scanner or a curious caller gets out of a stock deployment without
holding a credential, and which of those answers are settings you can change
versus properties of the shipped artifact. Each check runs against your own
build; none of them needs a key.

### Source-control metadata in the image

**Not present, and the reason is structural rather than a setting you could
forget.** `.dockerignore` excludes `.git/`, `.github/` and `.gitignore` from the
build context, and — the part that matters more — the published `runtime` stage
is a fresh `gcr.io/distroless/cc-debian13` that copies in only `/app` from the
builder, which itself received exactly `pyproject.toml`, `uv.lock`, `README.md`
and the `nautilus` package. Nothing else from the working tree can reach the
image, whatever is in the context.

Verify it on the image you are actually shipping, not on the Dockerfile:

```bash
docker build -t nautilus:local .
```

```console
$ cid=$(docker create nautilus:local)
$ docker export "$cid" | tar -t | grep -cE '(^|/)\.(git|svn|hg)/'
0
$ docker export "$cid" | tar -t | grep -E '^app/[^/]+/?$'
app/.venv/
app/README.md
app/nautilus/
app/nautilus_rkm.egg-info/
app/pyproject.toml
app/uv.lock
$ docker rm "$cid" > /dev/null
```

`grep -c` returning `0` is the assertion. Run the same check after any change to
`.dockerignore`, and after adding a build stage that copies more than the two
`COPY` lines above — a `COPY . /app` would put the whole repository, `.git`
included, into a layer that `docker history` will still show even if a later
stage deletes it.

If you build the image some other way (a CI recipe, a base image of your own),
this guarantee is yours to keep, not ours.

### Debug modes

**Nothing is in a debug mode by default, and no config file can put it there.**
That is a stronger claim than "remember to turn it off", so here is each place
one would normally live and the check for each.

**The application.** The FastAPI app is constructed with `title`, `description`,
`version` and `lifespan` only — `debug` is never passed, so it is `False`, and
Starlette answers an unhandled exception with a plain `Internal Server Error`
and no traceback. There is no config key and no environment variable that flips
it. Any config that loads will do — the answer does not depend on one:

```console
$ python - <<'PY'
from nautilus.transport.fastapi_app import create_app

app = create_app("/tmp/session-lab.yaml")
print("debug:", app.debug)
PY
debug: False
```

**The server.** `nautilus serve` builds its uvicorn config with host, port and
the `--log-level` value, which is `info` unless the command line says
otherwise. There is no `--reload` and no `--debug`:

```console
$ nautilus serve --help | grep -cE -- '--reload|--debug'
0
$ nautilus serve --reload
usage: nautilus [-h] command ...
nautilus: error: unrecognized arguments: --reload
$ echo $?
2
```

Reaching DEBUG therefore takes an explicit `--log-level debug` on the command
line, which makes it a grep of the unit files and the Deployment's `args:`,
exactly as for `--bind`. What that flag turns on is the broker's own
per-request reasoning — the config it loaded, why each source was queried,
skipped or denied, which rules fired, what each adapter dialled, what the SSRF
guard resolved a name to, why a session token was minted, and which `/readyz`
stage spent the time — and every library's `DEBUG` alongside it
([What `--log-level debug` adds](operator-guide.md#what-log-level-debug-adds)).
No credential is on that stream: every address in it is rebuilt from scheme,
host and port by `redact_connection`, and session tokens are named by their
session id rather than printed. Raising the threshold the other way has its
own cost — [Log verbosity](operator-guide.md#log-verbosity) lists the startup
lines this page tells you to read that `warning` and above take away.

If you run uvicorn yourself — one of the two supported TLS answers,
[Option A](#option-a-run-uvicorn-yourself-with-certificates) — then `--reload` is
yours to not pass. It re-imports source on change and has no place on a
production listener.

**Application logging.** `configure_logging` takes both the log *format* and
the log *level* from the CLI and from nowhere else. There is no
`NAUTILUS_LOG_LEVEL` and no config key — the flag is the whole mechanism — and
[`--log-format json`](#nautilus-serve-log-format-textjson) changes the
encoding, not the verbosity.

**The image.** The Dockerfile declares a `debug` target carrying `bash` and a
package manager, alongside the `runtime` target that carries neither. `runtime`
is declared last, so a bare `docker build .` selects it and `debug` is reachable
only through an explicit `--target debug`. Which one you are holding is a
one-line check, because a distroless runtime image has no shell at all:

```console
$ cid=$(docker create nautilus:local)
$ docker export "$cid" | tar -t | grep -cE '^(bin|usr/bin|usr/local/bin)/(sh|bash|dash)$'
0
$ docker rm "$cid" > /dev/null
```

Anything other than `0` means a shell is in the image you are about to run.

What *is* disclosed by design, and is not a debug mode: `/docs`, `/redoc`,
`/openapi.json`, `/metrics` and the `GET /` route index are unauthenticated and
have no off switch. They are covered in
[Routes and what gates them](#routes-and-what-gates-them); the control for them
is the reverse proxy, not a config key.

### Directory listings

**None are served.** The only static mount is `/admin/static`, it exists only
when `ui.enabled: true`, and it is a plain `StaticFiles(directory=...)` — the
`html=True` mode that would render an index is not used. A request for the
directory is a 404, and only named files resolve:

```console
$ curl -s -w '\n%{http_code}\n' http://127.0.0.1:8000/admin/static/
{"detail":"Not Found"}
404
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/admin/static/styles.css
200
```

No route resolves a caller-supplied path to a file. The audit log is served as
parsed entries through `GET /v1/audit` under the `audit_read` capability, never
as bytes off disk, and the key ring, the session database and the state
directory are not on the HTTP surface at all. That also means the filesystem
permissions in [Lay down the filesystem](#lay-down-the-filesystem) are the whole
of their access control, and there is no route from which to test them.

### HTTP TRACE and the other methods a route does not serve

**`TRACE` is not implemented on any route, and there is nothing to disable.**
Starlette's router dispatches only the methods a route declares; everything else
is refused before any handler runs. On a path that exists the answer is 405 with
an `Allow` header naming what the route does serve:

```console
$ curl -s -D - -o /dev/null -X TRACE http://127.0.0.1:8000/healthz \
  | grep -iE '^(HTTP/|allow:)'
HTTP/1.1 405 Method Not Allowed
allow: GET
$ curl -s -X TRACE http://127.0.0.1:8000/healthz
{"detail":"Method Not Allowed"}
```

On a path that does not exist it is a 404, so `TRACE` is never a discriminator
between "route present" and "route absent" either:

```console
$ curl -s -w '\n%{http_code}\n' -X TRACE http://127.0.0.1:8000/no-such-path
{"detail":"Not Found"}
404
```

Every other method a scanner reaches for lands in the same place, on the one
route that is unauthenticated on every deployment:

```console
$ for m in HEAD OPTIONS PUT PATCH DELETE TRACE TRACK; do
    printf '%-8s %s\n' "$m" "$(curl -s -o /dev/null -w '%{http_code}' -X "$m" http://127.0.0.1:8000/healthz)"
  done
HEAD     405
OPTIONS  405
PUT      405
PATCH    405
DELETE   405
TRACE    405
TRACK    400
```

`TRACK` is the odd one: uvicorn's HTTP parser rejects it before the application
is reached at all, with a plain-text body and no JSON envelope, which is what
that shape means whenever you see it:

```console
$ curl -s -D - -X TRACK http://127.0.0.1:8000/healthz | head -1
HTTP/1.1 400 Bad Request
$ curl -s -X TRACK http://127.0.0.1:8000/healthz
Invalid HTTP request received.
```

Two caveats that are yours, not Nautilus's:

- **A reverse proxy in front is a second implementation of this.** The 405 above
  is what *Nautilus* answers; what your ingress answers is its own behaviour and
  its own configuration. Run the same `curl -X TRACE` against the public name,
  not against `127.0.0.1`, in the same way
  [Confirm the gate is closed](#confirm-the-gate-is-closed) tests the other
  controls from outside.
- **The 405 body and the `Allow` header confirm a route exists.** That is
  ordinary REST behaviour and not a leak of anything the unauthenticated
  `GET /docs` and `/openapi.json` do not already publish in full.

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
also how you scope `/metrics` and `/admin`, how the response headers Nautilus
does not send get sent, and how the whole chain is made to agree on message
length. It is one file, and every transcript on this page that involves TLS was
taken against exactly it:

```nginx
# /etc/nginx/conf.d/nautilus.conf
# Ports are 8080/8443 so the file runs unprivileged and the transcripts below
# are literal; production is 80/443 with $host and no :port in the redirect.

# V4.1.2 -- only the surface a human reaches by typing a URL redirects.
server {
    listen 8080;
    server_name nautilus.example.com;
    charset utf-8;

    # The console: a browser followed a bookmark. Send it to HTTPS.
    location /admin { return 301 https://$host:8443$request_uri; }

    # The API: no redirect, on purpose. A 301 teaches an agent that a plaintext
    # request is recoverable. It is not -- the key was already on the wire in
    # clear, and a retry over TLS does not un-send it.
    location /v1/ {
        # nginx appends the charset only to the types named here, and
        # application/json is not in the stock charset_types list.
        default_type  application/json;
        charset       utf-8;
        charset_types application/json;
        add_header Cache-Control "no-store" always;
        return 403 '{"detail":"Plaintext HTTP is not accepted on /v1/. Use https://; rotate any key sent over this connection."}';
    }

    location / { return 403; }
}

server {
    listen 8443 ssl;
    http2 on;
    server_name nautilus.example.com;
    charset utf-8;

    ssl_certificate     /etc/nginx/tls/nautilus.crt;
    ssl_certificate_key /etc/nginx/tls/nautilus.key;

    # V12.1.2 -- recommended suites only, strongest first, server order wins.
    ssl_protocols             TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_conf_command          Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
    ssl_ciphers               ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_ecdh_curve            X25519:prime256v1;
    ssl_session_tickets       off;

    # V4.2.1 -- one framing rule for the whole chain. Nautilus takes small JSON
    # bodies and never needs a chunked upload, so the encoding the two ends
    # frame differently is refused at the edge; 444 closes the connection so no
    # trailing bytes can be re-read as a second request. client_max_body_size
    # is api.max_request_bytes to the byte.
    proxy_http_version      1.1;
    proxy_set_header        Connection "";
    proxy_request_buffering on;
    client_max_body_size    1048576;
    if ($http_transfer_encoding) { return 444; }

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;

    # The data surface.
    location /v1/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # proxy_trust only: set it, never pass a client-supplied value through.
        proxy_set_header X-Forwarded-User  $ssl_client_s_dn;
        # V14.3.2 -- brokered rows and the audit trail are not cacheable.
        add_header Cache-Control "no-store" always;
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
    }

    # The console, if you enable it at all. Operator subnet only.
    location /admin/ {
        allow 10.30.0.0/16;
        allow 127.0.0.1;
        deny  all;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        add_header Cache-Control "no-store" always;
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
    }

    location = /admin {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        add_header Cache-Control "no-store" always;
    }

    # Scrapes come from the monitoring subnet and nowhere else.
    location = /metrics {
        allow 10.20.0.0/16;
        allow 127.0.0.1;
        deny  all;
        proxy_pass http://127.0.0.1:8000;
    }

    location = /healthz { proxy_pass http://127.0.0.1:8000; }
    location = /readyz  { proxy_pass http://127.0.0.1:8000; }
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

Load it and prove it parsed before you rely on any of the checks below:

```console
$ nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

### Cipher suites: what the pin above actually refuses

`ssl_protocols` alone is not the control. Within TLS 1.2, nginx's compiled
default is `HIGH:!aNULL:!MD5`, which is wide enough to negotiate a suite with a
SHA-1 MAC in CBC mode and, worse, one with no forward secrecy at all — a
recorded session that a future key compromise decrypts retroactively. The two
directives that close it are `ssl_ciphers` (which suites exist) and
`ssl_prefer_server_ciphers on` (whose preference order decides), plus
`ssl_conf_command Ciphersuites` for the separate TLS 1.3 list, which
`ssl_ciphers` does not govern.

The difference is one scan wide. Run the same vhost twice — once on nginx's
stock TLS defaults, once with the block above — and enumerate what each will
actually negotiate, with a scanner that carries its own TLS stack rather than
your local libssl (a modern `openssl` has dropped the old suites itself, so a
refusal from *it* proves nothing about the server):

```console
$ # stock nginx defaults -- the first six of twenty-five TLS 1.2 suites:
$ nmap --script ssl-enum-ciphers -p 8444 127.0.0.1 \
    | sed -n '/TLSv1.2/,/compressors/p' | head -6
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp256r1) - A
$ nmap --script ssl-enum-ciphers -p 8444 127.0.0.1 | grep -c 'TLS_RSA_WITH'
14

$ # the same vhost with ssl_ciphers pinned -- the whole scan:
$ nmap --script ssl-enum-ciphers -p 8443 127.0.0.1 \
    | sed -n '/ssl-enum/,/least strength/p'
| ssl-enum-ciphers: 
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|     compressors: 
|       NULL
|     cipher preference: server
|   TLSv1.3: 
|     ciphers: 
|       TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
|       TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|     cipher preference: server
|_  least strength: A
```

The `grep -c` is the sharpest line in that pair: fourteen of the twenty-five
stock suites are `TLS_RSA_WITH_*` — static RSA key exchange, no ECDHE, no
forward secrecy — and a recording of any session negotiated with one of them is
decrypted retroactively the day that certificate's private key leaks.

Three numbers off those two scans are the whole control:

```console
$ for p in 8444 8443; do
    nmap --script ssl-enum-ciphers -p $p 127.0.0.1 > /tmp/scan-$p.txt
    printf 'port %s: %s TLS1.2 suites, %s of them without forward secrecy, preference %s\n' \
      "$p" \
      "$(sed -n '/TLSv1.2/,/compressors/p' /tmp/scan-$p.txt | grep -c 'TLS_')" \
      "$(sed -n '/TLSv1.2/,/compressors/p' /tmp/scan-$p.txt | grep -c 'TLS_RSA_')" \
      "$(grep -m1 'cipher preference' /tmp/scan-$p.txt | sed 's/.*preference: //')"
  done
port 8444: 25 TLS1.2 suites, 14 of them without forward secrecy, preference client
port 8443: 3 TLS1.2 suites, 0 of them without forward secrecy, preference server
```

`nmap` grades every one of those twenty-five `A`, and reports
`least strength: A` for both ports — which is exactly why the grade is not the
assertion and the counts are. `cipher preference` is the other half: `server`
means `ssl_prefer_server_ciphers on` took effect, `client` means the peer
chooses, and a downgrading client chooses badly.

If you have no scanner, the same two assertions come out of `openssl s_client`,
one suite at a time:

```console
$ echo Q | openssl s_client -connect 127.0.0.1:8444 -servername nautilus.example.com \
    -tls1_2 -cipher 'AES256-GCM-SHA384' 2>&1 | grep -oE 'Cipher is [^ ]+'
Cipher is AES256-GCM-SHA384
$ echo Q | openssl s_client -connect 127.0.0.1:8443 -servername nautilus.example.com \
    -tls1_2 -cipher 'AES256-GCM-SHA384' 2>&1 | grep -oE 'handshake failure'
handshake failure
$ echo Q | openssl s_client -connect 127.0.0.1:8443 -servername nautilus.example.com \
    -tls1_2 -cipher 'ECDHE-RSA-AES256-SHA' 2>&1 | grep -oE 'handshake failure'
handshake failure
$ echo Q | openssl s_client -connect 127.0.0.1:8443 -servername nautilus.example.com \
    -tls1_2 -cipher 'ECDHE-RSA-AES128-GCM-SHA256' 2>&1 | grep -oE 'Cipher is [^ ]+'
Cipher is ECDHE-RSA-AES128-GCM-SHA256
```

The last one matters as much as the refusals: the pinned vhost still negotiates
a 128-bit AEAD suite, so "refuses everything" is not what happened.

**Strongest preferred** gets its own probe — offer the weaker suite *first* and
see which comes back:

```console
$ echo Q | openssl s_client -connect 127.0.0.1:8443 -servername nautilus.example.com \
    -tls1_2 -cipher 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384' 2>&1 \
  | grep -oE 'Cipher is [^ ]+'
Cipher is ECDHE-RSA-AES256-GCM-SHA384
$ echo Q | openssl s_client -connect 127.0.0.1:8443 -servername nautilus.example.com \
    -tls1_3 2>&1 | grep -oE 'Cipher is [^ ]+'
Cipher is TLS_AES_256_GCM_SHA384
```

The client asked for AES-128 first and got AES-256. That is
`ssl_prefer_server_ciphers on` against an `ssl_ciphers` list written
strongest-first; drop either and the client's order wins. The TLS 1.3 line comes
from `ssl_conf_command Ciphersuites`, whose first entry is
`TLS_AES_256_GCM_SHA384` — `ssl_ciphers` does not govern TLS 1.3 at all, which
is why both directives are in the block.

None of this is a Nautilus setting. There is no `api.tls` key, `nautilus serve`
forwards no TLS options, and `grep -rn 'ssl_ciphers\|SSLContext\|set_ciphers'
nautilus/` returns nothing. Under [Option A](#option-a-run-uvicorn-yourself-with-certificates)
the equivalent knob is uvicorn's `--ssl-ciphers`, whose default is the literal
OpenSSL cipher string `TLSv1` — every TLSv1-era suite, static RSA included, and
far wider than the list above. Confirm the default for the uvicorn you have
rather than trusting this page:

```console
$ python -c "import inspect; from uvicorn.config import Config; \
print(inspect.signature(Config.__init__).parameters['ssl_ciphers'].default)"
TLSv1
```

Pass `--ssl-ciphers` explicitly, or terminate in front.

### Which requests redirect to HTTPS, and which must not

**Nautilus never redirects HTTP to HTTPS.** It terminates no TLS, binds no
second listener, and has no config key that would add a redirect — the `301` in
the block above is nginx's, scoped to `/admin` and nothing else. That
scoping is the control, and it is deliberate:

```console
$ # the console: a human typed it, so send them somewhere useful
$ curl -sS -D- -o/dev/null http://nautilus.example.com:8080/admin/audit \
  | grep -iE '^HTTP|^location'
HTTP/1.1 301 Moved Permanently
Location: https://nautilus.example.com:8443/admin/audit

$ # the API: no redirect, and the reason is in the body
$ curl -sS -D- http://nautilus.example.com:8080/v1/audit \
  | grep -iE '^HTTP|^location|content-type|cache-control|^\{'
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Cache-Control: no-store
{"detail":"Plaintext HTTP is not accepted on /v1/. Use https://; rotate any key sent over this connection."}
```

An agent that sent `X-API-Key` to port 80 has already leaked it to every hop on
the path. Redirecting it to HTTPS makes the client library retry, the retry
succeed, and the incident invisible — the operator sees a healthy 200 and no
sign that a credential was disclosed. A refusal that names the consequence is
the honest answer, and it shows up as a 403 in the metrics you already scrape.
There is no `Location` in that response, which is the assertion: `grep -i
'^location'` prints nothing.

**The other half of this control is the redirect Nautilus *does* emit.**
Starlette's `redirect_slashes` answers `/admin` with a `307` to `/admin/`, and
FastAPI builds that `Location` as an absolute URL from the request scheme. Which
scheme it believes depends on whether uvicorn trusted your proxy's
`X-Forwarded-Proto`, and uvicorn trusts `127.0.0.1` and nothing else unless you
say otherwise. Same broker, same request, one environment variable apart:

```console
$ # proxy on loopback -- uvicorn's default trust list
$ curl -sS -D- -o/dev/null -H 'X-Forwarded-Proto: https' \
    -H 'Host: nautilus.example.com' http://127.0.0.1:8000/admin \
  | grep -iE '^HTTP|^location'
HTTP/1.1 307 Temporary Redirect
location: https://nautilus.example.com/admin/

$ # the same broker started with FORWARDED_ALLOW_IPS=10.9.9.9
$ curl -sS -D- -o/dev/null -H 'X-Forwarded-Proto: https' \
    -H 'Host: nautilus.example.com' http://127.0.0.1:8001/admin \
  | grep -iE '^HTTP|^location'
HTTP/1.1 307 Temporary Redirect
location: http://nautilus.example.com/admin/
```

`http://` in a `Location` sent to a browser that reached you over TLS is a
downgrade: the browser follows it in clear, and the console cookie — which
Nautilus marks `Secure` precisely because it holds an API key — is then
withheld, so the operator lands on a login page over plaintext and types the key
again. Two ways to be sure it cannot happen:

- **Run the proxy on loopback**, which is the shape this page recommends
  (`api.host: 127.0.0.1`) and which uvicorn already trusts.
- **If the proxy is on another host**, set `FORWARDED_ALLOW_IPS` to its address
  in the unit's `EnvironmentFile`. It is uvicorn's variable, not Nautilus's —
  `nautilus serve` constructs `uvicorn.Config(app, host=..., port=...,
  log_level=...)` and passes no `forwarded_allow_ips`, so uvicorn's own default
  (`127.0.0.1`, overridable by that variable) is what is in force.

Never set it to `*`. That trusts the scheme, and the client IP, from anyone who
can reach the port.

Check which way your deployment resolved it, from outside, in one line:

```console
$ curl -sk -D- -o/dev/null -H 'X-Forwarded-Proto: https' \
    https://nautilus.example.com:8443/admin | grep -i '^location'
location: https://nautilus.example.com/admin/
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

## Message framing: every hop must count the body the same way

If the proxy and the broker disagree about where one request ends and the next
begins, an attacker writes bytes that the proxy reads as one request and the
broker reads as two. The second one is *smuggled*: it never passed the proxy's
`location` blocks, so `deny all` on `/admin/` and `/metrics` did not apply to
it, and it arrives on a connection the proxy already authenticated for someone
else. This is not a header you can set. It is an agreement you have to test.

Nautilus's half of the agreement is uvicorn's HTTP parser, and **which parser
that is depends on what is installed**, not on any Nautilus setting.
`nautilus serve` builds `uvicorn.Config(app, host=..., port=..., log_level=...)`
and leaves `http="auto"`, so uvicorn picks `httptools` when the package is
present and falls back to `h11` when it is not. Print which one your process
resolved to before trusting any result below:

```console
$ python - <<'PY'
from uvicorn.config import Config
async def app(scope, receive, send): ...
c = Config(app=app); c.load()
print(c.http, "->", c.http_protocol_class.__name__)
PY
auto -> HttpToolsProtocol
```

### What Nautilus refuses on its own

Five framing primitives, spoken straight at the broker over a raw socket. Save
this as `smuggle.py`; it is the same script used against every hop below.

```python
# smuggle.py <port> -- the five ways to make two parsers disagree.
import socket, sys

CASES = {
 "Content-Length + Transfer-Encoding":
  b"POST /v1/request HTTP/1.1\r\nHost: nautilus.example.com\r\n"
  b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
 "two Content-Length headers":
  b"POST /v1/request HTTP/1.1\r\nHost: nautilus.example.com\r\n"
  b"Content-Length: 6\r\nContent-Length: 0\r\n\r\nGET /x HTTP/1.1\r\nHost: n\r\n\r\n",
 "Transfer-Encoding: chunked, identity":
  b"POST /v1/request HTTP/1.1\r\nHost: nautilus.example.com\r\n"
  b"Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n",
 "Transfer-Encoding<SP>: chunked":
  b"POST /v1/request HTTP/1.1\r\nHost: nautilus.example.com\r\n"
  b"Transfer-Encoding : chunked\r\nContent-Length: 0\r\n\r\n",
 "bare-LF chunk terminator":
  b"POST /v1/request HTTP/1.1\r\nHost: nautilus.example.com\r\n"
  b"Transfer-Encoding: chunked\r\n\r\n0\n\n"
  b"GET /admin/audit HTTP/1.1\r\nHost: nautilus.example.com\r\n\r\n",
}

for name, payload in CASES.items():
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 3)
    s.sendall(payload); s.settimeout(2.5); buf = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except TimeoutError:
        pass
    s.close()
    first = buf.split(b"\r\n")[0].decode("latin1") if buf else "(closed, no response)"
    print(f"  {name:<38} {first:<28} requests_parsed={buf.count(b'HTTP/1.1 ')}")
```

```console
$ python smuggle.py 8000
  Content-Length + Transfer-Encoding     HTTP/1.1 400 Bad Request     requests_parsed=1
  two Content-Length headers             HTTP/1.1 400 Bad Request     requests_parsed=1
  Transfer-Encoding: chunked, identity   HTTP/1.1 400 Bad Request     requests_parsed=1
  Transfer-Encoding<SP>: chunked         HTTP/1.1 400 Bad Request     requests_parsed=1
  bare-LF chunk terminator               HTTP/1.1 400 Bad Request     requests_parsed=1
```

`requests_parsed=1` on every row is the assertion, not the `400`. Two of those
five payloads — `two Content-Length headers` and `bare-LF chunk terminator` —
carry a whole second request in the tail, and the broker parsed neither. The 400
body is uvicorn's, not Nautilus's — `Invalid HTTP request received.`,
`text/plain; charset=utf-8`, `connection: close` — so it will not appear in the
audit trail and there is no Nautilus error string to search for. Look for the
uvicorn line instead:

```console
$ journalctl -u nautilus --since "-1h" | grep -c 'Invalid HTTP request received'
```

### What happens when a proxy joins the chain

Now the same script against nginx from
[Option B](#option-b-terminate-in-front-and-tell-nautilus-who-did-it), with
the `if ($http_transfer_encoding) { return 444; }` line commented out, so you
can see what the guard is for:

```console
$ python smuggle.py 8081          # nginx -> broker, no framing guard
  Content-Length + Transfer-Encoding     HTTP/1.1 400 Bad Request     requests_parsed=1
  two Content-Length headers             HTTP/1.1 400 Bad Request     requests_parsed=1
  Transfer-Encoding: chunked, identity   HTTP/1.1 501 Not Implemented requests_parsed=1
  Transfer-Encoding<SP>: chunked         HTTP/1.1 400 Bad Request     requests_parsed=1
  bare-LF chunk terminator               HTTP/1.1 401 Unauthorized    requests_parsed=2
```

**The last row is a real disagreement, and it is measured, not theorised.**
`0\n\n` — a chunked terminator ended with bare LFs instead of CRLFs — is a
protocol error to uvicorn and a valid terminator to nginx. nginx therefore reads
the tail as a second request and sends it on. The broker's access log shows both
arriving:

```console
$ journalctl -u nautilus --since "-1m" | tail -2
INFO:     127.0.0.1:52226 - "POST /v1/request HTTP/1.1" 401 Unauthorized
INFO:     127.0.0.1:52240 - "GET /admin/audit HTTP/1.1" 401 Unauthorized
```

`GET /admin/audit` was never written by a client that nginx's `location /admin/`
block would have seen as such — it came out of the body of a `POST /v1/request`.
Two things keep this from being a working exploit in *this* chain and both are
accidents you should not rely on: nginx opened a fresh upstream connection for
the second request (`:52226` and `:52240` are different sockets), and the broker
authenticates every request independently, so the smuggled one got its own 401.
Put a CDN, a service mesh sidecar or a second load balancer in front of nginx —
any hop that reads `0\n\n` the way uvicorn does, as *one* request — and the two
views diverge with nothing in between to notice.

### Closing it

One line, in the vhost, and it closes the class rather than the case:

```nginx
if ($http_transfer_encoding) { return 444; }
```

`444` and not `400`: a `400` still leaves nginx holding a connection whose
buffer contains the trailing bytes, and it parses them. `444` closes the
connection without a response, so there is nothing left to re-read.

```console
$ python smuggle.py 8081          # the same nginx, guard restored
  Content-Length + Transfer-Encoding     HTTP/1.1 400 Bad Request     requests_parsed=1
  two Content-Length headers             HTTP/1.1 400 Bad Request     requests_parsed=1
  Transfer-Encoding: chunked, identity   HTTP/1.1 501 Not Implemented requests_parsed=1
  Transfer-Encoding<SP>: chunked         HTTP/1.1 400 Bad Request     requests_parsed=1
  bare-LF chunk terminator               (closed, no response)        requests_parsed=0

$ journalctl -u nautilus --since "-1m" | grep -c 'GET /admin/audit'
0
```

`requests_parsed=0` and nothing in the broker's log.

**The guard is an HTTP/1.1 control and only fires there**, because
`$http_transfer_encoding` is a request header and HTTP/2 has none — h2 frames a
body in DATA frames and nginx re-frames it to HTTP/1.1 upstream with a
`Content-Length` it computed itself, so there is nothing for two parsers to
disagree about. Same request, two protocol versions:

```console
$ curl -sk --http1.1 -o /dev/null -w '%{http_code}\n' -X POST \
    https://nautilus.example.com:8443/v1/request -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    -H 'Transfer-Encoding: chunked' -H 'Content-Type: application/json' --data-binary '{}'
000
$ curl -sk --http2 -o /dev/null -w '%{http_code}\n' -X POST \
    https://nautilus.example.com:8443/v1/request -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    -H 'Transfer-Encoding: chunked' -H 'Content-Type: application/json' --data-binary '{}'
422
```

`000` is curl reporting a closed connection with no response — the guard. `422`
is the broker validating an empty body, which means the request reached it: over
h2 the header was never a framing instruction and was dropped before nginx saw
it. So when you test this control, force `--http1.1`, or you will test nothing.

Refusing chunked outright costs you nothing here: every Nautilus route takes a small JSON body, no route
accepts a stream or an upload, and `curl`, `httpx` and `requests` all send
`Content-Length` for a `-d`/`json=` body. If some client of yours does chunk,
you will find out immediately — it gets a closed connection, not a silent
truncation.

### The other half of framing: one length limit, one number

`api.max_request_bytes` and the proxy's `client_max_body_size` are two
components deciding the same question, and if they differ the smaller one
answers first with a message the other end never sees. Set them to the same
integer — the config default is `1048576`, so the nginx line is
`client_max_body_size 1048576;` and not `1m`, which is the same number written
in a way that hides the comparison.

```console
$ python -c "import json; print(json.dumps({'agent_id':'reporting','intent':'x'*1100000}))" \
    > /tmp/big.json

$ curl -s -X POST -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    -H 'Content-Type: application/json' --data-binary @/tmp/big.json \
    http://127.0.0.1:8000/v1/request -w ' [%{http_code}]\n'
{"detail": "Request body is 1100040 bytes; this broker accepts at most 1048576 (api.max_request_bytes)."} [413]

$ curl -sk -w ' [%{http_code}]\n' -X POST \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    --data-binary @/tmp/big.json https://nautilus.example.com:8443/v1/request
<html>
<head><title>413 Request Entity Too Large</title></head>
<body>
<center><h1>413 Request Entity Too Large</h1></center>
<hr><center>nginx/1.27.5</center>
</body>
</html>
 [413]
```

Same status at both hops, from different components — which is the point of
setting the two limits to the same integer. Raise `api.max_request_bytes` and
forget `client_max_body_size` and the proxy starts refusing bodies the broker
would have accepted, with the HTML above instead of the JSON string your callers
parse, and with no Nautilus log line and no audit entry to explain it.

## Log injection: what the two log formats escape

A log line is a record until something else writes into it. If a value a caller
or an operator controls reaches a log line with a newline in it, whoever wrote
that value chose the text of the *next* line — and the next line is what your
SIEM alerts on, what an auditor reads, and what a responder believes.

Nautilus writes to two places and they have opposite properties.

### The audit trail encodes, and cannot be made not to

`audit.jsonl` is one JSON object per line, written by
`json.dumps(payload, separators=(",", ":"))` in
`nautilus/audit/logger.py`. `json.dumps` escapes U+000A as the two characters
`\n` inside the string, so a newline in an intent, an agent id or a session id
cannot become a line. Count lines before and after, with the newline injected
into the `session_id` a caller declares:

```console
$ wc -l < /tmp/session-lab/audit.jsonl
4
$ for i in 1 2 3; do
    curl -s -o /dev/null -X POST http://127.0.0.1:8000/v1/request \
      -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
      --data-binary "{\"agent_id\":\"reporting\",\"intent\":\"list customers\",\"context\":{\"session_id\":\"inj$i\\n{\\\"decision\\\":\\\"allow\\\"}\"}}"
  done
$ wc -l < /tmp/session-lab/audit.jsonl
10
```

Three requests, two records each, six lines. Not seven, not nine. The newline is
in the file, as the two characters `\` and `n`, and not as a line break:

```console
$ grep -cP 'inj1\n' /tmp/session-lab/audit.jsonl     # a real U+000A
0
$ grep -Fc 'inj1\n' /tmp/session-lab/audit.jsonl     # a backslash and an n
2
```

It round-trips, too — the value is preserved exactly, it is simply not
line-structured:

```console
$ python -c 'import json
for line in open("/tmp/session-lab/audit.jsonl"):
    sid = json.loads(line)["session_id"]
    if "\n" in str(sid):
        print(repr(sid)); break'
'inj1\n{"decision":"allow"}'
```

This is not configurable and does not need to be. `AuditConfig` has three keys
— `path`, `chained`, `checkpoint_interval` — and none of them is a format, so
there is no way to ask for an unescaped audit line.

### The application log encodes too, in both formats

`--log-format json` installs `JsonFormatter` from
`nautilus/observability/logging.py`, which builds a dict and calls
`json.dumps` on it. `--log-format text` — the default — installs
`TextFormatter` from the same module: `logging.BASIC_FORMAT`, the layout
`logging.basicConfig()` would have given, with every C0 control character and
DEL rendered as its escape sequence before the record is written. A newline
becomes the two characters `\n`; `\r`, which would let a value overwrite the
line a terminal already drew, and `\x1b`, which starts an ANSI sequence, go the
same way. The same record, both ways:

```console
$ python - <<'PY'
import json, logging
from nautilus.observability.logging import JsonFormatter, TextFormatter
rec = logging.LogRecord("nautilus.core.broker", logging.INFO, __file__, 1,
    "request from agent %s",
    ("alice\nWARNING:nautilus.core.broker:escalation approved",), None)
text = TextFormatter().format(rec)
line = JsonFormatter().format(rec)
print("text ->", len(text.splitlines()), "line")
print("json ->", len(line.splitlines()), "line")
print("json msg round-trips:", json.loads(line)["msg"] == rec.getMessage())
PY
text -> 1 line
json -> 1 line
json msg round-trips: True
```

Escaping is applied to the interpolated message only, so a traceback attached
by `log.exception` is still a readable multi-line traceback — it is generated
from the interpreter's own frames, not from anybody's input.

Here is the product doing it, from its own startup path, with nothing staged.
`nautilus/core/broker.py:1056` logs the config path when no `agents:` block is
declared, and a path is a filename, and a filename may contain a newline:

```console
$ mkdir -p /tmp/naut-inject
$ F=$'/tmp/naut-inject/naut\nWARNING:nautilus.core.broker:audit chain verified OK.yaml'
$ cp /etc/nautilus/nautilus.yaml "$F"
$ nautilus serve --config "$F" 2>&1 | grep -A1 "No 'agents:'"
WARNING:nautilus.core.broker:No 'agents:' are declared in '/tmp/naut-inject/naut\nWARNING:nautilus.core.broker:audit chain verified OK.yaml', so every request declares its own clearance, compartments and purpose and the broker enforces them against the sources it knows. Declare agents to turn enforcement on.
INFO:nautilus.core.broker:discovered adapter entry-point 'influxdb' -> InfluxDBAdapter (from 'nautilus-rkm')
```

The whole warning is one record, and the line `grep -A1` printed after it is the
next thing the broker logged — adapter discovery — not the second half of this
one. Before this release the same command emitted two `WARNING` records and the
second read as Nautilus asserting that the audit chain had verified:

```text
WARNING:nautilus.core.broker:No 'agents:' are declared in /tmp/naut-inject/naut
WARNING:nautilus.core.broker:audit chain verified OK.yaml, so every request declares its own clearance, ...
```

JSON says the same thing, with the newline escaped by `json.dumps` instead:

```console
$ nautilus serve --config "$F" --log-format json 2>&1 | grep "No 'agents:'"
{"ts": "2026-09-01T14:07:35.275115+00:00", "level": "WARNING", "logger": "nautilus.core.broker", "module": "broker", "msg": "No 'agents:' are declared in '/tmp/naut-inject/naut\\nWARNING:nautilus.core.broker:audit chain verified OK.yaml', so every request declares its own clearance, compartments and purpose and the broker enforces them against the sources it knows. Declare agents to turn enforcement on."}
```

**Run production with `--log-format json` anyway.** Not because `text` leaks —
it no longer does — but because the JSON lines carry `extra={...}` fields as
top-level keys, and a SIEM can index those. Both formats are now safe to read;
only one is safe to *query*.

### The three layers, and what each one is for

The formatter is the layer that covers every call site, including the ones
nobody has written yet. Two more sit in front of it, because a formatter is
process-wide configuration and an embedder of the library may not install one.

**1. The character set of an identifier is bounded where it is read.**
`SourceConfig.id` carries `pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"`. A source id
is interpolated into log lines, becomes the OpenTelemetry span name
`adapter.<id>`, and is the `{name}` segment of `GET /v1/adapters/{name}/schema`;
one pattern covers all three and everything added later.

```console
$ nautilus serve --config /tmp/badid.yaml
ERROR: invalid config: Config validation failed:
  sources.0.id: String should match pattern '^[A-Za-z0-9][A-Za-z0-9._-]*$' [type=string_pattern_mismatch]
```

The anchors are exact, not lenient: `"customers\n"` — a *trailing* newline — is
refused as well, which is the case a Python `re`-style `$` would have let
through.

`agents[].id` is deliberately *not* constrained. It reaches no `%s`, no span
name and no path segment; adding a pattern there would break an existing config
on upgrade to close nothing. If you want the same discipline anyway, that is
your `agents:` block and your change review.

**2. No logging call hand-rolls `repr()`.** Every site that had this defect had
the same shape — a value wrapped in literal single quotes and interpolated with
`%s`:

```python
log.warning("schema fetch failed for adapter '%s'; skipping ...", source_id)
```

`'%s'` produces the quotes but not the escaping, which is the half that matters.
`%r` produces both, and for a well-formed identifier the emitted string is
byte-identical: `repr("vuln_db")` is `'vuln_db'`. Every one of them now reads
`%r`, and the rule is enforced rather than reviewed —
`tests/defects/test_wave_e27.py::test_e27_no_logging_call_hand_rolls_repr_with_quoted_percent_s`
walks the AST of every module under `nautilus/` and fails on any logging format
string containing `'%s'`. There is no case where `'%s'` is the right answer, so
it is a rule and not a judgement.

You can run the same shape yourself over the values a *caller* controls, which
have always been `%r`:

```python
# logscan.py -- every logging call carrying caller- or config-supplied text,
# and the conversion it uses. %r is repr(), which escapes CR and LF.
import ast, pathlib, re, sys

CARRIED = ("agent_id", "purpose", "session_id", "user", "reviewer", "intent",
           "subject", "rule_name", "proposal_id", "request_id", "source_id")
LOGGERS = {"log", "logger", "LOG", "_log"}
LEVELS = {"debug", "info", "warning", "error", "exception", "critical"}

bad = 0
for path in sorted(pathlib.Path("nautilus").rglob("*.py")):
    for node in ast.walk(ast.parse(path.read_text())):
        fn = getattr(node, "func", None)
        if not (isinstance(node, ast.Call) and isinstance(fn, ast.Attribute)
                and fn.attr in LEVELS and isinstance(fn.value, ast.Name)
                and fn.value.id in LOGGERS and node.args):
            continue
        args = [ast.unparse(a) for a in node.args[1:]]
        if not any(c in a for a in args for c in CARRIED):
            continue
        fmt = node.args[0]
        if not isinstance(fmt, ast.Constant):
            print(f"UNSAFE {path}:{node.lineno} non-literal format string")
            bad += 1
            continue
        convs = re.findall(r"%[-#0 +]*[\d.*]*[a-zA-Z]", fmt.value)
        for conv, arg in zip(convs, args, strict=False):
            if not any(c in arg for c in CARRIED):
                continue          # a count, a fingerprint, a class name
            bad += conv != "%r"
            print(f"{'UNSAFE' if conv != '%r' else 'ok    '} {path}:{node.lineno} {conv} on {arg}")
print(f"\n{bad} unescaped interpolations")
sys.exit(1 if bad else 0)
```

```console
$ python logscan.py
ok     nautilus/core/broker.py:601 %r on request_id
ok     nautilus/core/broker.py:2642 %r on state.request_id
ok     nautilus/core/broker.py:2642 %r on state.intent_analysis.raw_intent
ok     nautilus/core/broker.py:2642 %r on state.intent_analysis.data_types_needed
ok     nautilus/core/broker.py:3111 %r on record.source_id
ok     nautilus/core/broker.py:3208 %r on source_id
ok     nautilus/core/broker.py:3432 %r on agent_id
ok     nautilus/core/broker.py:3432 %r on state.session_id
ok     nautilus/core/broker.py:3432 %r on purpose
ok     nautilus/core/broker.py:3759 %r on source_id
ok     nautilus/core/broker.py:4007 %r on source_id
ok     nautilus/core/broker.py:2657 %r on state.request_id
ok     nautilus/core/broker.py:2657 %r on source_id
ok     nautilus/core/broker.py:3420 %r on agent_id
ok     nautilus/core/broker.py:3420 %r on purpose
ok     nautilus/core/broker.py:2155 %r on receiving_agent_id
ok     nautilus/core/broker.py:2155 %r on session_id
ok     nautilus/core/broker.py:2989 %r on state.request_id
ok     nautilus/core/broker.py:2989 %r on source_id
ok     nautilus/core/broker.py:3012 %r on state.request_id
ok     nautilus/core/broker.py:3012 %r on source_id
ok     nautilus/core/broker.py:3739 %r on source_id
ok     nautilus/transport/auth.py:287 %r on user

0 unescaped interpolations
$ echo $?
0
```

Run it from the repository root; the paths are relative to it. Twenty-three
rows, every one of them `%r`, `0 unescaped interpolations`, exit `0`.
`auth.py:287` logs the `X-Forwarded-User` header a proxy sent;
`broker.py:3420` logs the `agent_id` and `purpose` out of a request body; `broker.py:2155` logs a handoff's `agent_id` and `session_id`,
also from the body; the `broker.py` `source_id` rows are the per-source
failure, schema-fetch, drift, quarantine-lift and truncation sites plus the
`--log-level debug` routing and dial records; `broker.py:3432` is the
`debug`-level session-token mint line.

`broker.py:601` is the broker-level failure record. Its `request_id` is the
`uuid4()` minted in `_new_request_state`, so no caller can put a byte in it —
and it is `%r` anyway, because the scan matches on argument *names* and a rule
that has to be argued with at one call site is a rule that gets lost at the
next one. The cost of the convention is nothing: `repr()` of a uuid4 string is
the same characters inside quotes.

Neither layer is the only one. `%r` escapes the value at the call site;
`TextFormatter` escapes C0 controls and DEL out of the whole interpolated
message afterwards, so a value that reaches a `%s` — a `data_types` entry
quoted into a `debug` skip reason, say — is still one record. Confirm the
caller-facing half against a live broker rather than reading the source — send
a purpose with a newline in it and count lines:

```console
$ curl -s -o /dev/null -X POST http://127.0.0.1:8000/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    --data-binary '{"agent_id":"reporting","intent":"list customers","context":{"purpose":"nope\nWARNING:root:FORGED"}}'
$ journalctl -u nautilus --since "-1m" | grep -c FORGED
1
```

One line, not two — the `\n` in that output is the two characters `repr()`
wrote:

```text
WARNING:nautilus.core.broker:not minting a session token for agent 'reporting': purpose 'nope\nWARNING:root:FORGED' is not one it may claim, and the request will be denied on that ground
```

Two paths need no layer at all, so you do not re-test them: uvicorn's access log
percent-encodes the request target, so a newline in a path never reaches the
line —

```console
$ curl -s -o /dev/null --path-as-is \
    "http://127.0.0.1:8000/v1/audit%0aWARNING:root:FORGED" \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING"
$ journalctl -u nautilus --since "-1m" | tail -1
INFO:     127.0.0.1:51100 - "GET /v1/audit%0AWARNING%3Aroot%3AFORGED HTTP/1.1" 404 Not Found
```

— and `nautilus/ui/audit_reader.py:297` truncates a corrupt audit line to
`%.120s` before logging it, which bounds a hand-edited `audit.jsonl` on top of
the formatter escaping it.

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

Two reloads, no restart and no outage. `api.keys` is the one part of `api` a
running broker adopts on `SIGHUP`, and the auth guard resolves the list per
request, so the second reload retires the old credential on the very next call.

**Give the entry a `principal` first.** The exposure ledger and session
ownership are keyed by the caller's authenticated identity, and with no
`principal` set that identity is the secret — so the rotation below would hand
the caller a clean cumulative-exposure budget and lock it out of the sessions it
already opened. See [`api.keys[].principal`](#apikeysprincipal). Adding one is
itself a reload; do it while the ledger is cold, because nothing carries the old
ledger onto the new name.

```bash
# 0. Once, before your first rotation: name the caller, so a key change is a
#    key change and not a new principal.
#    api:
#      keys:
#        - {key: "${NAUTILUS_KEY_REPORTING}", principal: reporting-service,
#           agent_id: reporting, capabilities: [query]}
sudo systemctl reload nautilus

# 1. Mint the replacement.
export NAUTILUS_KEY_REPORTING_NEW="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
# 2. Add it alongside the old one, under the SAME principal, and reload —
#    both are now valid and both accumulate into one ledger.
#    api:
#      keys:
#        - {key: "${NAUTILUS_KEY_REPORTING}",     principal: reporting-service, agent_id: reporting, capabilities: [query]}
#        - {key: "${NAUTILUS_KEY_REPORTING_NEW}", principal: reporting-service, agent_id: reporting, capabilities: [query]}
sudo systemctl reload nautilus
# 3. Move callers to the new value, confirm the old one is unused in your logs.
# 4. Remove the old entry and reload again.
sudo systemctl reload nautilus
# 5. Confirm the old key is dead — on the running process, with no restart.
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://nautilus.example.com/v1/request \
  -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
  -d '{"agent_id":"reporting","intent":"list customers","context":{}}'
# expect: 401
```

`systemctl reload` needs `ExecReload=/bin/kill -HUP $MAINPID` in the unit — see
[Start it](#start-it). A refused reload changes nothing and says why; the
credential in force is the one from before the signal, never a half-applied
list. Under `--transport both` the MCP port re-reads the same list on the same
signal, so a retired key is retired on both doors at once.

**An emergency revocation is step 4 alone.** Drop the compromised entry, reload,
and it is refused on the next request. Under a stable `principal` the ledger
that credential built up stays with the caller, which is what you want when the
question is what the compromised key had already reached.

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
  enabled: false                   # second front door; the cookie holds an API key

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
# The config reload. systemd expands $MAINPID to this service's own main
# process, which is the only way to reach it exactly: a host that also runs the
# container image has a second process whose command line contains
# `nautilus serve`. Without this line `systemctl reload nautilus` fails with
# "Job type reload is not applicable for unit nautilus.service".
ExecReload=/bin/kill -HUP $MAINPID
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

# --- what the proxy must add ---
# The two cache-control checks pass against a bare broker too: Nautilus sets
# that header itself. Every other check below FAILS against a bare broker and
# passes behind the vhost in "Option B" -- those measure the proxy, not the
# application. Keeping the cache-control pair here is deliberate: it catches a
# proxy that strips or rewrites the upstream header on its way out.
PLAIN="${PLAIN:-${BASE/https:/http:}}"
h() { curl -sk -D- -o /dev/null "${@:2}" | tr -d '\r' \
      | awk -v k="$1:" 'tolower($1)==tolower(k){$1="";sub(/^ /,"");print}' ; }

chk "audit responses are uncacheable" "no-store" \
  "$(h cache-control "$BASE/v1/audit" -H "X-API-Key: $KEY")"
chk "console responses are uncacheable" "no-store" \
  "$(h cache-control "$BASE/admin/audit" -H "X-API-Key: $KEY")"
chk "HSTS is set" "max-age=63072000; includeSubDomains" \
  "$(h strict-transport-security "$BASE/v1/audit" -H "X-API-Key: $KEY")"
chk "sniffing is off" "nosniff" \
  "$(h x-content-type-options "$BASE/v1/audit" -H "X-API-Key: $KEY")"
chk "JSON responses are JSON" "application/json" \
  "$(h content-type "$BASE/v1/audit" -H "X-API-Key: $KEY")"
chk "console HTML declares utf-8" "text/html; charset=utf-8" \
  "$(h content-type "$BASE/admin/login")"
chk "no CORS is advertised" "" \
  "$(h access-control-allow-origin "$BASE/v1/audit" \
       -H "X-API-Key: $KEY" -H 'Origin: https://evil.example')"
chk "the API does not redirect plaintext to TLS" "" \
  "$(h location "$PLAIN/v1/audit")"
chk "the console does redirect plaintext to TLS" "301" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$PLAIN/admin")"
chk "chunked bodies are refused at the edge" "000" \
  "$(curl -sk --http1.1 -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/request" \
       -H "X-API-Key: $KEY" -H 'Transfer-Encoding: chunked' \
       -H 'Content-Type: application/json' --data-binary '{}' 2>/dev/null)"

# --ssl-ciphers / ssl_ciphers, measured rather than read out of the config file.
if command -v nmap > /dev/null 2>&1; then
  if nmap --script ssl-enum-ciphers -p 443 "${BASE#https://}" 2>/dev/null \
     | grep -q 'TLS_RSA_WITH'; then
    echo "FAIL ciphers: a suite without forward secrecy is enabled"; fail=1
  else
    echo "ok   no static-RSA suite is enabled"
  fi
else
  echo "SKIP ciphers: nmap is not installed, so this control is unverified"
fi

echo "--- the application log must be structured, or a newline can forge a line:"
journalctl -u nautilus --since "-1h" -n 1 -o cat | grep -q '^{"ts":' \
  && echo "ok   --log-format json is in force" \
  || { echo "FAIL log format: run nautilus serve --log-format json"; fail=1; }

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
| `{"detail":"Invalid session token: broker_instance_mismatch"}` (401) | token minted by a different `broker_instance_id` | align the id across the deployment's replicas |
| `{"detail":"Invalid session token (agent_mismatch): session token was minted for agent '...', presented by '...'"}` (401) | a valid token presented by another agent | use the token minted for the agent you are asking as |
| `{"detail":"session_not_yours: session '...' belongs to another principal."}` (403) | a caller named a `session_id` opened by a different credential | use your own session id, or have its owner declare a handoff |
| `{"detail":"kid '...' is the current primary; rotate first, then revoke"}` (409) | `nautilus key revoke` aimed at the live signing key | `nautilus key rotate --yes` first, then revoke the rotated-out kid |
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
| `Invalid HTTP request received.` (400, `text/plain`) | uvicorn's parser rejected the framing — duplicate `Content-Length`, `Content-Length` with `Transfer-Encoding`, or a malformed chunk terminator. Not a Nautilus string and never reaches the audit trail | see [Message framing](#message-framing-every-hop-must-count-the-body-the-same-way); if it is not an attack, a client is speaking HTTP badly |
| `{"detail":"Plaintext HTTP is not accepted on /v1/. ...}` (403) | **the proxy's**, from [Option B](#option-b-terminate-in-front-and-tell-nautilus-who-did-it) — an agent sent a request to port 80 | the credential is already disclosed: rotate it, then fix the client's base URL |

## Four controls Nautilus does not implement

An operator hardening this deployment against a control catalogue will reach
four requirements this software has no surface for at all. The honest answer to
each is the same shape: **the control is not implemented**, here is the command
that proves it, here is what the deployment boundary can be made to do instead,
and here is the part that still is not covered. Nothing below is a feature.

Each subsection names its OWASP ASVS 5.0 identifier, because that is the
catalogue most readers arrive with; the wording is the requirement's, the
verdicts are ours.

### V6.3.3 — multi-factor authentication

*The requirement:* a multi-factor mechanism, or a combination of single-factor
mechanisms, must be used to access the application.

**Not implemented.** There is one factor, and it is a bearer secret. Nautilus
contains no second-factor code of any kind — no TOTP, no WebAuthn, no
out-of-band challenge, and no notion of a factor at all:

```console
$ grep -rniE 'totp|webauthn|fido|\bmfa\b|multi.?factor|otpauth|u2f' nautilus/ | wc -l
0
```

Nor can it consume somebody else's. An OIDC provider reports what it did in the
`amr` / `acr` / `auth_time` claims; Nautilus reads none of them, because it
never sees a token from a provider:

```console
$ grep -rnE '\bamr\b|\bacr\b|auth_time' nautilus/ --include='*.py' | wc -l
0
```

**What Nautilus has instead** is one credential, checked one way, in whichever
mode you run:

- `api.auth.mode: api_key` — an opaque secret in `X-API-Key`, compared against
  `api.keys` in constant time (`nautilus/transport/auth.py:73`). Whoever holds
  the string is the caller. The admin console is the same secret in a form
  field: `nautilus/ui/templates/pages/login.html:92` is an
  `<input type="password">` whose value is an API key, exchanged for a cookie
  that *is* the key.
- `api.auth.mode: proxy_trust` — Nautilus authenticates nobody. It reads the
  subject your ingress already resolved out of `X-Forwarded-User`
  (`nautilus/transport/auth.py:243`).

**What compensates**, and only in the second mode: put an authenticating proxy
in front and make it the only reachable peer. The factors then live in the
proxy, where they can be as many as your IdP enforces, and Nautilus never
handles a credential at all. This is a real boundary, not a gesture — under
`proxy_trust` an API key buys nothing on any route that returns data. Confirm it
on your own deployment rather than taking the mode's name for it:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST https://nautilus.example.com/v1/request \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list orders","context":{}}'
401
$ curl -s -X POST https://nautilus.example.com/v1/request \
    -H "X-API-Key: $NAUTILUS_KEY_REPORTING" -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list orders","context":{}}'
{"detail":"Missing X-Forwarded-User"}
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST https://nautilus.example.com/v1/request \
    -H 'X-Forwarded-User: spiffe://idp-a.example/ns/agents/sa/alice' \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list orders","context":{}}'
200
```

A valid API key answering `401 Missing X-Forwarded-User` is the check that
matters. It says the proxy is the only authenticator, which is the whole claim.

Two things this does **not** cover, and both are load-bearing:

1. **Nautilus cannot tell whether the proxy asked for a second factor.** It
   receives a subject string and nothing else — no `amr`, no `acr`, no
   authentication timestamp. If your ingress is configured to let some route or
   some client past with one factor, Nautilus will serve it exactly like any
   other. The control is enforced entirely in a component this page does not
   configure; verify it there.
2. **`POST /admin/login` still validates an API key in `proxy_trust` mode.** It
   calls `verify_api_key` unconditionally (`nautilus/ui/router.py:194`), so
   it answers `302` for a correct key and `401` for a wrong one even when no key
   authorises anything — a live oracle for guessing `api.keys`, with no rate
   limit in front of it. The cookie it hands back opens nothing, which is the
   only reason this is a nuisance rather than a hole:

   ```console
   $ curl -s -o /dev/null -w '%{http_code}\n' -X POST https://nautilus.example.com/admin/login \
       -d "api_key=$NAUTILUS_KEY_REPORTING"
   302
   $ curl -s -b "nautilus_key=$NAUTILUS_KEY_REPORTING" https://nautilus.example.com/admin/sources
   {"detail":"Missing X-Forwarded-User"}
   ```

   Under `proxy_trust`, set `ui.enabled: false`, or block `/admin/login` at the
   proxy the same way [the private surface](#keep-the-private-surface-off-the-public-listener)
   is blocked.

In `api_key` mode nothing compensates. One factor is the whole authentication
story, and the mitigations available to you are the ones on this page already:
one key per caller ([`api.keys`](#apikeys)), [scoped
capabilities](#apikeyscapabilities), [agent binding](#apikeysagent_id), and
[rotation](#rotate-and-revoke).

### V6.8.1 — restricting which identity provider may assert an identity

*The requirement:* where an application supports multiple identity providers, a
user's identity must not be spoofable via another supported provider — the
standard mitigation being to namespace the user's ID with the IdP's ID.

**Not implemented.** Nautilus integrates with no identity provider, so it has no
notion of *which* one asserted anything. Under `proxy_trust` the entire assertion
is one opaque string:

```console
$ grep -rniE 'oidc|saml|oauth|openid|id_token' nautilus/ --include='*.py'
nautilus/transport/auth.py:9:  (mTLS, SPIFFE, OIDC) and forwards its identity in ``X-Forwarded-User``.
nautilus/transport/auth.py:247:    mesh/ingress has already authenticated the caller (mTLS, SPIFFE, OIDC) and
nautilus/config/models.py:242:    # id, an OIDC subject, a certificate CN. Matched against ``X-Forwarded-User``
```

Three comments, no implementation. Every one of them describes something the
*proxy* does.

**What Nautilus has instead** is two flat lookups, neither of which knows about
issuers:

- `api.auth.trusted_proxies` — a list of CIDR blocks. A socket peer inside **any**
  block may assert **any** subject (`nautilus/transport/auth.py:226`). There is
  no per-proxy subject allowlist, so front the broker with two proxies and
  either one can assert the other's identities.
- `agents.<id>.subject` — a `dict[subject → agent_id]` built by
  `nautilus/transport/fastapi_app.py:167-172`. The key is the raw header value.

Both properties are visible from one host. Two agents bound to two subjects that
differ only in their namespace, and a single peer asserting each in turn:

```yaml
agents:
  reporting:
    id: reporting
    clearance: confidential
    subject: "spiffe://idp-a.example/ns/agents/sa/alice"
  finance:
    id: finance
    clearance: secret
    subject: "spiffe://idp-b.example/ns/agents/sa/alice"
api:
  auth:
    mode: proxy_trust
    trusted_proxies: ["127.0.0.1/32"]
```

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H 'X-Forwarded-User: spiffe://idp-a.example/ns/agents/sa/alice' \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list orders","context":{}}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["outcome"])'
allowed
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H 'X-Forwarded-User: spiffe://idp-b.example/ns/agents/sa/alice' \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"finance","intent":"list orders","context":{}}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["outcome"])'
allowed
```

The same client was `alice` at two providers, in the same second, because
nothing binds a subject to the peer that may assert it.

**What compensates** is the mitigation the requirement itself names, done by
you: **make the namespace part of the subject string.** A SPIFFE ID already
carries one — the trust domain, `idp-a.example` above — and an OIDC deployment
should prefix the subject with the issuer. Two providers then cannot collide,
because the strings differ. Nautilus enforces none of this; it only compares
strings, so the separation is exactly as good as the strings your proxy emits.

Two checks make that auditable. First, that every declared subject is namespaced
and that no two agents share one — a duplicate is silently resolved by config
order, not refused:

```console
$ python - <<'EOF'
import collections, sys, yaml
agents = yaml.safe_load(open("/etc/nautilus/nautilus.yaml"))["agents"]
subjects = {a: r.get("subject") for a, r in agents.items()}
bare = [a for a, s in subjects.items() if s and "://" not in s and "/" not in s]
dupes = [s for s, n in collections.Counter(filter(None, subjects.values())).items() if n > 1]
print("un-namespaced subjects:", bare or "none")
print("subjects claimed twice:", dupes or "none")
sys.exit(1 if bare or dupes else 0)
EOF
un-namespaced subjects: none
subjects claimed twice: none
```

A duplicate is not hypothetical arithmetic. `subjects[subject] = agent_id`
overwrites, so the last agent in file order wins and the earlier one becomes
unreachable — with no startup warning and no config error. Give both agents
above the *same* subject and `reporting` disappears:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request \
    -H 'X-Forwarded-User: spiffe://idp-a.example/ns/agents/sa/alice' \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"reporting","intent":"list orders","context":{}}'
{"detail":"This credential is bound to agent_id='finance', so it cannot ask as 'reporting'"}
```

Second, that the proxy cannot be bypassed — the `V6.3.3` check above, which is
the same check, because an attacker who can reach the port directly can assert
any subject in the file regardless of how well it is namespaced.

**What is still not covered:** a compromised or misconfigured proxy inside
`trusted_proxies` can assert every identity in the config, and nothing in the
audit trail records which proxy did. The `peer` field
(`nautilus/transport/auth.py:147`) holds the socket address, so a forensic
answer exists after the fact if your proxies have distinct addresses — but it is
not an authorization input, and the exposure ledger keys on the subject, not on
the pair.

### V8.1.2 — documented rules for field-level access

*The requirement:* authorization documentation must define read and write rules
at field level, based on the consumer's permissions and the resource's
attributes.

**Not implemented, because there are no field-level rules to document.** The
authorization model has four granularities and none of them is a field. This is
the whole of it:

| Granularity | Mechanism | Where |
|---|---|---|
| Route | `api.keys[].capabilities` — one of `query`, `audit_read`, `govern`, `keys` | [`api.keys[].capabilities`](#apikeyscapabilities) |
| Identity | `api.keys[].agent_id` binds a credential to exactly one agent | [`api.keys[].agent_id`](#apikeysagent_id) |
| Source | clearance vs `sources[].classification`, compartments, `allowed_purposes`, and any rule that emits a denial | [`agents`](#agents-who-the-credential-may-speak-for) |
| Row | `ScopeConstraint` — `(source_id, field, operator, value)`, compiled into the adapter's `WHERE` clause (`nautilus/core/models.py:95-108`) | [`sources`](#sources-what-the-broker-holds-credentials-for) |

Note the fourth row carefully, because it is the one that looks like a
field-level control and is not. A scope constraint names a `field`, but it uses
it to choose **which rows** come back, never which columns. Nothing anywhere in
the model selects columns:

```console
$ grep -rniE 'allowed_fields|denied_fields|field_policy|projection|select_columns' nautilus/ | wc -l
0
```

**Writes do not exist at all.** No adapter emits an `INSERT`, `UPDATE`, `DELETE`
or `MERGE` — Nautilus reads from sources and never writes to them:

```console
$ grep -rniE '\b(INSERT INTO|UPDATE |DELETE FROM|MERGE INTO)\b' nautilus/adapters/ | wc -l
0
```

So the write half of this requirement has no surface. The read half has one, and
it is not restricted.

**What compensates:** put the projection where the columns are, in the source,
and let the source id be the unit of authorization Nautilus already understands.
A view that exposes only the permitted columns becomes a separate source with
its own `classification`, its own `data_types` and therefore its own routing and
denial rules — see [the next section](#v823-enforcing-field-level-access) for
the demonstration and the shape.

**What is still not covered:** the mapping from a consumer to a permitted set of
fields exists only as your discipline in maintaining one view per audience.
Nautilus will not detect that two sources overlap, will not warn that a caller
can reach both, and has nowhere to record the intent.

### V8.2.3 — enforcing field-level access

*The requirement:* field-level access must be restricted to consumers with
explicit permission to specific fields, to mitigate broken object property level
authorization (BOPLA).

**Not implemented on the read path.** Every adapter returns the whole record.
The query builders are three lines, and none of them projects:

| Adapter | What it asks for | Where |
|---|---|---|
| `postgres`, `pgvector` | `SELECT * FROM <table> [WHERE ...] LIMIT $n` | `nautilus/adapters/postgres.py:168` |
| `neo4j` | `MATCH (n:<label>) [WHERE ...] RETURN n LIMIT $L` | `nautilus/adapters/neo4j.py:303` |
| `elasticsearch` | the hit's entire `_source` document | `nautilus/adapters/elasticsearch.py:427-432` |

And the caller has no say either: `BrokerRequest` has four fields — `agent_id`,
`intent`, `context` and `fact_set_hash` (`nautilus/core/models.py:52-61`). None
of them is a field list.

Point a source at a table with a column nobody should see, and the column comes
back:

```yaml
sources:
  - id: employees
    type: postgres
    classification: confidential
    data_types: [hr]
    connection: "${HR_DSN}"
    table: employees
agents:
  agent-alpha:
    id: agent-alpha
    clearance: confidential
```

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"agent-alpha","intent":"list hr employees","context":{}}' \
  | python -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["data"], indent=2))'
{
  "employees": [
    {
      "id": 1,
      "name": "Ada Lovelace",
      "department": "engineering",
      "salary": "185000",
      "ssn": "123-45-6789"
    }
  ]
}
```

The request asked for employees. It received salaries and social security
numbers, because `SELECT *` is the only query the adapter knows how to write.

**What compensates:** a view. Do the projection in the database, where the
column names actually live, and give the result its own source id — which is a
unit Nautilus *does* authorize, with its own classification and its own routing:

```sql
CREATE VIEW employees_directory AS SELECT id, name, department FROM employees;

-- The role the directory source dials. Grant it the view and nothing else, so
-- the projection survives a mistake in the YAML.
CREATE ROLE hr_directory LOGIN PASSWORD '<HR_DIRECTORY_PASSWORD>';
GRANT CONNECT ON DATABASE lab TO hr_directory;
GRANT USAGE ON SCHEMA public TO hr_directory;
GRANT SELECT ON employees_directory TO hr_directory;
```

```console
$ psql "$HR_DIRECTORY_DSN" -c 'SELECT * FROM employees;'
ERROR:  permission denied for table employees
```

```yaml
sources:
  - id: employees
    type: postgres
    classification: confidential      # only cleared agents route here
    data_types: [hr]
    connection: "${HR_DSN}"
    table: employees
  - id: employees-directory
    type: postgres
    classification: cui               # the projection, at its own level
    data_types: [directory]
    connection: "${HR_DIRECTORY_DSN}" # a role with SELECT on the view only
    table: employees_directory
agents:
  agent-alpha:
    id: agent-alpha
    clearance: confidential
```

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"agent-alpha","intent":"list the employee directory","context":{}}' \
  | python -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d["data"], indent=2)); print(d["skip_records"])'
{
  "employees-directory": [
    {
      "id": 1,
      "name": "Ada Lovelace",
      "department": "engineering"
    }
  ]
}
[{'source_id': 'employees', 'reason': "no data type in common with the intent: source 'employees' offers ['hr'], the request needed ['directory']"}]
```

Two details make this a control rather than a rename. The `data_types` differ,
so the router picks one source or the other from the intent and reports the
other as skipped rather than silently including it. And `connection` names a
database role with `SELECT` on the view and nothing else — without that, a
`classification` in a YAML file is the only thing between the caller and the
base table, and a rule change or a routing surprise is enough to lose it.

**On the write path there is one field-level check, and it is hand-written.**
The transcript below needs
[`session_tokens.enabled: true`](#session_tokensenabled); on a default config
the route answers `409 session tokens are disabled`.
`POST /v1/sessions` takes an untyped body (`nautilus/transport/fastapi_app.py:939`),
and `clearance` in that body would be an authorization assertion signed by
Nautilus and verifiable by anyone against the public JWKS. It is not a parameter
of `Broker.issue_session_token` at all (`nautilus/core/broker.py:1611-1617`) —
the value comes from the agent registry, so the body cannot reach it:

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/sessions -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    -H 'Content-Type: application/json' \
    -d '{"session_id":"s1","agent_id":"agent-alpha","purpose":"support","clearance":"top-secret","is_admin":true}' \
  | python -c 'import json,sys; d=json.load(sys.stdin); d.pop("token"); print(json.dumps(d, indent=2))'
{
  "session_id": "s1",
  "agent_id": "agent-alpha",
  "purpose": "support",
  "clearance": "confidential",
  "issued_at": 1788276186,
  "expires_at": 1788279786,
  "broker_instance_id": "eff3658d-5ae2-4991-b9d7-b074c49b5623",
  "kid": "39a3b0f6-ca81-4ce0-90e4-e01e039a9b70"
}
```

`top-secret` in, `confidential` out. That is the control working — for the one
property somebody thought about. Note the other half of the same transcript:
`is_admin` was accepted without complaint, because the body is a bare
`dict[str, Any]` and unknown properties are dropped rather than refused. Only
`/v1/request` and `/v1/query` are strict, and they are strict because
`BrokerRequest` sets `extra="forbid"` (`nautilus/core/models.py:50`):

```console
$ curl -s -X POST http://127.0.0.1:8000/v1/request -H "X-API-Key: $NAUTILUS_KEY_REPORTING" \
    -H 'Content-Type: application/json' \
    -d '{"agent_id":"agent-alpha","intent":"list hr employees","context":{},"clearance":"top-secret"}'
{"detail":[{"type":"extra_forbidden","loc":["body","clearance"],"msg":"Extra inputs are not permitted","input":"top-secret"}]}
```

**What is still not covered:** every other `POST` body on the surface is a bare
`dict[str, Any]`, so the guarantee is "the handler reads the keys it names",
which is an audit of handlers rather than a schema. There is no per-consumer
field permission anywhere, and no rule engine reaches inside a returned row.

## What this does not give you

Named so you do not assume otherwise. The first four are the section above, in
one line each:

- **No multi-factor authentication, and no way to require one.** One bearer
  secret, or one forwarded subject. See
  [V6.3.3](#v633-multi-factor-authentication).
- **No identity-provider awareness.** `X-Forwarded-User` is a string; nothing
  records or restricts which proxy asserted it. See
  [V6.8.1](#v681-restricting-which-identity-provider-may-assert-an-identity).
- **No field-level authorization rules.** Source and row are the finest
  granularities the model has. See
  [V8.1.2](#v812-documented-rules-for-field-level-access).
- **No field-level enforcement.** `SELECT *`; put the projection in a view. See
  [V8.2.3](#v823-enforcing-field-level-access).
- **No credential that is hidden from the account running the process.**
  [`NAUTILUS_API_KEY`](#nautilus_api_key) keeps the key out of `argv`, where
  every local account could read it, and puts it in `/proc/<pid>/environ`, where
  the process's own user and root still can. There is no keyring integration, no
  credential file format, and no short-lived credential for the CLI to exchange
  for one — `api.keys` entries never expire.
- **No TLS.** There is no `api.tls` key and `nautilus serve` passes no TLS
  options. Terminate it yourself.
- **No rate limiting.** `api.max_concurrent_requests` bounds *concurrency*, not
  rate. A single caller can issue unlimited sequential requests.
- **No per-key rate or quota.** The exposure ledger accumulates by caller, but
  the ceiling is a policy rule you write, not a config key.
- **No secret manager integration.** `${VAR}` reads the process environment.
  Vault, KMS and CSI drivers all work — as long as they land the value in the
  environment before the broker starts.
- **No key expiry for API keys.** `api.keys` entries never expire. Nothing
  ages one out, warns that one is old, or tells you when one was last used;
  rotation is an operator action on a schedule you keep, run through
  [the procedure above](#the-api-keys).
- **No `Secure` cookie over plain HTTP.** The console cookie carries `Secure`
  only when the login arrived over TLS, directly or via `X-Forwarded-Proto:
  https`; over plain HTTP the attribute is omitted on purpose, because a browser
  silently drops a `Secure` cookie on an http:// origin. So `ui.enabled: true`
  without TLS puts an API key on the wire in clear.
- **No session limit and no session registry.** Nothing counts or caps a
  principal's concurrent sessions, nothing lists them, and there is no "sign out
  everywhere" — the closest thing is revoking the signing key. See
  [Sessions](#sessions-lifetime-parallelism-and-termination).
- **No inactivity timeout on a credential.** `session_store.ttl_seconds` idles
  out the exposure ledger, not the token; the token's only bound is the
  `expires_at` written at mint time.
- **No config hot-reload for anything on this page except the credentials.**
  `SIGHUP` reloads exactly `sources`, `rules`, `api.keys`,
  `session_store.lock_timeout_s` and `session_store.purpose_ttl_seconds`. Every
  other *security* key here — `api.auth.*`, `api.max_request_bytes`,
  `api.max_concurrent_requests`, `attestation.*`, `audit.*`,
  `session_tokens.*`, the rest of `session_store.*`, `agents`, `ui.*` — is read
  at startup and changing one means a restart. That is a property, not a gap:
  the audit sink and the attestation sink hold an exclusive `flock`, the key
  ring is already minting tokens, and the two ASGI limits are middleware
  objects rather than values anything re-reads. A reload that adopted them
  would leave one process describing a sink another process owns. The reload
  refuses such a file **whole** and names the key, so a half-applied security
  posture is not a state this broker can be in. See
  [Which keys reload, and which need a restart](operator-guide.md#which-keys-reload-and-which-need-a-restart).
- **No authentication on `/metrics` or `/v1/keys/jwks.json`.** Both are
  deliberate; scope `/metrics` at the proxy and leave JWKS public.
- **No response security headers other than `Cache-Control`.** Nautilus sends
  no `Strict-Transport-Security`, no `X-Content-Type-Options` and no
  `Access-Control-*` on any route, and there is no key that would add them —
  `grep -rn 'Strict-Transport\|nosniff\|Access-Control' nautilus/
  --include='*.py'` returns nothing. `Cache-Control` *is* set, on every
  response, and is not configurable; the rest belongs on the proxy. See
  [Response headers](#response-headers-byte-for-byte).
- **No HTTP→HTTPS redirect, and no HTTP listener to redirect from.** Which is
  correct for `/v1/` and has to be supplied for `/admin`; see
  [Which requests redirect to HTTPS](#which-requests-redirect-to-https-and-which-must-not).
- **No character restriction on `agents[].id`.** It is `id: str` with no
  pattern, unlike `sources[].id`. Nothing interpolates it into a text log, a
  span name or a path segment today, so it closes nothing to constrain it and
  would break configs on upgrade — but if you add a consumer that does, the
  pattern is yours to add. See
  [Log injection](#log-injection-what-the-two-log-formats-escape).

## See also

- [Operator Guide](operator-guide.md) — day-two operation.
- [Configure attestation](configure-attestation.md) — the signing path in depth.
- [Verify a token](verify-a-token.md) — checking a receipt offline.
- [REST API reference](../reference/rest-api.md) — every route and schema.
- [CLI reference](../reference/cli.md) — every subcommand and flag.
- [Errors reference](../reference/errors/index.md) — error codes and meanings.
- [The Trust Boundary](../concepts/trust-boundary.md) — why the broker holds the
  credentials.
