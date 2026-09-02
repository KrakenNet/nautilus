# Adapters and data sources

Two exception types cover almost everything here, and the difference matters:

- **`ScopeEnforcementError`** (`nautilus/adapters/base.py:42`) — the adapter **cannot honestly
  enforce** what policy asked for. It refuses instead of returning data it cannot vouch for.
  Every one of these is a refusal to over-return.
- **`AdapterError`** (`nautilus/adapters/base.py:38`) — the source itself failed: not connected,
  misconfigured, unreachable, or over a size ceiling.

`SSRFBlockedError` (`nautilus/adapters/rest.py:85`) and `EmbeddingUnavailableError`
(`nautilus/adapters/base.py:50`) are subclasses of `AdapterError`.

## Shared scope validation

Applied by every SQL-shaped adapter through `nautilus/adapters/base.py`.

### `Operator '{op}' not in allowlist: {sorted(_OPERATOR_ALLOWLIST)}`

`validate_operator`, `nautilus/adapters/base.py:184-187`. Rendered example:

```text
Operator 'DROP' not in allowlist: ['!=', '<', '<=', '=', '>', '>=', 'BETWEEN', 'IN',
'IS NULL', 'LIKE', 'NOT IN']
```

The allowlist is closed: an operator that is not on it is refused, never passed through. Fix the
`operator` in the rule or in `context.scope_constraints`.

### `Invalid field identifier '{f}'`

`validate_field`, `nautilus/adapters/base.py:197-200`. The field name does not match
`_FIELD_PATTERN`. Spaces, quotes, semicolons and parentheses are all rejected — the name is
interpolated into a query, so only identifier-shaped strings are allowed.

### `table name {table!r} has more than one schema qualifier`

`quote_table`, `nautilus/adapters/base.py:235-238`. At most one `.` is allowed:
`public.orders` is fine, `db.public.orders` is not.

### `Operator '{op}' requires a list value, got {type(bad).__name__}`

`IN` and `NOT IN` need a list. Raised by Elasticsearch (`:161`), Neo4j (`:130`) and REST
(`:188`); Postgres and InfluxDB spell it per operator, as `Operator 'IN' requires a list value,
got {type(value).__name__}` (`nautilus/adapters/postgres.py:130`,
`nautilus/adapters/influxdb.py:321`) and the `NOT IN` twin.

### `Operator 'IN' requires a list value, got {type(value).__name__}`

`nautilus/adapters/postgres.py:131` and `nautilus/adapters/influxdb.py:322`. The same refusal as
the generic one above, but with the operator baked into the literal, because these two adapters
build the `IN` clause themselves rather than going through the shared validator. `{type(value).__name__}`
is the Python type name of the offending value — `str`, `int`, `dict`. Grep for either spelling;
which one you get depends on the source type.

### `Operator 'NOT IN' requires a list value, got {type(value).__name__}`

`nautilus/adapters/postgres.py:139` and `nautilus/adapters/influxdb.py:329`. As above, for the
negated form. A `NOT IN` given a bare string is the more dangerous of the two: had it been
accepted it would have excluded nothing.

### `Operator 'LIKE' requires a string value, got {type(bad).__name__}`

`nautilus/adapters/elasticsearch.py:165`, `neo4j.py:134`, `rest.py:194`,
`postgres.py:146`, `influxdb.py:335`.

### `Operator 'BETWEEN' requires a 2-tuple/list value`

Raised twice per adapter — once when the value is not a sequence, once when it does not have
exactly two elements (`postgres.py:154`, `elasticsearch.py:170,175`, `neo4j.py:139,144`,
`rest.py:199,204`, `influxdb.py:288,341`).

### `operator not allowed: {op}`

`elasticsearch.py:371`, `neo4j.py:254,300`, `rest.py:377`. The final guard in an operator switch:
the operator passed the shared allowlist but this adapter has no translation for it.

### `Operator '{op}' unhandled in _build_sql`

`nautilus/adapters/postgres.py:162`. Same situation on the Postgres path.

```bash
python - <<'PY'
from nautilus.adapters.base import (
    ScopeEnforcementError, quote_table, validate_field, validate_operator,
)
for label, call in [
    ("operator", lambda: validate_operator("DROP")),
    ("field", lambda: validate_field("id; DROP TABLE t")),
    ("table", lambda: quote_table("db.public.orders")),
]:
    try:
        call()
    except ScopeEnforcementError as exc:
        print(f"[{label}] {exc}")
PY
```

## Lifecycle and connection

### `{Adapter}.execute called before connect()`

One per adapter, with the class name spelled out:
`PostgresAdapter.execute called before connect()` (`postgres.py:187`),
`ElasticsearchAdapter.execute called before connect()` (`elasticsearch.py:410`),
`Neo4jAdapter.execute called before connect()` (`neo4j.py:323`),
`InfluxDBAdapter.execute called before connect()` (`influxdb.py:375`),
`RestAdapter.execute called before connect()` (`rest.py:429`),
`PgVectorAdapter.execute called before connect()` (`pgvector.py:212`),
`S3Adapter.execute called before connect()` (`s3.py:188`),
`ServiceNowAdapter.execute called before connect()` (`servicenow.py:282`),
`LLMAdapter.execute() called before connect()` (`llm.py:187`),
`StaticAdapter.execute() called before connect()` (`static.py:90`) and
`StaticAdapter.get_schema() called before connect()` (`static.py:114`).
`S3Adapter is not connected` (`s3.py:305,343,377`) is the same condition on other S3 methods.

**Means.** The adapter was used before its connection was established. Through
`nautilus serve` this only happens when startup partially failed; when driving an adapter
directly, `await adapter.connect(config)` first.

### `{Adapter} failed to connect to source '{config.id}': {exc}`

`postgres.py:78`, `influxdb.py:235`. Sibling spellings for adapters that build a client rather
than a pool: `ElasticsearchAdapter failed to build client for source '{config.id}': {exc}`
(`elasticsearch.py:270`), `Neo4jAdapter failed to build driver for source '{config.id}': {exc}`
(`neo4j.py:218`), `RestAdapter failed to build client for source '{config.id}': {exc}`
(`rest.py:350`), `S3Adapter failed to create client for source '{config.id}': {exc}`
(`s3.py:152`), `ServiceNowAdapter failed to build client for source '{config.id}': {exc}`
(`servicenow.py:189`).

`{exc}` is the driver's own error — DNS failure, refused connection, bad credentials, TLS
mismatch. Read it first; Nautilus adds only the source id.

### `{type(self).__name__}: execute failed for source '{source_id}': {type(exc).__name__}[: {exc}]`

`wrap_execute`, `nautilus/adapters/base.py:438-442`. The uniform wrapper around a query that
raised. Rendered example:

```text
PostgresAdapter: execute failed for source 'vuln_db': UndefinedTableError:
relation "vulnerabilities" does not exist
```

The inner class name and message belong to the driver. **`: {exc}` is omitted entirely when the
driver's exception has no text** — `httpx.ReadTimeout()` and its siblings carry none, and
appending an empty one rendered `RestAdapter: execute failed for source 'catalog': ReadTimeout: `,
a sentence ending in a colon and nothing after it, which was the whole message an operator got for
a dead backend. The class name is now the last thing on the line:

```text
RestAdapter: execute failed for source 'catalog': ReadTimeout
```

Read the failing entry's `endpoint` for the address that timed out.

### `source '{source_id}' declares mTLS but its client certificate could not be loaded (cert_path={auth.cert_path!r}, key_path={auth.key_path!r}): {exc}`

`mtls_context`, `nautilus/adapters/base.py:287-293`. Both paths are echoed so you can see which
one the process actually read. `{exc}` is the `ssl` failure: a missing file, an encrypted key
with no passphrase, or a cert/key pair that does not match.

### `source type '{source_type}' needs its driver -- {install_extra_hint(extra)}`

`nautilus/adapters/__init__.py:49,66`, from the stand-in adapter registered when an optional
driver is unimportable. `connect()` adds the original cause:
`{hint} (import failed: {exc})` (`:58`). Configured sources normally hit the startup
`ConfigError` instead — see [config.md](config.md).

`{install_extra_hint(extra)}` is the shared two-route remedy clause described in
[index.md](index.md#reading-a-quoted-message); for `extra='s3'` the whole message reads:

```
source type 's3' needs its driver -- host: pip install 'nautilus-rkm[s3]'; image: docker build --build-arg EXTRAS="--extra s3" . (the published image installs --extra otel only, and has no shell or pip to add to it)
```

Run the `image:` half if you are on the container image: there is no `pip` inside it.

## Size ceilings

| Message | Source | Meaning |
| --- | --- | --- |
| `source '{source_id}' answered with {declared} bytes, over the {MAX_RESPONSE_BYTES}-byte ceiling` | `rest.py:476` | `Content-Length` exceeded the ceiling; refused before reading. |
| `source '{source_id}' streamed more than the {MAX_RESPONSE_BYTES}-byte ceiling` | `rest.py:485` | No `Content-Length`; aborted mid-stream. |
| `source '{source_id}' object {key!r} is {declared} bytes, over the {MAX_OBJECT_BYTES}-byte ceiling` | `s3.py:313` | S3 object too large by its declared size. |
| `source '{source_id}' object {key!r} streamed more than the {MAX_OBJECT_BYTES}-byte ceiling` | `s3.py:321` | S3 object too large while streaming. |
| `sn-attachment-fetch-cap: {len(rows)} rows pinned, cap is {_MAX_ATTACHMENT_FETCHES}` | `servicenow.py:331` | Too many attachment fetches in one request. Narrow the scope. |

Fix by narrowing the query (add scope constraints, request fewer rows) rather than by chasing
the ceiling — it exists so one source cannot exhaust broker memory.

## SSRF guards (REST and LLM adapters)

### `RestAdapter refuses base_url host '{host}': it resolves to private/loopback/link-local address {ip}`

`nautilus/adapters/rest.py:231-236`, shared verbatim by `ServiceNowAdapter`
(`nautilus/adapters/servicenow.py:171`) — one function, not a copy per adapter. A `base_url`
that reaches a private, loopback or link-local address would let a rule reach cloud metadata
endpoints or internal services. Point the source at a routable host, or model the internal
service as its own source type.

`{host}` is what `connection` names; `{ip}` is the first address it answered with that failed the
check, so the two differ whenever a *name* was configured:

```text
RestAdapter refuses base_url host 'localhost': it resolves to private/loopback/link-local address 127.0.0.1
RestAdapter refuses base_url host '169.254.169.254': it resolves to private/loopback/link-local address 169.254.169.254
```

**The host is resolved, not pattern-matched.** Until 0.2.6 this check ran on an IP *literal* only:
`http://backend` inside a container resolved to an RFC1918 address and was dialled without
complaint, so every internal service with a DNS name — including a cloud metadata service fronted
by a name — passed a control this page said covered it. The name is now resolved at `connect()`
and **every** address it answers with must be routable.

**What it does not cover — read this before relying on it.**

- **It is a lookup, not a pin.** Resolution happens once, at `connect()`; httpx resolves again
  when it dials. A record that changes between the two answers — DNS rebinding, a short TTL, a
  round-robin set that rotates — is not caught. Closing that would mean pinning the resolved
  address into the transport for the life of the connection, which Nautilus does not do. Treat
  this as config hygiene with a real TOCTOU window, not as a boundary you can put a hostile
  resolver behind.
- **A name that does not resolve is accepted.** It reaches nothing, so refusing it would buy no
  security; the dial then fails with the driver's own DNS error, and the failing source's
  `endpoint` names the host.
- **It runs at connect, so it runs once per process per source.** A source that connected before
  DNS changed keeps its pool.
- **REST and ServiceNow only.** `postgres`, `elasticsearch`, `neo4j`, `influxdb`, `s3` and
  `pgvector` dial whatever their `connection` says; internal addresses are the *normal* case for
  those and there is no guard on them. The LLM adapter has its own, deliberately narrower rule —
  see below.

**A consequence worth planning for:** a REST source pointed at a sibling container or a
cluster-internal service by name (`http://backend`, `http://catalog.svc.cluster.local`) is now
refused where it previously worked. That was always this page's stated rule; the code has caught
up with it. The documented alternatives are unchanged — front the service with a routable host,
or model it as its own source type.

### `Refused redirect from host '{base_host}' to different host '{target_host}' (status={response.status_code})`

`nautilus/adapters/rest.py:523-527`. A 3xx tried to move the request to another host. Redirects
are never followed across hosts.

### `Refused same-host redirect (status={response.status_code}); configure the endpoint path directly to avoid 3xx responses.`

`nautilus/adapters/rest.py:529-532`. Even a same-host redirect is refused; point
`EndpointSpec.path` at the final URL.

### `{adapter} requires a non-empty host in base_url (scheme={scheme!r}; the value is withheld because a connection string can carry credentials)`

`resolve_base_url`, `nautilus/adapters/base.py:149-153`. `{adapter}` is `RestAdapter` or
`LLMAdapter`. The URL parsed with no netloc — usually a missing `https://`. Rendered example:

```text
RestAdapter requires a non-empty host in base_url (scheme='http'; the value is withheld because a connection string can carry credentials)
```

The offending value is deliberately **not** echoed. A malformed connection string is exactly the
shape that still carries userinfo (`http://user:pw@`), and this message travels into the audit
trail and the requesting agent's response. The `source_id` on the same `sources_errored` entry
tells you which `connection` to go and read.

### `LLMAdapter refuses base_url host '{host}': it resolves to link-local/multicast/unspecified address {ip}`

`nautilus/adapters/llm.py:81-86`. The LLM adapter's rule is deliberately narrower than the REST
adapter's: loopback and RFC1918 are **allowed**, because a local inference server is the primary
and only air-gap-compatible deployment. Cloud metadata (`169.254.0.0/16`), multicast and the
unspecified address stay blocked.

Names are resolved here too, and for the same reason: every cloud metadata service also answers
to a name (`metadata.google.internal`, `instance-data`), and the literal-only version of this
check let all of them through. The residual above applies here identically — it is one lookup,
not a pin.

## Embeddings

### `NoopEmbedder(strict=True) cannot produce embeddings. Pass context['embedding']: list[float] at request time, configure a per-source embedder, or construct the broker with a non-strict embedder.`

**`EmbeddingUnavailableError`**, `nautilus/adapters/embedder.py:65-69`. A vector search was asked
for with no embedder wired. The message lists the three ways out; the default is strict so a
similarity query never silently degrades to a zero vector.

### `context['embedding'] must be list[float], got {type(override).__name__}`

`nautilus/adapters/pgvector.py:109-112`. The override was supplied but is the wrong type — a
string of JSON rather than a decoded list is the usual cause.

```bash
python - <<'PY'
from nautilus.adapters.base import EmbeddingUnavailableError
from nautilus.adapters.embedder import NoopEmbedder
try:
    NoopEmbedder(strict=True).embed("anything")
except EmbeddingUnavailableError as exc:
    print(exc)
PY
```

## Per-adapter messages

Each adapter adds refusals that only its backend can raise. Every one of them is grouped under its
own heading below, with the exception type, the raise site, what each placeholder holds, what the
caller sees, and a repro that needs no live backend.

**What the caller sees, for all of them.** These exceptions never escape the broker as an HTTP
error. `POST /v1/request` (and its alias `/v1/query`) answers **200** with `outcome: "errored"`,
and the message arrives as one entry in `sources_errored[]`:

```json
{
  "source_id": "ledger",
  "error_type": "AdapterError",
  "message": "PostgresAdapter: execute failed for source 'ledger': ConnectionRefusedError: [Errno 111] Connect call failed ('127.0.0.1', 15499)",
  "trace_id": "b8f39914-1ba2-4d3e-800c-43fffe1041e8",
  "endpoint": "postgresql://127.0.0.1:15499"
}
```

`error_type` is the exception class name (`ScopeEnforcementError`, `AdapterError`,
`SSRFBlockedError`, `EmbeddingUnavailableError`), and the failed source contributes no rows —
partial answers are labelled, never silently merged. Anything raised from `connect()` is prefixed
`connect() failed: ` by `nautilus/core/broker.py:3232`, and that source is not retried for
`connect_cooldown_s`. Anything raised from `execute()` arrives unprefixed
(`nautilus/core/broker.py:3822-3847`). The per-entry **Status** lines below say which of the two
it is.

### `endpoint` — which backend this was

`endpoint` names the address the failing source dials, as `scheme://host[:port]`. It is the
answer to *"one of my sources is down — which host?"*, which nothing the broker wrote used to
carry: a `source_id` is your label for a dependency, not the dependency. The same value appears
in the audit entry's `error_records[]` and in the log line below, so the question is answerable
from the durable trail after the fact.

It is **built from scheme, host and port only** (`redact_connection`,
`nautilus/config/models.py:813-827`), by copying those three out rather than by stripping
anything: userinfo (`postgres://user:pw@…`), path (`https://hooks.example/services/T0/B0/SECRET`),
query (`?password=…`, `?token=…`) and fragment cannot survive into it. That matters because this
field reaches the process log, the audit file and the requesting agent — three audiences wider
than the one that reads `nautilus.yaml`. `null` for a source that dials nothing (`static`) and
for any `connection` with no host (a filesystem path, a libpq keyword DSN like
`host=db password=pw`): there is no guess, because a guess is how the withheld half gets echoed
by accident.

A `source_id` of `<broker>` is not a source; it is the broker's own failure, and it carries the
same field on the same terms. The request that *fails* — HTTP 503 from a wedged or unreachable
session store, `BrokerBusyError` or `SessionStoreUnavailableError` — records the session store's
`scheme://host[:port]`, so "the request failed" and "here is what broke" are one observation
rather than two mutually exclusive ones (see
[sessions.md](sessions.md)). It stays `null` where the broker dialled nothing: a rejected session
token is checked in-process against the key ring, and `api.max_concurrent_requests` is an
in-process gate, so neither has an address to name.

If your source dials somewhere its `connection` does not name, an adapter may set `endpoint` on
an `ErrorRecord` it returns and the broker leaves it alone — strip credentials yourself if you do.

### The matching log line

`nautilus/core/broker.py:3391-3401`. Every per-source failure — unknown source, connect cooldown,
connect error, schema quarantine, wall-clock timeout, adapter contract violation, and the typed
record an adapter returns — emits exactly one `WARNING` on the `nautilus.core.broker` logger
before it reaches the response:

```text
WARNING:nautilus.core.broker:source 'ledger' failed (endpoint=postgresql://127.0.0.1:15499, error_type=AdapterError, trace_id=b8f39914-1ba2-4d3e-800c-43fffe1041e8): PostgresAdapter: execute failed for source 'ledger': ConnectionRefusedError: [Errno 111] Connect call failed ('127.0.0.1', 15499)
```

`WARNING`, so it is on stdout at the default `--log-level info` — you do not need
`--log-level debug`, which adds every library's records and still said nothing about this. Under
`--log-format json` the same record arrives as one JSON object with `logger:
"nautilus.core.broker"`. `endpoint=<none configured>` renders when the field is `null`.

### `exceeded the source's timeout_s budget of {timeout_s}s`

`nautilus/core/broker.py:3354-3357`, with `error_type: "TimeoutError"`. The broker wraps each
source's `connect()` + `execute()` in one wall-clock deadline
(`SourceConfig.timeout_s`, default `15.0`); this is what the entry says when the deadline fired
before the source answered. Rendered example:

```text
exceeded the source's timeout_s budget of 5.0s
```

`TimeoutError` carries no text of its own, so interpolating it produced `exceeded the source's
timeout_s budget: ` — a colon with nothing after it, and, like the `wrap_execute` case above, the
entire text an operator received. The budget that was actually spent is what the sentence now
ends with.

The variant `exceeded the source's timeout_s budget` (no number) means the source declares
`timeout_s: null`, so the broker imposed no deadline and the `TimeoutError` came from inside the
driver — there is no broker budget to quote.

Which source, and which host, are on the same entry: `source_id` and `endpoint`.

## Postgres and pgvector

### `PostgresAdapter requires 'table' on source '{config.id}' (Phase 1 shortcut)`

**`AdapterError`**, `nautilus/adapters/postgres.py:63`, from `connect()`, before the pool is built.
`{config.id}` is the source id.

**Means.** The adapter was handed a `SourceConfig` with no `table`. Postgres sources address one
table; there is no query planner here that could pick one.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, message prefixed
`connect() failed: `.

**Fix.** Add `table: schema.name` to the source block. A source declared `type: postgres` in YAML
never reaches this: `nautilus/config/models.py:213-219` rejects it at load with
`source 'vuln_db' has type 'postgres' but no 'table'. …` (see [config.md](config.md)). This one is
reachable when you build the config yourself, or register the adapter under a different type name.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.postgres import PostgresAdapter
from nautilus.config.models import SourceConfig
cfg = SourceConfig(id="vuln_db", type="pg-legacy", classification="unclassified",
                   data_types=["vuln"], connection="postgresql://u@h/db")
try:
    asyncio.run(PostgresAdapter().connect(cfg))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: PostgresAdapter requires 'table' on source 'vuln_db' (Phase 1 shortcut)
```

### `PostgresAdapter missing 'table' for source '{self._config.id}'`

**`AdapterError`**, `nautilus/adapters/postgres.py:190`, from `execute()`, after the connect-time
check has already passed. `{self._config.id}` is the source id held by the adapter instance.

**Means.** The adapter is connected but the config it is holding now has no `table` — the instance
was handed a *different* config after `connect()`, or its `_config` was mutated. The connect-time
form above means the config was wrong from the start; this one means it changed underneath.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, unprefixed.

**Fix.** Do not reuse one adapter instance across two source configs. `Broker` keeps one instance
per source id; this is a hazard for direct callers only.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.postgres import PostgresAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis
a = PostgresAdapter()
a._pool = object()  # stand in for a live pool
a._config = SourceConfig(id="vuln_db", type="pg-legacy", classification="unclassified",
                         data_types=["vuln"], connection="postgresql://u@h/db")
try:
    asyncio.run(a.execute(IntentAnalysis(raw_intent="x", data_types_needed=[], entities=[]), [], {}))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: PostgresAdapter missing 'table' for source 'vuln_db'
```

### `PgVectorAdapter requires 'table' on source '{config.id}'`

**`AdapterError`**, `nautilus/adapters/pgvector.py:90`, from `connect()`. The pgvector twin of the
Postgres check, minus the "(Phase 1 shortcut)" suffix — grep for the exact spelling, the two are
not interchangeable. `{config.id}` is the source id.

**Means.** A pgvector source with no table to search.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, prefixed
`connect() failed: `.

**Fix.** Add `table:`; `type: pgvector` in YAML is caught earlier by the same loader rule as
Postgres.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.pgvector import PgVectorAdapter
from nautilus.config.models import SourceConfig
cfg = SourceConfig(id="kb", type="pgv-legacy", classification="unclassified",
                   data_types=["doc"], connection="postgresql://u@h/db")
try:
    asyncio.run(PgVectorAdapter().connect(cfg))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: PgVectorAdapter requires 'table' on source 'kb'
```

### `PgVectorAdapter missing 'table' for source '{config.id}'`

**`AdapterError`**, `nautilus/adapters/pgvector.py:216`, from `execute()`. Same
config-changed-underneath condition as the Postgres `missing 'table'` form. `{config.id}` is the
id on the config the adapter is holding.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, unprefixed.

**Fix.** One adapter instance per source config.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.pgvector import PgVectorAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis
a = PgVectorAdapter()
a._pool = object()
a._config = SourceConfig(id="kb", type="pgv-legacy", classification="unclassified",
                         data_types=["doc"], connection="postgresql://u@h/db")
try:
    asyncio.run(a.execute(IntentAnalysis(raw_intent="x", data_types_needed=[], entities=[]), [], {}))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: PgVectorAdapter missing 'table' for source 'kb'
```

### `distance_operator '{distance_operator}' not in allowlist: {sorted(_ALLOWED_DISTANCE_OPERATORS)}`

**`AdapterError`**, `nautilus/adapters/pgvector.py:157`, from `_build_vector_sql()`.
`{distance_operator}` is the operator that was about to be spliced into `ORDER BY`;
the allowlist renders as the sorted literal list `['<#>', '<->', '<=>']`.

**Means.** The similarity operator is interpolated into SQL, so it is checked against a closed set:
`<=>` (cosine), `<->` (L2), `<#>` (negative inner product). Anything else is refused rather than
escaped.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, unprefixed.

**Fix.** Set `distance_operator` to one of the three. From YAML this is already impossible —
`SourceConfig.distance_operator` is `Literal["<=>", "<->", "<#>"] | None`, so a bad value fails
config load. The guard exists for hand-built configs.

```bash
python - <<'PY'
from nautilus.adapters.pgvector import PgVectorAdapter
try:
    PgVectorAdapter()._build_vector_sql("docs", [], "embedding", "<~>", "metadata", [0.0], 10)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: distance_operator '<~>' not in allowlist: ['<#>', '<->', '<=>']
```

## Elasticsearch

### `ElasticsearchAdapter requires non-empty 'index' on SourceConfig`

**`ScopeEnforcementError`**, `nautilus/adapters/elasticsearch.py:74`, from `_validate_index()`,
called on the first line of `connect()` so a bad index never spins up a client. No interpolation.

**Means.** `config.index` was `None` or empty. There is no default index and no wildcard: an
adapter that guessed would query indices policy never scoped.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, prefixed
`connect() failed: `.

**Fix.** Set `index:` on the source. `type: elasticsearch` in YAML is caught at load instead, by
`nautilus/config/models.py:213-219`.

```bash
python - <<'PY'
from nautilus.adapters.elasticsearch import _validate_index
try:
    _validate_index(None)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: ElasticsearchAdapter requires non-empty 'index' on SourceConfig
```

### `Invalid Elasticsearch index '{index}': must match {_INDEX_PATTERN.pattern}`

**`ScopeEnforcementError`**, `nautilus/adapters/elasticsearch.py:78`. `{index}` is the configured
index, unquoted inside the literal `'` characters; `{_INDEX_PATTERN.pattern}` renders as
`^[a-z0-9][a-z0-9._-]*$`.

**Means.** The index name is put into the search URL, so it is pattern-checked first. Uppercase
letters, spaces, commas and `*` are all rejected — a comma or a `*` would silently widen the query
across indices.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, prefixed
`connect() failed: `.

**Fix.** Rename the index, or point the source at one concrete index. Multi-index search is not
expressible here by design.

```bash
python - <<'PY'
from nautilus.adapters.elasticsearch import _validate_index
try:
    _validate_index("Notes Index")
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: Invalid Elasticsearch index 'Notes Index': must match ^[a-z0-9][a-z0-9._-]*$
```

### `ElasticsearchAdapter could not read the mapping for index '{self._index}': {exc}`

**`AdapterError`**, `nautilus/adapters/elasticsearch.py:289`, from `_fetch_properties()`.
`{self._index}` is the validated index; `{exc}` is the Elasticsearch client's own error —
`NotFoundError(404, 'index_not_found_exception')`, an auth failure, or a connection error.

**Means.** The adapter needs the mapping before it can tell an analysed `text` field from a
`keyword` one (the two refusals below depend on it). It is fetched lazily, on the first request
whose scope touches a field, so this surfaces per request rather than at startup.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, unprefixed.

**Fix.** Read `{exc}`: a 404 means the index does not exist yet, a 403 means the credential cannot
read mappings. Grant `view_index_metadata` on the index, or create it.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.elasticsearch import ElasticsearchAdapter
class Client:
    class indices:
        @staticmethod
        async def get_mapping(index=None):
            raise RuntimeError("NotFoundError(404, 'index_not_found_exception')")
a = ElasticsearchAdapter(client=Client())
a._index = "notes"
try:
    asyncio.run(a._fetch_properties())
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: ElasticsearchAdapter could not read the mapping for index 'notes': NotFoundError(404, 'index_not_found_exception')
```

Two more refusals are specific to how Elasticsearch indexes text, and both exist to stop a scope
constraint from silently over-returning data. Both are `ScopeEnforcementError`, surfaced through
`/v1/request` the same way as every other adapter refusal — **200** with the message in
`sources_errored[]` — and both are fixed in the index mapping, not in the rule.

### `ElasticsearchAdapter: field '{field}' is mapped as analysed 'text' with no 'keyword' subfield, so it cannot be matched exactly. An exact-match constraint on it would silently return over-scoped data. Add a keyword subfield to the mapping, or target one explicitly as 'field.<subfield>'.`

`nautilus/adapters/elasticsearch.py:328-333`. `{field}` is the constraint's field name with
`str()`, unquoted inside the literal `'` characters: `field 'owner' is mapped as analysed
'text'`.

**Means.** An analysed `text` field is tokenised, so a term query for `"Ada Lovelace"` matches
every document containing `ada` *or* `lovelace`. A policy constraint evaluated that way returns
rows the policy meant to exclude.

**Fix.** Add a `keyword` subfield to the mapping for that field, or write the constraint against
an existing exact subfield by name (`owner.raw`).

```bash
curl -s -X PUT 'http://localhost:9200/notes/_mapping' -H 'Content-Type: application/json' \
  -d '{"properties":{"owner":{"type":"text","fields":{"keyword":{"type":"keyword"}}}}}'
```

### `ElasticsearchAdapter: the only exact subfield for '{field}' is '{field}.{chosen}', which has ignore_above={limit}, and the constraint compares a value of length {longest}. Values over the limit are not indexed, so the comparison would silently return over-scoped data. Raise ignore_above on the mapping, or target a subfield without one as 'field.<subfield>'.`

`nautilus/adapters/elasticsearch.py:350-357`. `{field}` is the constraint's field;
`{chosen}` is the subfield with the largest `ignore_above` (ties broken by name);
`{limit}` is that `ignore_above` as an `int`; `{longest}` is the length of the longest string in
the constraint's value.

**Means.** A `keyword` subfield with `ignore_above` does not index values longer than the limit
*at all*. A term query for such a value matches nothing, and `!=` / `NOT IN` match everything —
the same fail-open the `.keyword` routing exists to close. The adapter prefers a subfield with no
`ignore_above` and only refuses when every candidate would drop the value.

**Fix.** Raise `ignore_above` above `{longest}` on the mapping, or add and target a subfield
without `ignore_above`.

```bash
curl -s -X PUT 'http://localhost:9200/notes/_mapping' -H 'Content-Type: application/json' \
  -d '{"properties":{"owner":{"type":"text","fields":{"raw":{"type":"keyword"}}}}}'
```

## Neo4j

### `Neo4jAdapter requires non-empty 'label' on SourceConfig`

**`ScopeEnforcementError`**, `nautilus/adapters/neo4j.py:91`, from `_validate_label()` on the first
line of `connect()`. No interpolation.

**Means.** `config.label` was `None` or empty. The label is the `MATCH (n:Label)` the whole query
hangs off; without it the adapter would have to scan every node in the graph.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, prefixed
`connect() failed: `.

**Fix.** Set `label:` on the source. `type: neo4j` in YAML is caught at config load instead.

```bash
python - <<'PY'
from nautilus.adapters.neo4j import _validate_label
try:
    _validate_label(None)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: Neo4jAdapter requires non-empty 'label' on SourceConfig
```

### `Invalid Neo4j label '{label}': must match {_LABEL_PATTERN.pattern}`

**`ScopeEnforcementError`**, `nautilus/adapters/neo4j.py:93`. `{label}` is the configured label;
`{_LABEL_PATTERN.pattern}` renders as `^[A-Z][A-Za-z0-9_]*$`.

**Means.** The label is interpolated into Cypher. Only an initial-capital identifier is accepted:
a space, a backtick or a `)` in that position would end the pattern early and let the rest of the
value run as Cypher.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, prefixed
`connect() failed: `.

**Fix.** Use the label as Neo4j spells it — `CaseFile`, not `Case File`.

```bash
python - <<'PY'
from nautilus.adapters.neo4j import _validate_label
try:
    _validate_label("Case File")
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: Invalid Neo4j label 'Case File': must match ^[A-Z][A-Za-z0-9_]*$
```

### `Invalid Neo4j property identifier '{name}'`

**`ScopeEnforcementError`**, `nautilus/adapters/neo4j.py:106`, from `_validate_property()`, called
for every scope constraint's field while the `WHERE` clause is built. `{name}` is the field name
from the constraint.

**Means.** The property name failed `_PROPERTY_PATTERN`. Values are always parameterised; property
*names* cannot be, so they are pattern-checked and then backticked.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, unprefixed —
this one is raised during `execute()`, so it fires per request, once a rule or
`context.scope_constraints` names that field.

**Fix.** Correct the `field` in the rule that produced the constraint. If the graph genuinely has a
property with a space in it, it cannot be scoped on.

```bash
python - <<'PY'
from nautilus.adapters.neo4j import _validate_property
try:
    _validate_property("owner name")
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: Invalid Neo4j property identifier 'owner name'
```

### `neo4j: get_schema failed for source '{self._config.id}': {exc}`

**`AdapterError`**, `nautilus/adapters/neo4j.py:419`, from `get_schema()`. `{self._config.id}` is
the source id; `{exc}` is the driver's error — `ServiceUnavailable`, an auth failure, or a
timeout.

**Means.** The schema probe (`CALL db.schema.nodeTypeProperties`) did not answer. It deliberately
raises rather than returning `AdapterSchema.unknown()`, because an unknown fingerprint is
indistinguishable from major drift and would quarantine a source that is merely offline.

**Status.** Two callers, two answers. `GET /v1/adapters/{name}/schema` answers **503** with
`{"detail": "Schema fetch failed: neo4j: get_schema failed for source 'cases': ..."}`
(`nautilus/transport/fastapi_app.py:1275-1280`). Inside a request, the broker's drift gate treats a
raising `get_schema` as "cannot check" and proceeds, so the request itself still answers **200**.

**Fix.** Read `{exc}`: it is the driver's diagnosis, not ours. Restore the database, or fix the
credential.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.neo4j import Neo4jAdapter
from nautilus.config.models import SourceConfig
class Driver:
    def session(self, **kw):
        raise RuntimeError("ServiceUnavailable: Unable to retrieve routing information")
a = Neo4jAdapter(driver=Driver())
a._config = SourceConfig(id="cases", type="neo4j", classification="unclassified",
                         data_types=["case"], connection="bolt://h:7687", label="Case")
a._label = "Case"
try:
    asyncio.run(a.get_schema())
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: neo4j: get_schema failed for source 'cases': ServiceUnavailable: Unable to retrieve routing information
```

## InfluxDB

### `InfluxDBAdapter: '_time' bound {value!r} is not a Flux duration (e.g. '-30d'), an RFC3339 instant (e.g. '2023-11-14T00:00:00Z') or a Unix-second integer`

**`ScopeEnforcementError`**, `nautilus/adapters/influxdb.py:75`, from `_flux_time()`. `{value!r}`
is the constraint value with `repr()`, so a string arrives quoted: `'last tuesday'`.

**Means.** A constraint on `_time` carried a string that is neither a Flux duration nor an RFC3339
instant. The bound goes into `range(start:, stop:)`, which is the only thing keeping the query off
the whole retention period.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, unprefixed.

**Fix.** Write the bound as `-30d`, `2023-11-14T00:00:00Z`, or a Unix-second integer.

```bash
python - <<'PY'
from nautilus.adapters.influxdb import _flux_time
try:
    _flux_time("last tuesday")
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: InfluxDBAdapter: '_time' bound 'last tuesday' is not a Flux duration (e.g. '-30d'), an RFC3339 instant (e.g. '2023-11-14T00:00:00Z') or a Unix-second integer
```

### `InfluxDBAdapter: '_time' bound {value!r} is not a time, duration or Unix-second integer`

**`ScopeEnforcementError`**, `nautilus/adapters/influxdb.py:66`. The first branch of `_flux_time`,
and it catches exactly one thing: a boolean. `{value!r}` is the `repr()` of the value, so it
renders as `True` or `False`.

**Means.** `bool` is a subclass of `int` in Python, so `True` would otherwise have been rendered as
the Unix second `1` — 1970-01-01T00:00:01Z. A boolean where a timestamp belongs is a bug in the
rule that produced the constraint, and it is refused rather than silently treated as the epoch.
Every other unusable value lands on the longer message at line 75.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, unprefixed.

**Fix.** Look at the rule that emitted the constraint: a boolean here usually means a template
substituted a truth value where it meant to substitute a timestamp.

```bash
python - <<'PY'
from nautilus.adapters.influxdb import _flux_time
try:
    _flux_time(True)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: InfluxDBAdapter: '_time' bound True is not a time, duration or Unix-second integer
```

### `InfluxDBAdapter: operator {op!r} is not expressible as a time range on '_time' (use <, <=, >, >= or BETWEEN)`

**`ScopeEnforcementError`**, `nautilus/adapters/influxdb.py:298`, from `_build_flux()`. `{op!r}` is
the operator with `repr()`: `'='`.

**Means.** `_time` is not a column in Flux, it is the `range()` call. An `=`, `IN`, `LIKE` or
`IS NULL` on it has no range form, and narrowing it approximately would change which points the
query returns.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, unprefixed.

**Fix.** Express the window as an inequality or a `BETWEEN`. For a single instant, use
`BETWEEN [t, t]`.

```bash
python - <<'PY'
from nautilus.adapters.influxdb import InfluxDBAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import ScopeConstraint
a = InfluxDBAdapter()
a._config = SourceConfig(id="metrics", type="influxdb", classification="unclassified",
                         data_types=["metric"], connection="http://h:8086")
try:
    a._build_flux("metrics", [ScopeConstraint(source_id="metrics", field="_time",
                                              operator="=", value="-30d")], 10)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: InfluxDBAdapter: operator '=' is not expressible as a time range on '_time' (use <, <=, >, >= or BETWEEN)
```

### `InfluxDBAdapter: LIKE pattern {pattern!r} uses the '_' single-character wildcard, which Flux cannot express`

**`ScopeEnforcementError`**, `nautilus/adapters/influxdb.py:140`, from `_flux_like()`.
`{pattern!r}` is the `LIKE` value with `repr()`: `'web_1%'`.

**Means.** Flux offers prefix matching, not SQL `LIKE`. `_` matches exactly one character and has
no Flux equivalent; translating it to `.` (regex) or dropping it would both change the row set.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, unprefixed.

**Fix.** Rewrite the constraint as a prefix (`web%`), or use `IN` with the explicit members.

```bash
python - <<'PY'
from nautilus.adapters.influxdb import _flux_like
try:
    _flux_like("host", "web_1%")
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: InfluxDBAdapter: LIKE pattern 'web_1%' uses the '_' single-character wildcard, which Flux cannot express
```

### `InfluxDBAdapter: LIKE pattern {pattern!r} has an interior '%' wildcard, which Flux cannot express`

**`ScopeEnforcementError`**, `nautilus/adapters/influxdb.py:148`. `{pattern!r}` is the pattern with
`repr()`: `'web%prod%'`.

**Means.** Only a trailing `%` is expressible, as a prefix match. A `%` in the middle is a
contains-with-gap that Flux has no operator for.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, unprefixed.

**Fix.** Reduce the pattern to a prefix, or enumerate the values with `IN`.

```bash
python - <<'PY'
from nautilus.adapters.influxdb import _flux_like
try:
    _flux_like("host", "web%prod%")
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: InfluxDBAdapter: LIKE pattern 'web%prod%' has an interior '%' wildcard, which Flux cannot express
```

### `InfluxDBAdapter: source '{config.id}' declares auth type {auth.type!r}, which InfluxDB cannot use. Use 'bearer' (token=the InfluxDB API token), or omit 'auth' to read INFLUXDB_V2_TOKEN from the environment.`

**`AdapterError`**, `nautilus/adapters/influxdb.py:176`, from `_auth_token()`, called by
`connect()`. `{config.id}` is the source id; `{auth.type!r}` is the discriminator from the `auth:`
block with `repr()` — `'basic'`, `'mtls'`.

**Means.** InfluxDB v2 authenticates with a token only. A username/password pair has nowhere to go,
and silently ignoring it would connect anonymously.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, prefixed
`connect() failed: `.

**Fix.** Use `auth: {type: bearer, token: ...}`, or drop the `auth:` block and export
`INFLUXDB_V2_TOKEN`.

```bash
python - <<'PY'
from nautilus.adapters.influxdb import _auth_token
from nautilus.config.models import BasicAuth, SourceConfig
cfg = SourceConfig(id="metrics", type="influxdb", classification="unclassified",
                   data_types=["metric"], connection="http://h:8086",
                   auth=BasicAuth(username="u", password="p"))
try:
    _auth_token(cfg)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: InfluxDBAdapter: source 'metrics' declares auth type 'basic', which InfluxDB cannot use. Use 'bearer' (token=the InfluxDB API token), or omit 'auth' to read INFLUXDB_V2_TOKEN from the environment.
```

### `influxdb: get_schema failed for source '{self._config.id}': {exc}`

**`AdapterError`**, `nautilus/adapters/influxdb.py:466`, from `get_schema()`.
`{self._config.id}` is the source id; `{exc}` is whatever `schema.measurements()` raised — most
often an authorisation error on the bucket.

**Means.** The measurement/field-key probe failed. Like the Neo4j twin it raises rather than
returning `unknown()`, so an outage is not mistaken for schema drift.

**Status.** `GET /v1/adapters/{name}/schema` answers **503** with
`{"detail": "Schema fetch failed: influxdb: get_schema failed for source 'metrics': ..."}`
(`nautilus/transport/fastapi_app.py:1275-1280`); inside a request the drift gate skips the check
and the request still answers **200**.

**Fix.** Grant the token read access to the bucket, or fix the bucket name (`table:`, falling back
to the source id).

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.influxdb import InfluxDBAdapter
from nautilus.config.models import SourceConfig
class QueryApi:
    def query(self, flux):
        raise RuntimeError("unauthorized: read:orgs/x/buckets is unauthorized")
a = InfluxDBAdapter()
a._config = SourceConfig(id="metrics", type="influxdb", classification="unclassified",
                         data_types=["metric"], connection="http://h:8086")
a._query_api = QueryApi()
try:
    asyncio.run(a.get_schema())
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: influxdb: get_schema failed for source 'metrics': unauthorized: read:orgs/x/buckets is unauthorized
```

## S3

Every scope refusal below is raised inside `execute()` while the constraint list is folded into a
`ListObjectsV2` / `GetObject` plan, so all of them answer **200** with the message in
`sources_errored[]` under `error_type: "ScopeEnforcementError"` and no rows from that source. The
repros drive the adapter directly with a stand-in client, which is why they need neither AWS nor
`aiobotocore` credentials.

### `S3Adapter: source '{config.id}' declares auth type {auth.type!r}, which S3 cannot use. Use 'basic' (username=access key id, password=secret access key), or omit 'auth' to use the ambient credential chain.`

**`AdapterError`**, `nautilus/adapters/s3.py:77`, from `_client_kwargs()`, called by `connect()`.
`{config.id}` is the source id; `{auth.type!r}` is the `auth:` discriminator with `repr()` —
`'bearer'`, `'mtls'`.

**Means.** SigV4 signs with an access-key pair. A bearer token or a client certificate has nowhere
to go in that scheme, and connecting anyway would fall through to the ambient credential chain —
an unrelated identity with unknown permissions.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, prefixed
`connect() failed: `.

**Fix.** Use `auth: {type: basic, username: <access key id>, password: <secret access key>}`, or
delete the `auth:` block and let the instance role / `AWS_*` environment supply credentials.

```bash
python - <<'PY'
from nautilus.adapters.s3 import _client_kwargs
from nautilus.config.models import BearerAuth, SourceConfig
cfg = SourceConfig(id="evidence", type="s3", classification="unclassified", data_types=["object"],
                   connection="s3://us-east-1", table="evidence-bucket",
                   auth=BearerAuth(token="t"))
try:
    _client_kwargs(cfg)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: S3Adapter: source 'evidence' declares auth type 'bearer', which S3 cannot use. Use 'basic' (username=access key id, password=secret access key), or omit 'auth' to use the ambient credential chain.
```

### `S3Adapter: unsupported operator '{op}' for field 'key'`

**`ScopeEnforcementError`**, `nautilus/adapters/s3.py:219`. `{op}` is the constraint's operator.

**Means.** An object store indexes by key prefix and nothing else. `=` becomes a `GetObject`,
`LIKE` becomes a `Prefix`; `<`, `>`, `BETWEEN`, `IN` and `IS NULL` have no server-side form, and
emulating them client-side would mean listing the bucket first — the over-return this adapter
exists to prevent.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Scope keys with `=` or `LIKE 'prefix/%'`.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.s3 import S3Adapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint
a = S3Adapter()
a._client, a._bucket = object(), "evidence-bucket"
a._config = SourceConfig(id="evidence", type="s3", classification="unclassified",
                         data_types=["object"], connection="s3://us-east-1",
                         table="evidence-bucket")
c = ScopeConstraint(source_id="evidence", field="key", operator=">", value="restricted/")
try:
    asyncio.run(a.execute(IntentAnalysis(raw_intent="x", data_types_needed=[], entities=[]), [c], {}))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: S3Adapter: unsupported operator '>' for field 'key'
```

### `S3Adapter: unsupported operator '{op}' for tag filter`

**`ScopeEnforcementError`**, `nautilus/adapters/s3.py:227`. `{op}` is the constraint's operator, on
a field named `tag.<name>`.

**Means.** Tags are fetched per object and compared exactly. `=`, `!=` and `IN` are supported;
`LIKE`, the ordering operators and `BETWEEN` are not, because a tag value is an opaque string.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Compare tags with `=`, `!=` or `IN`.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.s3 import S3Adapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint
a = S3Adapter()
a._client, a._bucket = object(), "evidence-bucket"
a._config = SourceConfig(id="evidence", type="s3", classification="unclassified",
                         data_types=["object"], connection="s3://us-east-1",
                         table="evidence-bucket")
c = ScopeConstraint(source_id="evidence", field="tag.owner", operator="LIKE", value="ada%")
try:
    asyncio.run(a.execute(IntentAnalysis(raw_intent="x", data_types_needed=[], entities=[]), [c], {}))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: S3Adapter: unsupported operator 'LIKE' for tag filter
```

### `S3Adapter: unsupported operator '{op}' for classification`

**`ScopeEnforcementError`**, `nautilus/adapters/s3.py:233`. `{op}` is the constraint's operator on
the `classification` field.

**Means.** `classification` is not a property of the objects — it is the single value declared on
the source. The only meaningful test is equality against that value; `!=`, `IN` and the ordering
operators would imply a per-object classification the bucket does not carry.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Use `classification = <level>`, or model each classification as its own source so the
clearance check does the work.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.s3 import S3Adapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint
a = S3Adapter()
a._client, a._bucket = object(), "evidence-bucket"
a._config = SourceConfig(id="evidence", type="s3", classification="unclassified",
                         data_types=["object"], connection="s3://us-east-1",
                         table="evidence-bucket")
c = ScopeConstraint(source_id="evidence", field="classification", operator="!=", value="secret")
try:
    asyncio.run(a.execute(IntentAnalysis(raw_intent="x", data_types_needed=[], entities=[]), [c], {}))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: S3Adapter: unsupported operator '!=' for classification
```

### `S3Adapter: unsupported scope field '{field}'`

**`ScopeEnforcementError`**, `nautilus/adapters/s3.py:238`, the fall-through of the field switch.
`{field}` is the constraint's field name.

**Means.** The adapter understands three field shapes: `key`, `tag.<name>` and `classification`.
Anything else — `size`, `last_modified`, a column name carried over from a SQL rule — has no S3
equivalent, and a constraint that cannot be applied is a constraint that would be ignored.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Rewrite the rule for this source, or restrict the rule to the SQL sources it was written
for.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.s3 import S3Adapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint
a = S3Adapter()
a._client, a._bucket = object(), "evidence-bucket"
a._config = SourceConfig(id="evidence", type="s3", classification="unclassified",
                         data_types=["object"], connection="s3://us-east-1",
                         table="evidence-bucket")
c = ScopeConstraint(source_id="evidence", field="size", operator="<", value=1024)
try:
    asyncio.run(a.execute(IntentAnalysis(raw_intent="x", data_types_needed=[], entities=[]), [c], {}))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: S3Adapter: unsupported scope field 'size'
```

### `S3Adapter: empty tag name`

**`ScopeEnforcementError`**, `nautilus/adapters/s3.py:225`. No interpolation.

**Means.** The field was the bare string `tag.` — the prefix with nothing after it. An empty tag
name would match every tag, which is the opposite of a filter.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Name the tag: `tag.owner`.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.s3 import S3Adapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint
a = S3Adapter()
a._client, a._bucket = object(), "evidence-bucket"
a._config = SourceConfig(id="evidence", type="s3", classification="unclassified",
                         data_types=["object"], connection="s3://us-east-1",
                         table="evidence-bucket")
c = ScopeConstraint(source_id="evidence", field="tag.", operator="=", value="ada")
try:
    asyncio.run(a.execute(IntentAnalysis(raw_intent="x", data_types_needed=[], entities=[]), [c], {}))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: S3Adapter: empty tag name
```

### `S3Adapter: IN operator requires a list value, got {type(value).__name__}`

**`ScopeEnforcementError`**, `nautilus/adapters/s3.py:103`, from `_tag_operand()`.
`{type(value).__name__}` is the Python type name of the value — `dict`, `int`.

**Means.** `IN` on a tag needs members to compare against. A bare string is accepted and treated as
a single member (`("alice",)`), precisely so a one-element `IN` is not read character by character;
a mapping or a number is neither a member list nor a member.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Pass a list: `tag.owner IN ["alice", "bob"]`.

```bash
python - <<'PY'
from nautilus.adapters.s3 import _tag_operand
try:
    _tag_operand("IN", {"owner": "alice"})
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: S3Adapter: IN operator requires a list value, got dict
```

### `S3Adapter: LIKE operator requires a string value`

**`ScopeEnforcementError`**, `nautilus/adapters/s3.py:213`. No interpolation — the offending type
is not echoed here, unlike the `IN` twin above.

**Means.** A `LIKE` on `key` becomes a `Prefix`, which has to be a string. The adapter strips a
trailing `%` and passes the rest to `ListObjectsV2`.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Give `LIKE` a string pattern, `restricted/%`.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.s3 import S3Adapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint
a = S3Adapter()
a._client, a._bucket = object(), "evidence-bucket"
a._config = SourceConfig(id="evidence", type="s3", classification="unclassified",
                         data_types=["object"], connection="s3://us-east-1",
                         table="evidence-bucket")
c = ScopeConstraint(source_id="evidence", field="key", operator="LIKE", value=5)
try:
    asyncio.run(a.execute(IntentAnalysis(raw_intent="x", data_types_needed=[], entities=[]), [c], {}))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: S3Adapter: LIKE operator requires a string value
```

### `S3Adapter request failed for source '{self._config.id}': {exc}`

**`AdapterError`**, `nautilus/adapters/s3.py:285`. `{self._config.id}` is the source id; `{exc}` is
the botocore error — `An error occurred (AccessDenied) …`, `(NoSuchBucket)`, an endpoint timeout.

**Means.** The plan was valid and the call to S3 failed. Everything after the colon belongs to
botocore.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, unprefixed.

**Fix.** Read the botocore code: `AccessDenied` is an IAM policy that does not allow
`s3:ListBucket` / `s3:GetObject` on that prefix, `NoSuchBucket` is a wrong `table:`.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.s3 import S3Adapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint
class Client:
    async def list_objects_v2(self, **kw):
        raise RuntimeError("An error occurred (AccessDenied) when calling the ListObjectsV2 operation")
a = S3Adapter()
a._client, a._bucket = Client(), "evidence-bucket"
a._config = SourceConfig(id="evidence", type="s3", classification="unclassified",
                         data_types=["object"], connection="s3://us-east-1",
                         table="evidence-bucket")
c = ScopeConstraint(source_id="evidence", field="key", operator="LIKE", value="restricted/%")
try:
    asyncio.run(a.execute(IntentAnalysis(raw_intent="x", data_types_needed=[], entities=[]), [c], {}))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: S3Adapter request failed for source 'evidence': An error occurred (AccessDenied) when calling the ListObjectsV2 operation
```

## ServiceNow

The short hyphenated codes are deliberate: they are stable, greppable tokens for a log pipeline,
and they carry no table or field data of their own beyond what the `{…}` shows.

### `sn-invalid-field: {field!r}`

**`ScopeEnforcementError`**, `nautilus/adapters/servicenow.py:111`, from `_validate_sn_field()`.
`{field!r}` is the constraint's field name with `repr()`, so it arrives quoted:
`'short description'`.

**Means.** The field name goes into the `sysparm_query` encoded query, where `^` and `,` are
segment separators. Only `^[a-z][a-z0-9_.]*$`-shaped column names are accepted; anything else could
end its own clause and start another.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Use the ServiceNow column name (`short_description`), not its label
(`short description`). Dotted walks (`caller_id.email`) are accepted.

```bash
python - <<'PY'
from nautilus.adapters.servicenow import _validate_sn_field
try:
    _validate_sn_field("short description")
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: sn-invalid-field: 'short description'
```

### `sn-injection-rejected`

**`ScopeEnforcementError`**, `nautilus/adapters/servicenow.py:143`, from `_sanitize_sn_value()`. No
interpolation — deliberately: the rejected value is not echoed into the message, so it cannot be
replayed out of a log.

**Means.** A scope *value* contained `^` or `,`, the encoded-query separators. A value carrying one
of those could close its own clause and append another, which is the ServiceNow equivalent of SQL
injection.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Look at the rule that produced the value. A legitimate comma in a search term cannot be
expressed in an encoded query; match on a field that does not need it, or use `IN` with the
members as separate elements.

```bash
python - <<'PY'
from nautilus.adapters.servicenow import ServiceNowAdapter
try:
    ServiceNowAdapter._sanitize_sn_value("open^ORstate=7")
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: sn-injection-rejected
```

### `sn-unsupported-operator: {op!r}`

**`ScopeEnforcementError`**, `nautilus/adapters/servicenow.py:252`, the fall-through of
`_render_segment()`'s operator dispatch. `{op!r}` is the operator with `repr()`.

**Means.** No encoded-query translation exists for that operator. Every operator in
`ScopeConstraint`'s own allowlist *is* translated, so reaching this line means a constraint was
built without the model's validation — a hand-constructed `ScopeConstraint`, or a custom router.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Build constraints through `ScopeConstraint(...)` rather than `model_construct(...)`, which
skips validation.

```bash
python - <<'PY'
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.core.models import ScopeConstraint
c = ScopeConstraint.model_construct(source_id="tickets", field="state",
                                    operator="REGEX", value="^open")
try:
    ServiceNowAdapter._build_sysparm_query([c])
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: sn-unsupported-operator: 'REGEX'
```

### `sn-invalid-value: operator {op!r} requires a list, got {type(cast(object, value)).__name__}`

**`ScopeEnforcementError`**, `nautilus/adapters/servicenow.py:222`. `{op!r}` is `'IN'` or
`'NOT IN'` with `repr()`; `{type(cast(object, value)).__name__}` is the Python type name of the
value — `str`, `int`, `dict`.

**Means.** `IN` renders as `field IN a,b,c`. A bare string would be emitted as a single member,
which is a silently narrower filter than the rule asked for; a number has no members at all.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Pass a list, even for one member: `["open"]`.

```bash
python - <<'PY'
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.core.models import ScopeConstraint
c = ScopeConstraint(source_id="tickets", field="state", operator="IN", value="open")
try:
    ServiceNowAdapter._build_sysparm_query([c])
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: sn-invalid-value: operator 'IN' requires a list, got str
```

### `sn-invalid-value: operator 'BETWEEN' requires a 2-tuple/list`

**`ScopeEnforcementError`**, `nautilus/adapters/servicenow.py:234`. No interpolation.

**Means.** The `BETWEEN` value was not a list or a tuple at all. It renders as
`fieldBETWEENlo@hi`, so it needs two endpoints to render.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Pass `[lo, hi]`.

```bash
python - <<'PY'
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.core.models import ScopeConstraint
c = ScopeConstraint(source_id="tickets", field="sys_created_on",
                    operator="BETWEEN", value="2024")
try:
    ServiceNowAdapter._build_sysparm_query([c])
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: sn-invalid-value: operator 'BETWEEN' requires a 2-tuple/list
```

### `sn-invalid-value: operator 'BETWEEN' requires exactly two endpoints`

**`ScopeEnforcementError`**, `nautilus/adapters/servicenow.py:241`. No interpolation. The sibling of
the message above: the value *is* a sequence, but its length is not 2.

**Means.** Three endpoints is not a range, and one is not either. Rather than take the first two
and drop the rest — which would silently answer a different question — the constraint is refused.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Give exactly two endpoints.

```bash
python - <<'PY'
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.core.models import ScopeConstraint
c = ScopeConstraint(source_id="tickets", field="sys_created_on",
                    operator="BETWEEN", value=["2024-01-01", "2024-06-01", "2024-12-01"])
try:
    ServiceNowAdapter._build_sysparm_query([c])
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: sn-invalid-value: operator 'BETWEEN' requires exactly two endpoints
```

### `ServiceNowAdapter source '{config.id}' has invalid table {table!r} (expected regex '^[a-z][a-z0-9_]*$')`

**`ScopeEnforcementError`**, `nautilus/adapters/servicenow.py:155`, from `connect()`.
`{config.id}` is the source id; `{table!r}` is the configured table with `repr()`, so it arrives
quoted: `'Incident'`.

**Means.** The table name is interpolated into the request path `/api/now/table/{table}`. Only a
lowercase ServiceNow table identifier is accepted — the config-load check only requires that
`table` be non-empty, so a wrongly-cased or path-shaped value reaches here.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, prefixed
`connect() failed: `.

**Fix.** Use the table's internal name — `incident`, `sys_user`, `sc_req_item` — not its label.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.config.models import SourceConfig
cfg = SourceConfig(id="tickets", type="servicenow", classification="unclassified",
                   data_types=["ticket"], connection="https://example.service-now.com",
                   table="Incident")
try:
    asyncio.run(ServiceNowAdapter().connect(cfg))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: ServiceNowAdapter source 'tickets' has invalid table 'Incident' (expected regex '^[a-z][a-z0-9_]*$')
```

### `sn-attachment-fetch-cap: {len(rows)} rows pinned, cap is {_MAX_ATTACHMENT_FETCHES}`

**`AdapterError`**, `nautilus/adapters/servicenow.py:331`, from `_attach_content()`.
`{len(rows)}` is how many attachment rows the query pinned; `{_MAX_ATTACHMENT_FETCHES}` is the
constant at `servicenow.py:56`, currently **10**.

**Means.** A `sys_attachment` query whose scope pins `sys_id` triggers one binary download per row.
Past the cap that is a fan-out, not a query: ten downloads is a request, a hundred is an
exfiltration shaped like one.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, unprefixed. No attachment
is downloaded — the cap is checked before the first fetch, so the whole call is refused rather than
partially served.

**Fix.** Narrow the scope so fewer than ten attachments are pinned, or fetch in batches.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.config.models import SourceConfig
a = ServiceNowAdapter()
a._config = SourceConfig(id="tickets", type="servicenow", classification="unclassified",
                         data_types=["ticket"], connection="https://example.service-now.com",
                         table="sys_attachment")
rows = [{"sys_id": f"{i:032x}"} for i in range(11)]
try:
    asyncio.run(a._attach_content(None, rows, None))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: sn-attachment-fetch-cap: 11 rows pinned, cap is 10
```

### `servicenow: get_schema failed for source '{self._config.id}': {exc}`

**`AdapterError`**, `nautilus/adapters/servicenow.py:407`, from `get_schema()`.
`{self._config.id}` is the source id; `{exc}` is the underlying failure — an HTTP error from
`sys_dictionary`, or a transport error.

**Means.** The column probe against `sys_dictionary` failed. Like the other adapters it raises
rather than returning `unknown()`, so an outage does not read as schema drift.

**Status.** `GET /v1/adapters/{name}/schema` answers **503** with
`{"detail": "Schema fetch failed: servicenow: get_schema failed for source 'tickets': …"}`; inside
a request the drift gate skips the check and the request still answers **200**.

**Fix.** The integration user needs read access to `sys_dictionary` as well as to the table itself.
That is the usual cause of a 401/403 here on an otherwise working source.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.config.models import SourceConfig
class Client:
    async def request(self, *a, **k):
        raise RuntimeError("Client error '401 Unauthorized' for url '/api/now/table/sys_dictionary'")
a = ServiceNowAdapter(client=Client())
a._config = SourceConfig(id="tickets", type="servicenow", classification="unclassified",
                         data_types=["ticket"], connection="https://example.service-now.com",
                         table="incident")
a._table = "incident"
try:
    asyncio.run(a.get_schema())
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: servicenow: get_schema failed for source 'tickets': Client error '401 Unauthorized' for url '/api/now/table/sys_dictionary'
```

## REST

### `Operator 'NOT IN' is not supported by the REST adapter unless explicitly declared in EndpointSpec.operator_templates (AC-9.3).`

**`ScopeEnforcementError`**, `nautilus/adapters/rest.py:127` (the default builder
`_b_not_in_default`) and `nautilus/adapters/rest.py:383` (`_resolve_template`, reached first when
the endpoint declares no template for the operator). No interpolation.

**Means.** There is no universal query-string form for "not in". Rendering it as a repeated
parameter, or dropping it, would both widen the result set past what policy scoped — a `NOT IN`
that is ignored excludes nothing.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`.

**Fix.** Declare the API's own spelling on the endpoint, then the constraint renders through it:

```yaml
endpoints:
  - path: /v1/tickets
    operator_templates:
      "NOT IN": "{field}__not_in={value}"
```

```bash
python - <<'PY'
from nautilus.adapters.rest import RestAdapter
from nautilus.config.models import EndpointSpec, SourceConfig
from nautilus.core.models import ScopeConstraint
a = RestAdapter(client=object())
a._config = SourceConfig(id="api", type="rest", classification="unclassified",
                         data_types=["ticket"], connection="https://api.example.com")
a._endpoint = EndpointSpec(path="/v1/tickets")
c = ScopeConstraint(source_id="api", field="state", operator="NOT IN", value=["closed"])
try:
    a._build_params([c])
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: Operator 'NOT IN' is not supported by the REST adapter unless explicitly declared in EndpointSpec.operator_templates (AC-9.3).
```

### `RestAdapter source '{config.id}' declares endpoints=[] (must list at least one EndpointSpec or omit the field)`

**`ScopeEnforcementError`**, `nautilus/adapters/rest.py:317`, from `connect()`. `{config.id}` is the
source id.

**Means.** `endpoints:` present but empty is ambiguous: an omitted `endpoints` means "call the base
URL with an empty path" (the Phase-1 shape), while an empty list looks like an allowlist that
permits nothing. Rather than pick one, it is refused.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, prefixed
`connect() failed: `.

**Fix.** Either delete the `endpoints:` key, or list the endpoint you meant.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.rest import RestAdapter
from nautilus.config.models import SourceConfig
cfg = SourceConfig(id="api", type="rest", classification="unclassified",
                   data_types=["ticket"], connection="https://api.example.com", endpoints=[])
try:
    asyncio.run(RestAdapter().connect(cfg))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: RestAdapter source 'api' declares endpoints=[] (must list at least one EndpointSpec or omit the field)
```

### `EndpointSpec.operator_templates declares unknown operator '{op}' for source '{config.id}'`

**`ScopeEnforcementError`**, `nautilus/adapters/rest.py:326`, from `connect()`. `{op}` is the
offending key from `operator_templates`; `{config.id}` is the source id.

**Means.** Every key in `operator_templates` must be an operator from the shared allowlist
(`nautilus/adapters/base.py`): `=`, `!=`, `<`, `<=`, `>`, `>=`, `IN`, `NOT IN`, `LIKE`,
`IS NULL`, `BETWEEN`. A typo (`"REGEX"`, `"=="`, `"in"`) would otherwise sit in the config doing
nothing until a request needed it.

**Status.** **200**, `sources_errored[]`, `error_type: "ScopeEnforcementError"`, prefixed
`connect() failed: `. Checked at connect rather than execute so the typo surfaces on the first
request to that source, not on the first request that happens to use that operator.

**Fix.** Spell the key exactly as the allowlist does, uppercase and spaced: `NOT IN`, not `not_in`.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.rest import RestAdapter
from nautilus.config.models import EndpointSpec, SourceConfig
cfg = SourceConfig(id="api", type="rest", classification="unclassified", data_types=["ticket"],
                   connection="https://api.example.com",
                   endpoints=[EndpointSpec(path="/v1/tickets",
                                           operator_templates={"REGEX": "{field}~{value}"})])
try:
    asyncio.run(RestAdapter().connect(cfg))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
ScopeEnforcementError: EndpointSpec.operator_templates declares unknown operator 'REGEX' for source 'api'
```

## LLM source adapter

### `LLMAdapter source '{config.id}' requires a 'model' field in its source block`

**`AdapterError`**, `nautilus/adapters/llm.py:148`, from `connect()`. `{config.id}` is the source
id.

**Means.** The OpenAI-compatible `/chat/completions` body requires a `model`. There is no default:
picking one would silently send the request to whatever the endpoint happens to serve.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, prefixed
`connect() failed: `.

**Fix.** Add `model: <name>` to the source. A source declared `type: llm` in YAML is caught earlier,
at config load (`nautilus/config/models.py:213-219`).

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.llm import LLMAdapter
from nautilus.config.models import SourceConfig
cfg = SourceConfig(id="summariser", type="llm-preview", classification="unclassified",
                   data_types=["summary"], connection="https://llm.example.com")
try:
    asyncio.run(LLMAdapter().connect(cfg))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: LLMAdapter source 'summariser' requires a 'model' field in its source block
```

### `LLMAdapter source '{config.id}' does not support mTLS auth; use bearer/basic or front the endpoint with a TLS-terminating proxy`

**`AdapterError`**, `nautilus/adapters/llm.py:155`, from `connect()`, before any client is built.
`{config.id}` is the source id.

**Means.** This adapter builds a plain `httpx.AsyncClient` with no `cert=` wiring, so an `mtls:`
block would be accepted and then ignored — the connection would present no certificate while the
config said it did.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, prefixed
`connect() failed: `.

**Fix.** Use `auth: {type: bearer, token: …}`, or terminate mTLS in a sidecar and point
`connection:` at it. The REST adapter does support `mtls:` if the endpoint is a plain API.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.llm import LLMAdapter
from nautilus.config.models import MtlsAuth, SourceConfig
cfg = SourceConfig(id="summariser", type="llm", classification="unclassified",
                   data_types=["summary"], connection="https://llm.example.com",
                   model="gpt-4o-mini",
                   auth=MtlsAuth(cert_path="/etc/nautilus/client.pem",
                                 key_path="/etc/nautilus/client.key"))
try:
    asyncio.run(LLMAdapter().connect(cfg))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: LLMAdapter source 'summariser' does not support mTLS auth; use bearer/basic or front the endpoint with a TLS-terminating proxy
```

### `LLMAdapter call failed: {exc}`

**`AdapterError`**, `nautilus/adapters/llm.py:207`. `{exc}` is the `httpx` error: a DNS failure, a
refused connection, a TLS error, a timeout, or an HTTP error status raised by
`raise_for_status()`.

**Means.** The POST to `/chat/completions` did not come back with a usable response. The source id
is *not* in this message — correlate with `source_id` on the `sources_errored[]` entry.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, unprefixed. A slow endpoint
hits the source's `timeout_s` budget first and reports
`exceeded the source's timeout_s budget of {timeout_s}s` instead — see
[that entry](#exceeded-the-sources-timeout_s-budget-of-timeout_ss)
(`nautilus/core/broker.py:3354-3357`).

**Fix.** Read `{exc}`. A `401`/`403` is the token; `Name or service not known` is the `connection:`
host; a timeout usually means `timeout_s` is too tight for the model.

```bash
python - <<'PY'
import asyncio
import httpx
from nautilus.adapters.llm import LLMAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis
class Client:
    async def post(self, *a, **k):
        raise httpx.ConnectError("[Errno -2] Name or service not known")
a = LLMAdapter(client=Client())
a._config = SourceConfig(id="summariser", type="llm", classification="unclassified",
                         data_types=["summary"], connection="https://llm.example.com",
                         model="gpt-4o-mini")
a._model = "gpt-4o-mini"
try:
    asyncio.run(a.execute(IntentAnalysis(raw_intent="summarise", data_types_needed=[],
                                         entities=[]), [], {}))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: LLMAdapter call failed: [Errno -2] Name or service not known
```

### `LLMAdapter received a non-OpenAI-compatible response shape: {exc}`

**`AdapterError`**, `nautilus/adapters/llm.py:209`. `{exc}` is the `KeyError`, `IndexError` or
`TypeError` raised while reading the body — for a body with no `choices` key it renders as the
bare `'choices'`, because that is what `KeyError` stringifies to.

**Means.** The endpoint answered **200** but the JSON was not
`{"choices": [{"message": {"content": …}}]}`. A proxy error page served with a 200, a
non-OpenAI-compatible server, or a streaming response where a non-streaming one was expected.

**Status.** **200**, `sources_errored[]`, `error_type: "AdapterError"`, unprefixed.

**Fix.** Curl the endpoint yourself with the same body and look at what comes back. This adapter
speaks only the OpenAI chat-completions shape.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.llm import LLMAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis
class Response:
    status_code = 200
    def raise_for_status(self): pass
    def json(self): return {"error": "upstream proxy timeout"}
class Client:
    async def post(self, *a, **k): return Response()
a = LLMAdapter(client=Client())
a._config = SourceConfig(id="summariser", type="llm", classification="unclassified",
                         data_types=["summary"], connection="https://llm.example.com",
                         model="gpt-4o-mini")
a._model = "gpt-4o-mini"
try:
    asyncio.run(a.execute(IntentAnalysis(raw_intent="summarise", data_types_needed=[],
                                         entities=[]), [], {}))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
PY
```

```text
AdapterError: LLMAdapter received a non-OpenAI-compatible response shape: 'choices'
```

## Static adapter

### `source '{self._config.id}': the static adapter cannot enforce operator '{constraint.operator}' (supports {', '.join(sorted(_VALID_OPERATORS))})`

`nautilus/adapters/static.py:94-98`. Rendered example:

```text
source 'notes': the static adapter cannot enforce operator 'BETWEEN'
(supports =, !=, IN, IS NULL, LIKE, NOT IN)
```

`BETWEEN` and the ordering operators are deliberately absent: values come from YAML and are not
guaranteed mutually comparable, and a scope constraint that silently matches nothing is worse
than one that is refused.

## Analysis providers

`LLMProviderError` (`nautilus/analysis/llm/base.py:23`), raised when `analysis.mode: llm` is
configured. These are about the *intent analyser*, not about a data source.

| Message | Line |
| --- | --- |
| `the 'llm-anthropic' extra is not installed -- {install_extra_hint('llm-anthropic')}` | `anthropic_provider.py:78` |
| `the 'llm-openai' extra is not installed -- {install_extra_hint('llm-openai')}` | `openai_provider.py:78` |
| `analysis.provider.type=local talks to the local server over the OpenAI wire protocol, through the openai SDK, so it needs the 'llm-openai' extra -- {install_extra_hint('llm-openai')}` | `local_provider.py:53` |
| `AnthropicProvider: env var {self.api_key_env!r} is unset or empty` | `anthropic_provider.py:97` |
| `OpenAIProvider: env var {self.api_key_env!r} is unset or empty` | `openai_provider.py:95` |
| `LocalInferenceProvider: env var {self.api_key_env!r} is unset or empty` | `local_provider.py:78` |
| `anthropic SDK call failed: {exc}` | `anthropic_provider.py:130` |
| `openai SDK call failed: {exc}` | `openai_provider.py:131` |
| `anthropic response contained no tool_use block` | `anthropic_provider.py:157` |
| `anthropic tool_use block carried non-dict input: {type(payload)!r}` | `anthropic_provider.py:154` |
| `openai responses.parse returned no output_parsed payload` | `openai_provider.py:135` |

The first three fire from the constructor, so they stop `Broker.from_config` rather than a
request: `ERROR: broker construction failed: …`, exit 2. `{install_extra_hint(...)}` expands to
both remedies ([index.md](index.md#reading-a-quoted-message)) — the published image carries
neither SDK, so on that image the answer is a rebuild with
`--build-arg EXTRAS="--extra llm-openai"`, not a `pip install`. `analysis.mode: pattern` needs
no SDK at all. The third exists because `type: local` names no vendor: the local-inference
provider drives an OpenAI-compatible server through the `openai` SDK, so an OpenAI extra is
the answer even for a model running on your own hardware. The env-var messages name the
variable the provider was configured to read (`api_key_env`), not a fixed name — set that variable, or change `api_key_env`. The last three mean the model returned
a shape the structured-output contract does not accept; retry, or fall back to
`analysis.mode: pattern`.
