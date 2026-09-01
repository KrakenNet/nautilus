# Adapters and data sources

Two exception types cover almost everything here, and the difference matters:

- **`ScopeEnforcementError`** (`nautilus/adapters/base.py:32`) — the adapter **cannot honestly
  enforce** what policy asked for. It refuses instead of returning data it cannot vouch for.
  Every one of these is a refusal to over-return.
- **`AdapterError`** (`nautilus/adapters/base.py:28`) — the source itself failed: not connected,
  misconfigured, unreachable, or over a size ceiling.

`SSRFBlockedError` (`nautilus/adapters/rest.py:83`) and `EmbeddingUnavailableError`
(`nautilus/adapters/base.py:40`) are subclasses of `AdapterError`.

## Shared scope validation

Applied by every SQL-shaped adapter through `nautilus/adapters/base.py`.

### `Operator '{op}' not in allowlist: {sorted(_OPERATOR_ALLOWLIST)}`

`validate_operator`, `nautilus/adapters/base.py:107-110`. Rendered example:

```text
Operator 'DROP' not in allowlist: ['!=', '<', '<=', '=', '>', '>=', 'BETWEEN', 'IN',
'IS NULL', 'LIKE', 'NOT IN']
```

The allowlist is closed: an operator that is not on it is refused, never passed through. Fix the
`operator` in the rule or in `context.scope_constraints`.

### `Invalid field identifier '{f}'`

`validate_field`, `nautilus/adapters/base.py:120-123`. The field name does not match
`_FIELD_PATTERN`. Spaces, quotes, semicolons and parentheses are all rejected — the name is
interpolated into a query, so only identifier-shaped strings are allowed.

### `table name {table!r} has more than one schema qualifier`

`quote_table`, `nautilus/adapters/base.py:158-161`. At most one `.` is allowed:
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

`nautilus/adapters/elasticsearch.py:165`, `neo4j.py:134`, `rest.py:192`,
`postgres.py:146`, `influxdb.py:335`.

### `Operator 'BETWEEN' requires a 2-tuple/list value`

Raised twice per adapter — once when the value is not a sequence, once when it does not have
exactly two elements (`postgres.py:154`, `elasticsearch.py:170,175`, `neo4j.py:139,144`,
`rest.py:197,202`, `influxdb.py:288,341`).

### `operator not allowed: {op}`

`elasticsearch.py:371`, `neo4j.py:254,300`, `rest.py:367`. The final guard in an operator switch:
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
`RestAdapter.execute called before connect()` (`rest.py:419`),
`PgVectorAdapter.execute called before connect()` (`pgvector.py:212`),
`S3Adapter.execute called before connect()` (`s3.py:188`),
`ServiceNowAdapter.execute called before connect()` (`servicenow.py:280`),
`LLMAdapter.execute() called before connect()` (`llm.py:184`),
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
(`rest.py:340`), `S3Adapter failed to create client for source '{config.id}': {exc}`
(`s3.py:152`), `ServiceNowAdapter failed to build client for source '{config.id}': {exc}`
(`servicenow.py:187`).

`{exc}` is the driver's own error — DNS failure, refused connection, bad credentials, TLS
mismatch. Read it first; Nautilus adds only the source id.

### `{type(self).__name__}: execute failed for source '{source_id}': {type(exc).__name__}: {exc}`

`wrap_execute`, `nautilus/adapters/base.py:352-358`. The uniform wrapper around a query that
raised. Rendered example:

```text
PostgresAdapter: execute failed for source 'vuln_db': UndefinedTableError:
relation "vulnerabilities" does not exist
```

The inner class name and message belong to the driver.

### `source '{source_id}' declares mTLS but its client certificate could not be loaded (cert_path={auth.cert_path!r}, key_path={auth.key_path!r}): {exc}`

`mtls_context`, `nautilus/adapters/base.py:210-216`. Both paths are echoed so you can see which
one the process actually read. `{exc}` is the `ssl` failure: a missing file, an encrypted key
with no passphrase, or a cert/key pair that does not match.

### `source type '{source_type}' needs its driver: pip install 'nautilus-rkm[{extra}]'`

`nautilus/adapters/__init__.py:49,64`, from the stand-in adapter registered when an optional
driver is unimportable. `connect()` adds the original cause:
`{hint} (import failed: {exc})` (`:56`). Configured sources normally hit the startup
`ConfigError` instead — see [config.md](config.md).

## Size ceilings

| Message | Source | Meaning |
| --- | --- | --- |
| `source '{source_id}' answered with {declared} bytes, over the {MAX_RESPONSE_BYTES}-byte ceiling` | `rest.py:466` | `Content-Length` exceeded the ceiling; refused before reading. |
| `source '{source_id}' streamed more than the {MAX_RESPONSE_BYTES}-byte ceiling` | `rest.py:475` | No `Content-Length`; aborted mid-stream. |
| `source '{source_id}' object {key!r} is {declared} bytes, over the {MAX_OBJECT_BYTES}-byte ceiling` | `s3.py:313` | S3 object too large by its declared size. |
| `source '{source_id}' object {key!r} streamed more than the {MAX_OBJECT_BYTES}-byte ceiling` | `s3.py:321` | S3 object too large while streaming. |
| `sn-attachment-fetch-cap: {len(rows)} rows pinned, cap is {_MAX_ATTACHMENT_FETCHES}` | `servicenow.py:329` | Too many attachment fetches in one request. Narrow the scope. |

Fix by narrowing the query (add scope constraints, request fewer rows) rather than by chasing
the ceiling — it exists so one source cannot exhaust broker memory.

## SSRF guards (REST and LLM adapters)

### `RestAdapter refuses private/loopback/link-local IP base URL: {host}`

`nautilus/adapters/rest.py:222-226`. A `base_url` resolving to a private, loopback or link-local
address would let a rule reach cloud metadata endpoints or internal services. Point the source at
a routable host, or model the internal service as its own source type.

### `Refused redirect from host '{base_host}' to different host '{target_host}' (status={response.status_code})`

`nautilus/adapters/rest.py:513-517`. A 3xx tried to move the request to another host. Redirects
are never followed across hosts.

### `Refused same-host redirect (status={response.status_code}); configure the endpoint path directly to avoid 3xx responses.`

`nautilus/adapters/rest.py:519-522`. Even a same-host redirect is refused; point
`EndpointSpec.path` at the final URL.

### `LLMAdapter requires a non-empty host in base_url '{base_url}'` / `RestAdapter requires a non-empty host in base_url '{base_url}'`

`llm.py:73`, `rest.py:215`. The URL parsed with no netloc — usually a missing `https://`.

### `LLMAdapter refuses link-local/multicast/unspecified base URL host: {host}`

`llm.py:81`.

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

### Postgres and pgvector

| Message | Line |
| --- | --- |
| `PostgresAdapter requires 'table' on source '{config.id}' (Phase 1 shortcut)` | `postgres.py:63` |
| `PostgresAdapter missing 'table' for source '{self._config.id}'` | `postgres.py:190` |
| `PgVectorAdapter requires 'table' on source '{config.id}'` | `pgvector.py:90` |
| `PgVectorAdapter missing 'table' for source '{config.id}'` | `pgvector.py:216` |
| `distance_operator '{distance_operator}' not in allowlist: {sorted(_ALLOWED_DISTANCE_OPERATORS)}` | `pgvector.py:157` |

The `requires` form is raised at connect time, the `missing` form at execute time — the first
means the config is wrong, the second means the adapter was handed a different config later.

### Elasticsearch

| Message | Line |
| --- | --- |
| `ElasticsearchAdapter requires non-empty 'index' on SourceConfig` | `elasticsearch.py:74` |
| `Invalid Elasticsearch index '{index}': must match {_INDEX_PATTERN.pattern}` | `elasticsearch.py:78` |
| `ElasticsearchAdapter could not read the mapping for index '{self._index}': {exc}` | `elasticsearch.py:289` |

Two more refusals are specific to how Elasticsearch indexes text, and both exist to stop a scope
constraint from silently over-returning data. Both are `ScopeEnforcementError`, surfaced as
**HTTP 400** through `/v1/request`, and both are fixed in the index mapping, not in the rule.

#### `ElasticsearchAdapter: field '{field}' is mapped as analysed 'text' with no 'keyword' subfield, so it cannot be matched exactly. An exact-match constraint on it would silently return over-scoped data. Add a keyword subfield to the mapping, or target one explicitly as 'field.<subfield>'.`

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

#### `ElasticsearchAdapter: the only exact subfield for '{field}' is '{field}.{chosen}', which has ignore_above={limit}, and the constraint compares a value of length {longest}. Values over the limit are not indexed, so the comparison would silently return over-scoped data. Raise ignore_above on the mapping, or target a subfield without one as 'field.<subfield>'.`

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

### Neo4j

| Message | Line |
| --- | --- |
| `Neo4jAdapter requires non-empty 'label' on SourceConfig` | `neo4j.py:91` |
| `Invalid Neo4j label '{label}': must match {_LABEL_PATTERN.pattern}` | `neo4j.py:93` |
| `Invalid Neo4j property identifier '{name}'` | `neo4j.py:106` |
| `neo4j: get_schema failed for source '{self._config.id}': {exc}` | `neo4j.py:419` |

### InfluxDB

| Message | Line |
| --- | --- |
| `InfluxDBAdapter: '_time' bound {value!r} is not a Flux duration (e.g. '-30d'), an RFC3339 instant (e.g. '2023-11-14T00:00:00Z') or a Unix-second integer` | `influxdb.py:75` |
| `InfluxDBAdapter: '_time' bound {value!r} is not a time, duration or Unix-second integer` | `influxdb.py:66` |
| `InfluxDBAdapter: operator {op!r} is not expressible as a time range on '_time' (use <, <=, >, >= or BETWEEN)` | `influxdb.py:298` |
| `InfluxDBAdapter: LIKE pattern {pattern!r} uses the '_' single-character wildcard, which Flux cannot express` | `influxdb.py:140` |
| `InfluxDBAdapter: LIKE pattern {pattern!r} has an interior '%' wildcard, which Flux cannot express` | `influxdb.py:148` |
| `InfluxDBAdapter: source '{config.id}' declares auth type {auth.type!r}, which InfluxDB cannot use. Use 'bearer' (token=the InfluxDB API token), or omit 'auth' to read INFLUXDB_V2_TOKEN from the environment.` | `influxdb.py:176` |
| `influxdb: get_schema failed for source '{self._config.id}': {exc}` | `influxdb.py:466` |

The `LIKE` refusals are not bugs to work around: Flux has no equivalent, and translating
approximately would widen the scope.

### S3

| Message | Line |
| --- | --- |
| `S3Adapter: source '{config.id}' declares auth type {auth.type!r}, which S3 cannot use. Use 'basic' (username=access key id, password=secret access key), or omit 'auth' to use the ambient credential chain.` | `s3.py:77` |
| `S3Adapter: unsupported operator '{op}' for field 'key'` | `s3.py:219` |
| `S3Adapter: unsupported operator '{op}' for tag filter` | `s3.py:227` |
| `S3Adapter: unsupported operator '{op}' for classification` | `s3.py:233` |
| `S3Adapter: unsupported scope field '{field}'` | `s3.py:238` |
| `S3Adapter: empty tag name` | `s3.py:225` |
| `S3Adapter: IN operator requires a list value, got {type(value).__name__}` | `s3.py:103` |
| `S3Adapter: LIKE operator requires a string value` | `s3.py:213` |
| `S3Adapter request failed for source '{self._config.id}': {exc}` | `s3.py:285` |

### ServiceNow

Short hyphenated codes, so they are greppable in logs:

| Message | Line | Meaning |
| --- | --- | --- |
| `sn-invalid-field: {field!r}` | `servicenow.py:111` | Field name is not a ServiceNow column identifier. |
| `sn-injection-rejected` | `servicenow.py:143` | A value contained encoded-query syntax (`^`, `,`) that would escape its clause. |
| `sn-unsupported-operator: {op!r}` | `servicenow.py:250` | No encoded-query translation for that operator. |
| `sn-invalid-value: operator {op!r} requires a list, got {type(cast(object, value)).__name__}` | `servicenow.py:220` | — |
| `sn-invalid-value: operator 'BETWEEN' requires a 2-tuple/list` | `servicenow.py:232` | — |
| `sn-invalid-value: operator 'BETWEEN' requires exactly two endpoints` | `servicenow.py:239` | — |
| `ServiceNowAdapter source '{config.id}' has invalid table {table!r} (expected regex '^[a-z][a-z0-9_]*$')` | `servicenow.py:155` | — |
| `servicenow: get_schema failed for source '{self._config.id}': {exc}` | `servicenow.py:405` | — |

### REST

| Message | Line |
| --- | --- |
| `Operator 'NOT IN' is not supported by the REST adapter unless explicitly declared in EndpointSpec.operator_templates (AC-9.3).` | `rest.py:125,373` |
| `RestAdapter source '{config.id}' declares endpoints=[] (must list at least one EndpointSpec or omit the field)` | `rest.py:307` |
| `EndpointSpec.operator_templates declares unknown operator '{op}' for source '{config.id}'` | `rest.py:316` |

### LLM source adapter

| Message | Line |
| --- | --- |
| `LLMAdapter source '{config.id}' requires a 'model' field in its source block` | `llm.py:145` |
| `LLMAdapter source '{config.id}' does not support mTLS auth; use bearer/basic or front the endpoint with a TLS-terminating proxy` | `llm.py:152` |
| `LLMAdapter call failed: {exc}` | `llm.py:204` |
| `LLMAdapter received a non-OpenAI-compatible response shape: {exc}` | `llm.py:206` |

### Static adapter

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
| `anthropic extra not installed; install nautilus[llm-anthropic]` | `anthropic_provider.py:77` |
| `openai extra not installed; install nautilus[llm-openai]` | `openai_provider.py:77` |
| `AnthropicProvider: env var {self.api_key_env!r} is unset or empty` | `anthropic_provider.py:95` |
| `OpenAIProvider: env var {self.api_key_env!r} is unset or empty` | `openai_provider.py:94` |
| `LocalInferenceProvider: env var {self.api_key_env!r} is unset or empty` | `local_provider.py:71` |
| `anthropic SDK call failed: {exc}` | `anthropic_provider.py:128` |
| `openai SDK call failed: {exc}` | `openai_provider.py:130` |
| `anthropic response contained no tool_use block` | `anthropic_provider.py:155` |
| `anthropic tool_use block carried non-dict input: {type(payload)!r}` | `anthropic_provider.py:152` |
| `openai responses.parse returned no output_parsed payload` | `openai_provider.py:134` |

The two `extra not installed` messages say `nautilus[…]` while the distribution on PyPI is
`nautilus-rkm` — install `pip install 'nautilus-rkm[llm-anthropic]'` or
`pip install 'nautilus-rkm[llm-openai]'`. The env-var messages name the variable the provider
was configured to read (`api_key_env`), not a fixed name — set that variable, or change `api_key_env`. The last three mean the model returned
a shape the structured-output contract does not accept; retry, or fall back to
`analysis.mode: pattern`.
