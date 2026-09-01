# Adapter SDK

Reference for everything a third-party adapter touches: the `Adapter`
protocol, the types in its signatures, the scope-enforcement helpers, the two
registration paths, the compliance suite, the `nautilus adapters` commands, and
the exact string the broker emits for each way an adapter can be wrong.

For the empty-directory-to-served-request walkthrough, see
[Developing Adapters](../how-to/developing-adapters.md).

Everything below ships in the `nautilus-rkm` distribution, so an adapter
package needs exactly one dependency:

```toml
dependencies = ["nautilus-rkm"]
```

| What you need | Import from |
| --- | --- |
| `Adapter`, `AdapterError`, `ScopeEnforcementError`, `EmbeddingUnavailableError` | `nautilus.adapters.base` |
| `validate_operator`, `validate_field`, `quote_identifier`, `quote_table`, `render_field` | `nautilus.adapters.base` |
| `row_bytes`, `bounded_rows`, `wrap_execute`, `session_token_headers`, `mtls_context`, `SESSION_TOKEN_HEADER` | `nautilus.adapters.base` |
| `AdapterResult`, `IntentAnalysis`, `ScopeConstraint`, `ScopeOperator`, `ErrorRecord` | `nautilus.core.models` |
| `SourceConfig` | `nautilus.config.models` |
| `AdapterSchema`, `AdapterTable`, `AdapterField` | `nautilus.adapters.schema` |
| `AdapterComplianceSuite` | `nautilus.adapters.testing` |
| `ADAPTER_REGISTRY` (built-in `source_type` → class) | `nautilus.adapters` |

## The `Adapter` protocol

`nautilus.adapters.base.Adapter` is a `@runtime_checkable` `Protocol`. Do not
subclass it — the broker checks conformance structurally, so a plain class with
the right members registers. Six members: four methods, one required class
attribute, one optional one.

### `source_type: ClassVar[str]`

Required. The `type:` key a `sources:` block uses to select this adapter. Must
be a `str` on the class (not an instance attribute, not `None`).

- Loaded by entry point: must equal the entry-point name, or the config
  declares a type that resolves to nothing.
- Loaded by `adapters:` config: must equal the entry's `source_type`, or the
  broker refuses to start (see [Failure catalogue](#failure-catalogue), row 8).

Missing or non-`str` → the class is reported as missing the protocol member
`source_type` and is skipped (entry point) or refuses startup (local path).

### `capabilities: ClassVar[frozenset[str]]`

Optional; omit it unless you need it. The only recognised member is
`"non_deterministic"`. Declare it when `rows` are not byte-reproducible across
identical requests (an LLM-backed source, say):

```python
capabilities: ClassVar[frozenset[str]] = frozenset({"non_deterministic"})
```

`Broker._is_non_deterministic` then omits the source from per-source response
hashing and the signed attestation carries `hash_skipped=True` instead. Omit it
and the broker hashes your rows: a source that legitimately varies will produce
a digest nobody can re-verify. It is deliberately **not** a typed protocol
member, so adding it never breaks `isinstance` or `type[Adapter]`
assignability.

### `async def connect(self, config: SourceConfig) -> None`

Open pools, clients, files. Called **lazily**, once per source, by
`Broker._prepare_adapter` on the first request that routes to it — not at
startup — under a per-source lock so concurrent first requests share one pool.
A source whose `connect` raises is not retried for `Broker.connect_cooldown_s`
(30 s), so a dead backend costs one request its `timeout_s`, not every request.

- **Argument** — `config` is this source's own YAML block, already
  environment-interpolated. Read `config.connection`, `config.table`,
  `config.timeout_s` from here rather than from the environment; keep the
  reference (`self._config = config`) because `execute` needs `config.id`.
- **Returns** — `None`. Anything you return is discarded.
- **Raises** — `AdapterError` on any connectivity or configuration failure.
  The broker converts it into a `sources_errored` entry rather than
  propagating it to the agent.
- **If you skip it** — nothing else calls it for you. `execute` running before
  `connect` is your bug to detect; the scaffold raises
  `AdapterError("<Class>.execute() called before connect()")`.

### `async def execute(self, intent: IntentAnalysis, scope: list[ScopeConstraint], context: dict[str, Any]) -> AdapterResult`

The one method that reads data. Called once per source per request, inside
`asyncio.gather` with every other routed source, under the source's
`timeout_s`.

- **`intent`** — [`IntentAnalysis`](#intentanalysis). What the caller asked
  for, already parsed. Nothing forces you to use it; a source that always
  returns the same projection may ignore it.
- **`scope`** — the router's constraints for **this** source. Every one of them
  must be applied to the rows you return, or refused. See
  [Honouring scope](#honouring-a-scopeconstraint).
- **`context`** — per-request dict. Keys the broker sets: `purpose`,
  `session_id`, `clearance`, and `session_token` when session tokens are
  enabled. Forward the token to downstream HTTP services with
  `session_token_headers(context)`.
- **Returns** — an `AdapterResult`. On success populate `rows` and leave
  `error` as `None`; on a handled failure return an empty `rows` with `error`
  set. Set `source_id=self._config.id` — the broker keys `data` by it, and
  `scope` can be empty so it is not a reliable source of the id.
- **Raises** — `ScopeEnforcementError` for a constraint you cannot enforce;
  `AdapterError` for anything else. Both land in `sources_errored`, typed.
- **If you return the wrong type** — the broker first tries
  `_coerce_adapter_result`: any object with a `model_dump()` that validates as
  an `AdapterResult` is accepted (this is what lets an adapter mirror the model
  instead of importing it). Anything else becomes a `sources_errored` entry
  with `error_type` `AdapterContractError` and the message
  `adapter returned <typename>, expected AdapterResult`. Co-queried sources are
  unaffected.
- **Never** compute your own response hash. `AdapterResult` has no
  `response_hash` field on purpose: the chain-of-custody digest is computed by
  the broker over the rows it actually returns, so a buggy or hostile adapter
  cannot inject a digest into the signed attestation.

### `async def close(self) -> None`

Release resources. **Must be idempotent** — the compliance suite calls it
twice, and the broker calls it on shutdown after paths that may already have
closed. Guard with a flag:

```python
async def close(self) -> None:
    if self._closed:
        return
    self._closed = True
    await self._pool.aclose()
```

Returns `None`. Raising on the second call fails
`test_idempotent_close`.

### `async def get_schema(self) -> AdapterSchema`

Optional in practice, present on the protocol. Returns the surface the broker
fingerprints for drift detection. The protocol's default implementation raises

```
NotImplementedError: AC-21.b: this adapter must implement get_schema() (task-006)
```

so registration still succeeds and only `nautilus adapters schema` /
`schema-fingerprint` / `schema-diff` fail, at the moment they are called.

Return `AdapterSchema.unknown(adapter_id, source_type)` when the backend has no
introspectable schema (an object store). That is honest — it means "no baseline
to compare against". It is the wrong answer for a backend that *does* have a
schema, because drift then goes undetected.

## Types in the signatures

### `SourceConfig`

`nautilus.config.models.SourceConfig`, one per `sources:` entry, `extra="forbid"`.
All 25 fields, in declaration order. "Required" is what the model itself
demands; the conditional rules below add more for specific `type:` values.

| Field | Type | Required | Default | Meaning for you |
| --- | --- | --- | --- | --- |
| `id` | `str` | yes | — | The key the broker files your rows under. Put it in `AdapterResult.source_id`. |
| `type` | `str` | yes | — | Matches your `source_type`. An open `str`, not a `Literal`, so entry-point and `adapters:` types are accepted; unknown ones still fail at load (row 5 of the [catalogue](#failure-catalogue)). |
| `description` | `str` | no | `""` | Free text for whoever reads the config. Nothing in `nautilus/` reads it. |
| `classification` | `str` | yes | — | Policy input; you do not enforce it. |
| `data_types` | `list[str]` | yes | — | What the router matches against the intent. |
| `allowed_purposes` | `list[str] \| None` | no | `None` | Policy input. |
| `max_response_bytes` | `int \| None` | no | `8388608` | Must be `> 0`; `null` removes the bound. The broker trims to it after you return. See [Truncation](#truncation). |
| `connection` | `str` | no | `""` | DSN / base URL / path, after `${ENV}` interpolation. Required non-empty for the built-in types that dial out (below). |
| `rows` | `list[dict[str, Any]]` | no | `[]` | Inline rows, straight from the YAML. `static` only. |
| `table` | `str \| None` | no | `None` | Table or collection name. |
| `embedding_column` | `str \| None` | no | `None` | pgvector only: the vector column. Unset, the adapter uses `"embedding"`. |
| `metadata_column` | `str \| None` | no | `None` | pgvector only: the metadata column. Unset, the adapter uses `"metadata"`. |
| `distance_operator` | `Literal["<=>", "<->", "<#>"] \| None` | no | `"<=>"` | pgvector only: the operator spliced into `ORDER BY <embedding_column> <op> $E`. Re-checked against the same three in the adapter, so it is never interpolated unchecked; `null` falls back to `<=>`. |
| `top_k` | `int` | no | `10` | pgvector only: the `LIMIT` on the nearest-neighbour query. |
| `embedder` | `Literal["default"] \| None` | no | `None` | Only `default` (the broker-wide embedder) resolves; there is no embedder registry, so any other name is rejected at config load rather than failing every request with `EmbeddingUnavailableError`. |
| `index` | `str \| None` | no | `None` | elasticsearch only: the index, validated in `connect`. |
| `label` | `str \| None` | no | `None` | neo4j only: the node label, validated against `^[A-Z][A-Za-z0-9_]*$` in `connect`. |
| `endpoints` | `list[EndpointSpec] \| None` | no | `None` | rest / servicenow endpoint descriptors — see the table below. `[]` is refused; the REST adapter reads `endpoints[0]` only. |
| `auth` | `BearerAuth \| BasicAuth \| MtlsAuth \| NoneAuth \| None` | no | `None` | Discriminated on `type` — see the table below. `mtls_context(config.auth, config.id)` turns an `MtlsAuth` into an `ssl.SSLContext`. |
| `compartments` | `str` | no | `""` | Pipe-delimited compartment list, asserted verbatim as the source's `compartments` fact by the router. Policy input; you do not enforce it. |
| `sub_category` | `str` | no | `""` | Declared classification metadata. Nothing in `nautilus/` reads it. |
| `purpose_field` | `str` | no | `""` | Column a purpose-scoping rule constrains on. Left empty, a pack that scopes by purpose denies the source rather than over-returning it. |
| `like_style` | `Literal["starts_with", "regex"]` | no | `"starts_with"` | How a `LIKE` constraint is rendered by an adapter that reads it. The neo4j adapter emits `STARTS WITH $p` for `starts_with` and `=~ $p` for `regex` (and logs a WARN at `connect` for `regex`); no other built-in adapter reads the field. See [Honouring a `ScopeConstraint`](#honouring-a-scopeconstraint). |
| `model` | `str \| None` | no | `None` | llm only: the model name sent to the OpenAI-compatible endpoint at `connection`. |
| `timeout_s` | `float \| None` | no | `15.0` | Per-source wall-clock budget for one connect+execute. The broker enforces it around `execute`; `null` waits indefinitely. |

Two conditional rules run in a `model_validator` on this model, so they are load
errors, not runtime ones:

- **Mandatory field by type.** `table` for `postgres`, `pgvector`, `servicenow`;
  `index` for `elasticsearch`; `label` for `neo4j`; `model` for `llm`; `rows`
  for `static`. Missing → `source '<id>' has type '<type>' but no '<field>'. The
  <type> adapter requires it, so every request to this source would fail at
  runtime.` (`rest` is deliberately absent: `endpoints` is optional by design.)
- **Non-empty `connection`** for `postgres`, `pgvector`, `elasticsearch`,
  `rest`, `neo4j`, `servicenow`, `influxdb`, `s3`, `llm`. Missing → `source
  '<id>' has type '<type>' but no 'connection'. The <type> adapter has nothing
  to dial, so every request to this source would fail at runtime.`

Neither rule covers a third-party `type`: the model cannot know what your
adapter needs, so validate it in `connect` and raise `AdapterError`.

**`EndpointSpec`** (`nautilus.config.models.EndpointSpec`, `extra="forbid"`) —
one entry of `endpoints`:

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `path` | `str` | yes | — | Appended to `connection`. The REST adapter uses `""` when no endpoint is declared. |
| `method` | `Literal["GET", "POST", "PUT", "PATCH", "DELETE"]` | no | `"GET"` | HTTP method for the request. |
| `path_params` | `list[str]` | no | `[]` | Declared; no adapter in `nautilus/` reads it. |
| `query_params` | `list[str]` | no | `[]` | Declared; no adapter in `nautilus/` reads it. |
| `operator_templates` | `dict[str, str]` | no | `{}` | Per-operator query templates. Opts an endpoint into operators the REST adapter otherwise refuses (`NOT IN`: `Operator 'NOT IN' is not supported by the REST adapter unless explicitly declared in EndpointSpec.operator_templates (AC-9.3).`). Keys are checked against the operator allowlist at `connect`: `EndpointSpec.operator_templates declares unknown operator '<op>' for source '<id>'`. |

**`auth`** — `AuthConfig`, a union discriminated on `type`, all four
`extra="forbid"`:

| `type` | Class | Fields |
| --- | --- | --- |
| `bearer` | `BearerAuth` | `token: str` (required) |
| `basic` | `BasicAuth` | `username: str`, `password: str` (both required) |
| `mtls` | `MtlsAuth` | `cert_path: str`, `key_path: str` (both required); `ca_path: str \| None`, default `None` |
| `none` | `NoneAuth` | none — the explicit no-auth marker |

Anything a custom adapter needs that is not on this model has no place to live
in `nautilus.yaml` — `SourceConfig` rejects unknown keys.

### `IntentAnalysis`

`nautilus.core.models.IntentAnalysis`:

| Field | Type |
| --- | --- |
| `raw_intent` | `str` (≤ 8192 chars, `MAX_INTENT_LENGTH`) |
| `data_types_needed` | `list[str]` |
| `entities` | `list[str]` |
| `temporal_scope` | `str \| None` |
| `estimated_sensitivity` | `str \| None` |

It is a *hint*, not a query. Never interpolate `raw_intent` into a query
string.

### `ScopeConstraint`

`nautilus.core.models.ScopeConstraint` — one row-level predicate the policy
engine attached to your source.

| Field | Type | Contract |
| --- | --- | --- |
| `source_id` | `str` | Always your source. |
| `field` | `str` | Identifier, or one dotted pair for JSON access. Validate with `validate_field`. |
| `operator` | `ScopeOperator` | One of the eleven below. |
| `value` | `Any` | Operator-dependent: scalar, `list` for `IN`/`NOT IN`, two-element sequence for `BETWEEN`, ignored for `IS NULL`. |
| `expires_at` | `str \| None` | **Broker-enforced, not yours.** |
| `valid_from` | `str \| None` | **Broker-enforced, not yours.** |

`ScopeOperator` is the `Literal` pinning the eleven operators; the runtime
`_OPERATOR_ALLOWLIST` in `nautilus.adapters.base` holds the same eleven, and a
drift-guard test keeps them equal:

```
=   !=   IN   NOT IN   <   >   <=   >=   LIKE   BETWEEN   IS NULL
```

`expires_at` / `valid_from` never reach you unsatisfied:
`Broker._apply_temporal_filter` runs `TemporalFilter.apply` before fan-out and
denies the source with a `scope-expired` `DenialRecord` if the window has
closed. Do not re-implement the check; do not assume a constraint you received
is expired.

### Honouring a `ScopeConstraint`

"Honour" means one of exactly two things, per constraint, **before** any data
leaves the backend:

1. **Apply it** — push the predicate into the query (`WHERE "field" = $1`) or
   filter the rows you are about to return.
2. **Refuse it** — `raise ScopeEnforcementError` naming the operator and field.

There is no third option. Returning rows that ignore a constraint is a silent
over-scope: the response, the audit entry and the signed attestation all record
that the constraint was applied, because the broker records what the router
issued. **Nothing downstream re-checks your rows against `scope`.** The
per-source digest proves the rows were not altered in transit; it proves
nothing about whether they were scoped.

What each operator means for a row `r`, and the shape of `value`:

| Operator | `value` | Row passes when |
| --- | --- | --- |
| `=` | scalar | `r[field] == value` |
| `!=` | scalar | `r[field] != value` |
| `IN` | list | `r[field]` in the list |
| `NOT IN` | list | `r[field]` not in the list |
| `<` `>` `<=` `>=` | scalar | the ordering holds |
| `LIKE` | pattern | matches, `%` as wildcard (`SourceConfig.like_style` selects `starts_with` or `regex` semantics for sources that use it) |
| `BETWEEN` | two-element sequence | `value[0] <= r[field] <= value[1]` |
| `IS NULL` | ignored | `r[field]` is null/absent |

A backend that cannot express one of these — an API with a fixed query shape,
say — must raise rather than approximate. Approximating `!=` as "return
everything" is the failure this contract exists to prevent.

### `AdapterResult`

`nautilus.core.models.AdapterResult`:

| Field | Type | Notes |
| --- | --- | --- |
| `source_id` | `str` | Required. Use `config.id`. |
| `rows` | `list[dict[str, Any]]` | Required. JSON-serialisable values. |
| `duration_ms` | `int` | Required. Your own measurement. |
| `error` | `ErrorRecord \| None` | Default `None`. Set it *or* raise, not both. |
| `truncated` | `bool` | Default `False`. Set `True` when you capped the row set yourself. |

There is no `response_hash` field, by design (see `execute` above).

### `ErrorRecord`

`nautilus.core.models.ErrorRecord`:

| Field | Type | Notes |
| --- | --- | --- |
| `source_id` | `str` | Required. Use `config.id`. |
| `error_type` | `str` | Required. Conventionally the exception class name. |
| `message` | `str` | Required. |
| `trace_id` | `str` | Leave empty (`""`) — `_gather_adapter_results` fills in the request id, because `execute` cannot see it. Records that arrive with a `trace_id` already set are left alone. |
| `endpoint` | `str \| None` | Default `None`. Leave it unset. |

`endpoint` is the address the source dials, as `scheme://host[:port]`, and it
is what makes a failed source answerable — a `source_id` is the operator's
label for a dependency, not the dependency's address. Leave it `None` and the
broker fills it from the source's `connection` (`redact_connection`, which
copies scheme, host and port out and nothing else, so a DSN password or a URL
token cannot reach the audit trail or the requesting agent). Set it yourself
only if your adapter dials somewhere its `connection` does not name — the
broker leaves a non-`None` value alone, so stripping credentials is then your
job.

### `AdapterSchema`

`nautilus.adapters.schema.AdapterSchema` (frozen dataclass):

| Member | Type / signature |
| --- | --- |
| `adapter_id` | `str` |
| `source_type` | `str` |
| `tables` | `tuple[AdapterTable, ...]` |
| `capability_flags` | `Mapping[str, bool]` |
| `fetched_at` | `datetime` |
| `AdapterSchema.unknown(adapter_id, source_type)` | classmethod → `AdapterSchema` with empty `tables` and flags |
| `schema.fingerprint()` | `str`, `"sha256:<hex>"` over the canonical JSON |

`fetched_at` is excluded from the fingerprint, so re-reading an unchanged
schema is not drift.

`tables` holds `AdapterTable` (frozen dataclass), each holding `AdapterField`
(frozen dataclass). Both are positional dataclasses, not models — nothing
validates them, so what you construct is what gets fingerprinted:

| Class | Member | Type | Required | Default |
| --- | --- | --- | --- | --- |
| `AdapterTable` | `name` | `str` | yes | — |
| `AdapterTable` | `fields` | `tuple[AdapterField, ...]` | yes | — |
| `AdapterTable` | `indexes` | `tuple[str, ...]` | no | `()` |
| `AdapterTable` | `primary_key` | `tuple[str, ...]` | no | `()` |
| `AdapterField` | `name` | `str` | yes | — |
| `AdapterField` | `type` | `str` | yes | — |
| `AdapterField` | `nullable` | `bool` | yes | — |
| `AdapterField` | `description` | `str` | no | `""` |

`AdapterField.type` is the backend's own type name as a string — nothing parses
it, but `classify_drift` compares it, and a change is `major` drift at
`tables.<table>.<field>.type`.

## Exceptions

| Class | Base | Raise it when |
| --- | --- | --- |
| `AdapterError` | `Exception` | Any adapter-layer failure. The broker turns it into a `sources_errored` entry with `error_type="AdapterError"`. |
| `ScopeEnforcementError` | `AdapterError` | A constraint's operator or field is one you cannot enforce. |
| `EmbeddingUnavailableError` | `AdapterError` | No embedder can vectorise the request (pgvector-shaped adapters). |

Nothing an adapter raises reaches the agent as an exception; every one becomes
a per-source error record, and the other sources in the same request still
answer.

## Scope-enforcement and helper API

All in `nautilus.adapters.base`.

| Signature | Returns | Raises |
| --- | --- | --- |
| `validate_operator(op: str) -> None` | — | `ScopeEnforcementError: Operator '<op>' not in allowlist: ['!=', '<', '<=', '=', '>', '>=', 'BETWEEN', 'IN', 'IS NULL', 'LIKE', 'NOT IN']` |
| `validate_field(f: str) -> None` | — | `ScopeEnforcementError: Invalid field identifier '<f>'` — the pattern is `^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$` |
| `quote_identifier(ident: str) -> str` | `"ident"`, validated first | `ScopeEnforcementError` via `validate_field` |
| `quote_table(table: str) -> str` | `"schema"."table"` or `"table"` | `ScopeEnforcementError: table name '<t>' has more than one schema qualifier` |
| `render_field(field: str) -> str` | `"col"`, or `"jsonb_col"->>'key'` for a dotted field | `ScopeEnforcementError` |
| `row_bytes(row: dict[str, Any]) -> int` | JSON length + 1, the same estimate the transport uses | — |
| `bounded_rows(rows, max_bytes) -> tuple[list[dict], bool]` | rows cut to the budget, and whether anything was dropped. Whole rows only; always keeps at least one | — |
| `session_token_headers(context: dict[str, Any]) -> dict[str, str] \| None` | `{"X-Nautilus-Session-Token": <jws>}` or `None` | — |
| `mtls_context(auth: MtlsAuth, source_id: str) -> ssl.SSLContext` | TLS context from the source's `auth: {type: mtls}` block | `AdapterError` naming `cert_path` / `key_path` if the material will not load |
| `await resolve_base_url(base_url: str, adapter: str) -> tuple[str, list[IPv4Address \| IPv6Address]]` | The host of `base_url` and every address it resolves to right now; an IP literal resolves to itself, an unresolvable name yields `[]`. The seam both SSRF guards run on — see [the SSRF entry](errors/adapters.md#ssrf-guards-rest-and-llm-adapters) for what it can and cannot promise | `ScopeEnforcementError` when `base_url` has no host |
| `wrap_execute(fn) -> fn` | Decorator: re-raises a driver's own exception as `AdapterError: <Class>: execute failed for source '<id>': <ExcType>: <msg>`, dropping `: <msg>` when the exception has no text | — |
| `SESSION_TOKEN_HEADER` | `"X-Nautilus-Session-Token"` | — |

`wrap_execute` passes `AdapterError` (and therefore `ScopeEnforcementError`)
through untouched, so a refused constraint stays distinguishable from an
infrastructure failure. Decorate `execute` with it if your driver raises its
own exception types:

```python
from nautilus.adapters.base import wrap_execute

class MyAdapter:
    @wrap_execute
    async def execute(self, intent, scope, context) -> AdapterResult: ...
```

## Registration

Two paths, and one built-in table.

### Entry points — `nautilus.adapters`

`nautilus.adapters` is the only entry-point group the adapter loader reads.
It is read twice, for different reasons:

- `Broker._discover_adapters` loads each target and merges the results **over**
  `ADAPTER_REGISTRY`.
- `nautilus.config.loader._extra_source_types` reads the *names* only, so
  config validation accepts a source type an installed package advertises.
  Because it never loads the target, a broken entry point passes config
  validation and fails later at `_build_adapter` (rows 1–3 of the
  [catalogue](#failure-catalogue)).

(`fathom.packs` is the entry-point group for rule packs, not adapters.
`RulesConfig.packs` resolves names against it.)

```toml
[project.entry-points."nautilus.adapters"]
my-csv = "my_csv_adapter:MyCsvAdapter"
my-adapter = "my_csv_adapter.extra:MyAdapter"
```

One line per source type; a package may advertise several, and the target may
point into a submodule. The entry-point **name** is the `source_type`; the
**target** must be the adapter class, `module:Class` — never a bare module,
which discovery skips with a warning so the adapter never registers (row 1 of
the [catalogue](#failure-catalogue)). Discovery is best-effort — a broken
third-party package is logged and skipped, never fatal — and one line is logged
per success:

```
INFO:nautilus.core.broker:discovered adapter entry-point 'my-csv' -> MyCsvAdapter (from 'my-csv-adapter')
```

An entry point may not take over a built-in source type. Name collisions with
`ADAPTER_REGISTRY` are refused unless the target *is* that built-in (nautilus
advertises its own optional adapters through this group).

### Local path — the `adapters:` config block

`nautilus.config.models.LocalAdapterConfig`, three keys, all required:

```yaml
adapters:
  - module_path: ./adapters/csv_adapter.py   # relative to the config file
    class: MyCsvAdapter                      # field name is class_name; the YAML key is 'class'
    source_type: my-csv
```

| YAML key | Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- | --- |
| `module_path` | `module_path` | `str` | yes | — | Path to the `.py` file, resolved relative to the config file. |
| `class` | `class_name` | `str` | yes | — | Attribute in that module holding the adapter class. `class` is a Python keyword, hence the alias. |
| `source_type` | `source_type` | `str` | yes | — | Must equal the class's `source_type` ClassVar (row 8 of the [catalogue](#failure-catalogue)). |

Unlike entry points, these are explicit operator config and **fail closed**:
a missing file, an import error, a missing or non-class attribute, a protocol
gap, or a `source_type` mismatch raises `ConfigError` and the broker does not
start. A partial load leaves nothing behind — every module registered so far is
removed from `sys.modules` before the error propagates.

!!! warning "Trust boundary"
    The module is executed at broker start with the broker's privileges.
    `adapters:` entries carry the same trust as installed packages; the config
    file must only be writable by the operator.

### Precedence and the built-in table

`nautilus.adapters.ADAPTER_REGISTRY` maps built-in `source_type` → class and is
public API. Its ten keys: `postgres`, `pgvector`, `elasticsearch`, `neo4j`,
`rest`, `servicenow`, `influxdb`, `s3`, `llm`, `static`.

Precedence when the same `source_type` is declared more than once:
**built-ins < entry points < local paths.** Built-ins whose driver extra is not
installed sit in the table as stand-ins carrying two extra ClassVars —
`missing_extra: ClassVar[str]` (the extra to install) and
`import_error: ClassVar[str]` (the original `ImportError`, stringified) — so
startup fails with an install hint (row 24 of the
[catalogue](#failure-catalogue)) rather than an import error mid-request.

## Compliance suite

`nautilus.adapters.testing.AdapterComplianceSuite`. Five checks, all `async`,
all independent — each builds its own adapter from the factory.

```python
AdapterComplianceSuite(
    adapter_factory: Callable[[], Any],
    source_config: SourceConfig,
)
```

`adapter_factory` is called with no arguments (pass the class itself when
`__init__` takes none). `source_config` is the config every check connects
with.

What each check feeds the adapter: `IntentAnalysis(raw_intent="test query",
data_types_needed=["generic"], entities=[])`; context `{"purpose": "testing",
"session_id": "compliance", "clearance": "unclassified"}`; and a single
constraint built with `ScopeConstraint.model_construct(source_id=<config.id>,
operator=<op>, field="id", value=<v>)`, where `<v>` is `"test"` except for the
enforcement check's refuting probe — `model_construct` because the
invalid-operator check has to build a value the `Literal` forbids.

| Method | What it does | Fails with |
| --- | --- | --- |
| `test_connect_execute_close_lifecycle()` | `connect` → `execute` (operator `=`) → asserts the result → `close` | `AssertionError: execute must return an AdapterResult, got <typename>` |
| `test_scope_enforcement_valid_operator()` | Two `execute` calls: `id = "test"`, then `id = "nautilus-compliance-no-such-id-8f4c1e0a"`. No row from the second may carry a different `id`, and the two runs may not return identical rows. Closes in `finally` | `AssertionError: the adapter returned N row(s) that contradict the scope constraint it accepted`, or `AssertionError: ... the constraint changed nothing`, or whatever `execute` raised |
| `test_scope_enforcement_invalid_operator()` | `execute` with operator `INVALID_OP` must raise `ScopeEnforcementError` | `AssertionError: an unsupported scope operator must raise ScopeEnforcementError` |
| `test_idempotent_close()` | `connect`, then `close()` twice | whatever the second `close()` raised |
| `test_error_path_reports_the_failure()` | `execute` with `raw_intent="__compliance_error_trigger__"`, `data_types_needed=["nonexistent"]`. Passes if it raises `AdapterError` **or** returns an `AdapterResult` | `AssertionError: the error path must return an AdapterResult carrying an ErrorRecord, or raise AdapterError; got <typename>` |

Scope of the suite, stated plainly: it checks *shape, fail-closed behaviour,
and that a constraint you accept actually narrows the rows*. It does not check
that your filtering is correct for every operator, that `get_schema` works, or
that `duration_ms` is real. Write your own tests for those.

The enforcement check is not optional politeness. The broker does not re-read
returned rows against the constraint it issued — it records that constraint in
`BrokerResponse.scope_restrictions`, in the audit entry, and in the signed
attestation, all of which say it was applied. This suite is the only thing
standing between an adapter that ignores the constraint and a signed receipt
that says it did not. Returning unfiltered rows used to pass all five checks.

If your source returns no rows for `id = "test"`, the check cannot tell an
enforcing adapter from an ignoring one, and warns rather than fails:

```
UserWarning: AdapterComplianceSuite could not verify scope enforcement: the
source returned no rows for id = 'test', ...
```

A freshly scaffolded adapter points at a backend the suite cannot seed, so that
warning is expected on the first run. Point `source_config` at a fixture holding
a row with `id = "test"` to make the check bite — until you do, you have four
checks, not five.

`nautilus adapters new` generates `tests/test_compliance.py` wiring all five
into pytest classes; keep them green as you replace the stub.

## `nautilus adapters` commands

Six subcommands. `--config` defaults to `./nautilus.yaml` when present, except
where marked required.

| Command | Arguments | Does | Exit 1 when |
| --- | --- | --- | --- |
| `nautilus adapters new NAME` | `--dir DIR` (default `.`) | Copier-scaffolds a package at `DIR/NAME` and prints the source type, class and next steps | `ERROR: invalid adapter name '<n>' (expected lowercase-dashed, e.g. my-csv-adapter)` — the pattern is `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`; `ERROR: destination already exists and is not empty: <path>`; `ERROR: copier is required for 'adapters new' — install it with: pip install copier` |
| `nautilus adapters list` | `--config`, `--url`, `--api-key`, `--status {active,quarantined}`, `--json` | Without `--url`: loads the config and prints `  <id>  type=<type>  status=configured` per source. With `--url`: `GET /v1/adapters` for live status | `ERROR: could not load <path>: <ConfigError>`; `ERROR: no config found: pass --config PATH, or run from a directory containing nautilus.yaml`; `ERROR: --status '<s>' needs --url: quarantine state lives in the serving process…` |
| `nautilus adapters schema NAME` | `--config`, `--json` | Connects the source named by `NAME` (a source `id`) and prints its `AdapterSchema` field by field | `ERROR: could not load <path>: <ConfigError>`; `ERROR: no schema available for adapter '<n>'` |
| `nautilus adapters schema-fingerprint NAME` | `--config` | Prints `sha256:<hex>` for the live schema | same as above |
| `nautilus adapters schema-diff NAME` | `--config` (required), `--json` | Compares live fingerprint against the stored baseline. Prints `OK: no drift for '<n>' (fingerprint matches)`, or `WARN: no stored fingerprint for '<n>'; treating as new`, or the stored/current pair followed by `DRIFT DETECTED`. JSON `status` is one of `clean`, `no_baseline`, `drift` | `ERROR: could not load <path>: <ConfigError>` — its only non-zero exit once argparse is satisfied. Drift itself is reported, not an error exit |
| `nautilus adapters schema-ack NAME` | `--config` (required), `--reason` (required), `--yes` (required) | Records the current fingerprint as the accepted baseline and emits a `schema_drift_severity_overridden` event. Prints `OK: schema-ack recorded for '<n>' by <reviewer>: <reason>` | `ERROR: schema-ack requires --yes to confirm`; missing `NAUTILUS_REVIEWER` env; `ERROR: could not load <path>: <ConfigError>`; `ERROR: no schema available for adapter '<n>'; cannot ack`; `ERROR: this acknowledgement cannot be recorded, so it will not be made: …` (exit `2`) when `audit.chained: true` and a running server holds the log's writer lock — the baseline is left untouched |

`status=configured`, never `active`: the CLI process is not the one serving
requests, so it cannot know whether an adapter is connected or quarantined.
Only `--url` can answer that.

## Truncation

Two independent caps can shorten a result, and the caller is told either way.

1. **Yours.** If you cap the row set inside `execute`, set
   `AdapterResult.truncated=True`. `bounded_rows(rows, budget)` returns the cut
   list and the flag.
2. **The broker's.** After `execute` returns, `Broker._bound_rows` trims the
   rows to the source's `max_response_bytes` (default 8 MiB) using the same
   `row_bytes` estimate, keeping whole rows and never fewer than one. It logs

   ```
   WARNING:nautilus.core.broker:source 'demo_rows' returned more than max_response_bytes (40); kept 1 of 2 rows
   ```

   and sets `truncated=True` on the result.

Either way the source id appears in `BrokerResponse.truncated_sources`, so the
caller can tell a partial answer from an exhaustive one:

```json
"data": {"demo_rows": [{"id": "1", "name": "alpha"}]},
"truncated_sources": ["demo_rows"]
```

Trimming happens *after* your rows exist, so it is a response bound, not a
memory bound: an adapter that can stop reading early (the postgres adapter
streams and breaks at the budget) should do so.

Returning **more than the scope allows** is a different thing entirely and has
no such backstop — see [Honouring a `ScopeConstraint`](#honouring-a-scopeconstraint).

## Failure catalogue

Exact strings, where they come from, and what to do. `<...>` marks the
interpolated part.

| # | Situation | Exact output | Fix |
| --- | --- | --- | --- |
| 1 | Entry point targets a module, not a class | `adapter entry-point 'my-csv' resolved to non-class module; skipping` (WARNING, `nautilus.core.broker`) then at startup `ERROR: could not load nautilus.yaml: Unsupported source type 'my-csv' for id='<source>'` | Change the target to `module:Class`. |
| 2 | Entry-point target is missing a protocol member | `adapter entry-point 'my-csv' resolved to <Class>, which is missing Adapter protocol members ['connect', 'execute', 'close', 'source_type']; skipping` (only the missing ones are listed) | Add the members; `source_type` must be a `str` class attribute. |
| 3 | Entry point fails to import | `failed to load adapter entry-point 'my-csv' (<module:Class>); skipping` with the traceback attached | Fix the import; `python -c "import my_csv_adapter"`. |
| 4 | Entry point collides with a built-in | `refusing adapter entry-point 'static' from distribution 'my-csv-adapter': it would replace the built-in StaticAdapter. Register it under a source type of its own, or name it explicitly in the config's 'adapters' block.` | Rename the entry point, or load it via `adapters:`. |
| 5 | Config declares a type nothing provides | `ERROR: could not load nautilus.yaml: Unsupported source type='my-csvv' for id='rows' (supported: ['elasticsearch', 'influxdb', 'llm', 'my-csv', 'neo4j', 'pgvector', 'postgres', 'rest', 's3', 'servicenow', 'static'])` — the list is every built-in plus every advertised entry-point name plus every `adapters:` `source_type` | Check the spelling against the printed list; if your type is absent the package is not installed in this environment. |
| 6 | Type is known but the class never registered (rows 1–3) | `ERROR: could not load nautilus.yaml: Unsupported source type 'my-csv' for id='rows'` — note: no `supported:` list, and quoted differently. This is `Broker._build_adapter`, past config validation | Read the WARNING above it; that names the real cause. |
| 7 | Local-path module is missing | `ERROR: could not load nautilus.yaml: adapters[1]: module_path does not exist or is not a file: adapters/gone.py` | Path is relative to the **config file**, not the working directory. |
| 8 | Local-path `source_type` mismatch | `ERROR: could not load nautilus.yaml: adapters[1]: declared source_type='refusr' does not match RefuserAdapter.source_type='refuser' in adapters/refuser.py` | Make the YAML key and the ClassVar agree. |
| 9 | Local-path class incomplete | `ERROR: could not load nautilus.yaml: adapters[1]: 'NoCloseAdapter' in adapters/noclose.py does not implement the Adapter protocol (missing: ['close'])` | Implement the listed members. Local paths fail closed — the broker will not start. |
| 10 | Local-path class not found / not a class / import error | `adapters[<i>]: class '<Name>' not found in <path>` · `adapters[<i>]: '<Name>' in <path> is not a class` · `adapters[<i>]: error executing <path>: <exc>` | As printed. |
| 11 | `execute` returns the wrong type | In `sources_errored`: `{"source_id": "bad_rows", "error_type": "AdapterContractError", "message": "adapter returned dict, expected AdapterResult", "trace_id": "<request_id>", "endpoint": null}` | Return an `AdapterResult` (or any object whose `model_dump()` validates as one). Other sources in the request are unaffected. |
| 12 | Adapter refuses a constraint | In `sources_errored`: `{"source_id": "refused_rows", "error_type": "ScopeEnforcementError", "message": "RefuserAdapter cannot enforce '=' on field 'name'", "trace_id": "<request_id>", "endpoint": null}` | Expected behaviour when the backend cannot express the predicate. To serve the source, implement the operator. |
| 13 | Operator outside the allowlist reaches a validator | `ScopeEnforcementError: Operator 'REGEX' not in allowlist: ['!=', '<', '<=', '=', '>', '>=', 'BETWEEN', 'IN', 'IS NULL', 'LIKE', 'NOT IN']` | Only the eleven are routable. A policy rule asserting anything else is the bug. |
| 14 | Bad field identifier | `ScopeEnforcementError: Invalid field identifier 'user-id'` | Identifiers must match `^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`; one dot is allowed, for JSON access. |
| 15 | Driver exception escapes a `@wrap_execute` method | `AdapterError: MyAdapter: execute failed for source 'rows': PostgresSyntaxError: syntax error at or near "FROM"` | Fix the query; the wrapper only re-labels. |
| 16 | `get_schema` not implemented | `NotImplementedError: AC-21.b: this adapter must implement get_schema() (task-006)` | Implement it, or return `AdapterSchema.unknown(...)` if the backend has no schema. |
| 17 | Compliance check fails: no fail-closed on a bad operator | `E   AssertionError: an unsupported scope operator must raise ScopeEnforcementError` / `FAILED tests/test_compliance.py::TestMyCsvAdapterCompliance::test_invalid_operator` | Raise `ScopeEnforcementError` for every operator you do not implement — do not fall through. |
| 18 | Compliance check fails: wrong return type | `E   AssertionError: execute must return an AdapterResult, got dict` | Return `AdapterResult`. |
| 19 | Compliance check fails: error path returns junk | `E   AssertionError: the error path must return an AdapterResult carrying an ErrorRecord, or raise AdapterError; got NoneType` | Raise `AdapterError`, or return an `AdapterResult` with `error` set. |
| 20 | `connect` raised on first use | In `sources_errored`: `{"source_id": "orders", "error_type": "AdapterError", "message": "connect() failed: source 'orders': cannot read orders.csv: [Errno 2] No such file or directory: 'orders.csv'", …}` — the prefix is `connect() failed: ` and `error_type` is the raised exception's own class name, so raising `AdapterError` is what keeps this readable | Fix the backend or the `connection` value; relative paths resolve from the broker's working directory. |
| 21 | A source in cooldown after a failed connect | In `sources_errored`: `{"error_type": "AdapterError", "message": "connect() failed 0.0s ago; not retried for another 30.0s", …}` | Wait out `Broker.connect_cooldown_s` (30 s) after fixing the cause; the next request reconnects. |
| 22 | Source quarantined by schema drift | In `sources_errored`: `{"error_type": "ADAPTER_QUARANTINED", "message": "Adapter 'orders' is quarantined due to major schema drift. Operator must acknowledge drift via schema-ack before resuming.", …}` | Review with `nautilus adapters schema-diff`, then `schema-ack --reason … --yes` with `NAUTILUS_REVIEWER` set. |
| 23 | Source has no adapter at request time | In `sources_errored`: `{"error_type": "AdapterError", "message": "No adapter registered for source 'orders'", …}` | The source is configured but its class never registered; see rows 1–4. |
| 24 | Built-in type whose driver extra is missing | `ERROR: could not load nautilus.yaml: source id='rows' has type 'postgres', whose driver is not installed: pip install 'nautilus-rkm[postgres]' (import failed: No module named 'asyncpg')` | Install the named extra. |
