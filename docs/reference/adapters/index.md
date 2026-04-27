# Adapter Implementations

Nautilus brokers data through a registry of adapters, each implementing the
`Adapter` Protocol from `nautilus_adapter_sdk` (or the in-tree
`nautilus.adapters.base.Adapter`). The broker selects an adapter via the
`type` field on each `SourceConfig` block.

## Built-in & first-party adapters

| `source_type` | Package | Transport | Auth modes | Writes? | Article |
|---|---|---|---|---|---|
| `postgres` | core (`nautilus.adapters.postgres`) | asyncpg | DSN env-interpolation | ❌ | (covered in core SDK reference) |
| `pgvector` | core (`nautilus.adapters.pgvector`) | asyncpg + `vector` extension | DSN env-interpolation | ❌ | (covered in core SDK reference) |
| `elasticsearch` | core (`nautilus.adapters.elasticsearch`) | `elasticsearch` Python client | bearer / basic / API-key | ❌ | (covered in core SDK reference) |
| `neo4j` | core (`nautilus.adapters.neo4j`) | `neo4j` Bolt driver | basic auth | ❌ | (covered in core SDK reference) |
| `rest` | core (`nautilus.adapters.rest`) | `httpx` | bearer / basic / mTLS / none | ❌ | [REST](rest.md) |
| `servicenow` | core (`nautilus.adapters.servicenow`) | `httpx` (Table API) | bearer / basic | ❌ | [ServiceNow](servicenow.md) |
| `influxdb` | core (`nautilus.adapters.influxdb`) | `influxdb-client` async | bearer | ❌ | (covered in core SDK reference) |
| `s3` | core (`nautilus.adapters.s3`) | `aiobotocore` | AWS IAM | ❌ | (covered in core SDK reference) |
| `llm` | core (`nautilus.adapters.llm`) | `openai` / `anthropic` SDKs (+ `httpx` for vLLM) | bearer / Vault | ❌ | [LLM](llm.md) |
| `nautobot` | external (`nautilus-adapter-nautobot`) | GraphQL primary, REST fallback | bearer (Token) | ❌ (v1) | [Nautobot](nautobot.md) |

## Adapter article template

Each per-adapter article in this directory follows the same structure:

1. **Description** — what data the adapter brokers and which use cases it
   serves.
2. **Use cases** — the typical agent intents that route here.
3. **Config schema** — the `SourceConfig` fields the adapter consumes,
   with examples.
4. **Endpoint / capability coverage matrix** — what's first-class, what's
   reachable via a generic transport, what's out of scope.
5. **Query language** — the predicate vocabulary and the v1 / v3 syntax
   notes that affect operator templates.
6. **Auth** — supported auth modes, secret references, key rotation.
7. **Error mapping** — provider failures → broker outcomes
   (`sources_errored`, `sources_skipped`, HTTP status code for transport
   failures, etc.).
8. **Example YAML** — at least one minimal `nautilus.yaml` snippet.
9. **Testing** — how to run unit + integration tests and how to refresh
   cassettes against live infrastructure.

## Naming conventions

* Built-in adapter modules live at `nautilus/adapters/<source_type>.py`.
* External adapter packages follow the `nautilus-adapter-<source_type>`
  PyPI convention and register via the `[project.entry-points."nautilus.adapters"]`
  table in `pyproject.toml`.
* The `source_type` literal must match the entry-point key, the
  `Adapter.source_type` class variable, and the value used in
  `SourceConfig.type`.
