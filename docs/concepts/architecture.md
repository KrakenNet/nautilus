# Architecture

Nautilus processes every request through a deterministic pipeline.

## Request pipeline

1. **Intent analysis** — classify the raw intent into data types, entities,
   temporal scope, and estimated sensitivity (pattern-matching or LLM-based).
2. **Policy routing** — the Fathom rules engine evaluates the agent's
   clearance, purpose, and requested data types against source classifications.
   Sources are routed, scoped, or denied.
3. **Adapter fan-out** — routed sources execute concurrently, each with
   per-source scope constraints (WHERE-clause fragments). One adapter failure
   never sinks the response.
4. **Synthesis** — results from all adapters are merged into a single
   `BrokerResponse`.
5. **Attestation** — an Ed25519 JWS token is signed over the routing decision,
   binding it to the `request_id`.
6. **Audit** — a JSONL entry is appended (fsync'd) covering the full request
   lifecycle: intent, routing, denials, errors, timing.

## Adapter model

Every data source implements the `Adapter` protocol:

- `connect()` — establish the connection
- `execute(intent, scope_constraints)` — run the scoped query
- `close()` — release resources

Built-in adapters: PostgreSQL, PgVector, Elasticsearch, Neo4j, REST,
ServiceNow, InfluxDB, S3. Third-party adapters register via
`[project.entry-points."nautilus.adapters"]`.

## Policy routing

Routing is powered by [Fathom](https://github.com/se-jo-ma/fathom), a
CLIPS-based expert system. Rules evaluate the `(clearance, purpose, source)`
triple and emit `allow`, `deny`, or `scope` decisions. Scope constraints
are passed to adapters as WHERE-clause fragments with injection-safe field
validation.

## Session management

Nautilus maintains working memory across requests within a session, enabling:

- **Cumulative exposure tracking** — deny access after an agent touches too
  many sensitive sources.
- **Cross-agent handoff reasoning** — evaluate whether data can flow from one
  agent to another based on clearance levels.
- **Escalation detection** — flag anomalous access patterns for forensic review.
