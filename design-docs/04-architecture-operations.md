# Nautilus — Architecture and Operations

> *Part 4 of 5 — Persistence, concurrency, failure modes, security, deployment, observability. See also:* [01-overview](./01-overview.md) · [02-core-engine](./02-core-engine.md) · [03-living-brain](./03-living-brain.md) · [05-ecosystem-roadmap](./05-ecosystem-roadmap.md)

---

## Persistence Architecture

CLIPS working memory is the runtime representation of everything Nautilus knows. But CLIPS has no native persistence — when the process stops, working memory dies. Nautilus uses dumb storage underneath for durability.

```
┌─────────────────────────────────────────────┐
│        CLIPS Working Memory (Runtime)       │
│                                             │
│  Facts: source metadata, relationships,     │
│         affinities, access logs, session    │
│         state, relationship candidates,     │
│         routing decisions, exposure state   │
│                                             │
│  Rules: routing, policy, transformation,    │
│         (v2: suggestions, meta-rules,       │
│          auto-generated rules)              │
│                                             │
│  RETE network indexes all of this for       │
│  sub-millisecond pattern matching           │
└──────────────┬──────────────────────────────┘
               │ serialize on shutdown
               │ deserialize on startup
               │
┌──────────────▼──────────────────────────────┐
│     Persistence Layer (Dumb Storage)        │
│                                             │
│  Production: PostgreSQL                     │
│  - Serialized facts (JSONB)                 │
│  - Rule definitions (YAML + compiled CLIPS) │
│  - Template definitions                     │
│  - Audit log (append-only)                  │
│  - Source registry config                   │
│  - Session exposure state                   │
│  - (v2) Rule proposal queue                 │
│  - (v2) Rule lineage metadata               │
│                                             │
│  Single-node / air-gapped: SQLite           │
│  - Same schema, zero operational overhead   │
│  - Ships as a single file                   │
└─────────────────────────────────────────────┘
```

The persistence layer is explicitly dumb. It doesn't do relationship traversal or query routing — CLIPS does that in memory. Postgres/SQLite just ensures nothing is lost on restart.

Neo4j is not in the architecture. If graph visualization is needed for an admin UI, it can be generated from serialized relationship facts in Postgres. A live graph database would create a sync problem — two representations of the same knowledge — with no runtime benefit since CLIPS handles all traversal via RETE.

### Startup and Deserialization Cost

Deserializing working memory on startup is not free. For a deployment with 5,000 facts and 200 rules, initial RETE network construction and fact assertion takes approximately 1-3 seconds (benchmarking required). For larger deployments (50,000+ facts), startup may take 10-30 seconds. This is acceptable for a service that is expected to run continuously, but it means Nautilus is not suitable for serverless/lambda deployment patterns where cold start latency matters.

v1 mitigates this by supporting a health check endpoint that returns `ready` only after deserialization completes. Orchestrators (Kubernetes, ECS) should gate traffic behind this check.

---

## Concurrency Model

CLIPS is single-threaded. The RETE network, working memory, and rule execution are not thread-safe. Nautilus must handle concurrent agent requests without corrupting CLIPS state.

### v1 Approach: Request Serialization with Async I/O

v1 uses a single CLIPS instance with serialized access. Requests are queued and processed one at a time through the CLIPS engine. However, the expensive part of most requests is not CLIPS evaluation (sub-millisecond) but adapter query execution (network I/O). The request lifecycle is:

1. **Acquire CLIPS lock.** Assert intent facts, run engine, collect routing decisions. Release lock. (~1ms)
2. **Execute adapter queries concurrently.** All selected adapters run in parallel via asyncio. (~50-500ms depending on sources)
3. **Acquire CLIPS lock.** Assert exposure facts, run transformation rules, collect results. Release lock. (~1ms)

The CLIPS lock is held for ~2ms per request. At 500 concurrent requests, the worst-case queue depth for CLIPS access is manageable. The bottleneck is adapter I/O, which is fully parallel.

### v2 Approach: Blackboard Architecture

For deployments where CLIPS lock contention becomes measurable, v2 introduces the Blackboard pattern with domain-specialized workers (see Scaling Architecture).

---

## Failure Modes and Recovery

### Corrupted Working Memory

**Cause:** A meta-rule (v2) or manual rule asserts facts that cause an unexpected retraction cascade, leaving working memory in an inconsistent state — for example, session exposure facts retracted mid-evaluation.

**Detection:** After each engine run, Nautilus performs a consistency check: are all required session facts still present? Do all routing decisions reference valid sources? If the check fails, the engine run is rolled back by retracting all facts asserted during that run and the request is denied with a `system-error` reason.

**Recovery:** The audit log records the pre-run fact snapshot (as a list of fact identifiers). On consistency failure, the snapshot is used to restore working memory to its pre-run state. The offending request is logged with full context for debugging.

**Prevention:** v2 meta-rules are restricted to asserting facts in the `curator` module. They cannot modify or retract facts in the `policy` or `routing` modules. This module isolation is enforced by Fathom at compile time.

### Adapter Failure

**Cause:** A data source is unreachable, times out, or returns an error.

**Behavior:** The adapter is excluded from results. The response includes the source in `sources_failed` with error class and timing. Other sources are unaffected — adapter queries are independent.

**Retry:** v1 does not retry. The calling agent can retry the full request. v2 may add configurable per-adapter retry with exponential backoff, but this is not committed.

### Persistence Failure

**Cause:** Postgres/SQLite is unreachable when Nautilus attempts to write the audit log or serialize session state.

**Behavior:** Nautilus continues serving requests from working memory. Audit log entries are buffered in-memory (bounded queue, default 10,000 entries). When persistence recovers, the buffer is flushed. If the buffer fills, the oldest entries are dropped and a warning is logged.

**Risk:** If Nautilus crashes while the buffer is full and persistence is down, audit log entries are lost. This is an accepted risk for v1. v2 may add a write-ahead log to local disk as a secondary buffer.

### Classification Leak via LLM-Generated Rule (v2)

**Cause:** The LLM knowledge engineer proposes a rule that passes sandbox validation but causes a subtle policy violation in production — for example, a suggestion rule that effectively reveals the *existence* of a classified source to an uncleared agent by suggesting it.

**Detection:** Suggestion rules include the source name in their output. A post-evaluation policy check (a rule in the `policy` module with salience -100, firing after suggestions) validates that every suggested source is within the agent's clearance. Suggestions referencing sources above the agent's clearance are silently dropped.

**Prevention:** The LLM knowledge engineer's prompt includes the classification hierarchy and a constraint that suggested rules must not reference specific source names — only data types. Source resolution happens at routing time within the policy module.

### Session State Loss

**Cause:** Nautilus restarts mid-session. Working memory is lost. The session's exposure facts are gone.

**Recovery:** On startup, Nautilus deserializes the last-persisted session state from the database. Sessions are persisted after every request (the exposure fact assertion step includes a persistence write). The worst case is loss of the *current* request's exposure update if Nautilus crashes between CLIPS assertion and persistence write. This means one request's worth of exposure tracking may be lost on crash — the session will continue with the previous exposure state.

**Mitigation:** The persistence write is synchronous by default. An async mode is available for higher throughput at the cost of this one-request-loss window.

---

## Attestation and Audit

### Attestation Token

Every response includes a signed attestation token — a JWT containing: the request hash, the routing trace hash, the list of sources queried and denied, the cumulative exposure state, and a timestamp. The token is signed with a configurable key (HMAC-SHA256 by default, RS256 for environments requiring asymmetric signing).

**Who holds the keys?** The Nautilus instance holds the signing key. In multi-instance deployments (v2 Blackboard), each worker holds the same key (distributed via secrets management — Vault, K8s secrets, etc.). Key rotation is supported via a `nautilus key rotate` command that generates a new key and re-signs active session tokens.

**Verification:** Any system with the public key (or shared secret) can verify the attestation. This is intended for downstream audit systems, compliance tools, or the Bosun governance layer.

### Audit Log

The audit log is append-only and records every request, every routing decision, every policy evaluation, every exposure fact, and (in v2) every rule proposal and promotion. It is the forensic record of everything Nautilus has done.

The audit log is stored in Postgres (or SQLite) and is queryable via SQL. v2 adds a REST API for audit queries and an admin UI for browsing the trail.

**Retention:** Configurable. Default: 90 days. Archived entries are exported to a configurable sink (S3, local filesystem) before deletion.

---

## Adapter Security Model

Adapters execute scoped queries against data sources. Scope enforcement is the mechanism by which Nautilus restricts what an adapter can return. This section addresses the security implications.

### WHERE Clause Injection (Postgres Adapter)

The Postgres adapter applies scope constraints by injecting WHERE clauses into queries. This is SQL injection-adjacent by design — the adapter is constructing SQL dynamically.

**Mitigations:**

1. **Parameterized queries only.** Scope constraints are always applied via parameterized queries, never string concatenation. The adapter uses `psycopg`'s parameter binding exclusively.

2. **Allowlisted columns.** Each source in the registry declares which columns can appear in scope constraints. The adapter rejects scope constraints referencing columns not in the allowlist.

3. **No raw SQL.** The routing engine produces scope constraints as structured objects (`{"field": "asset_type", "operator": "IN", "values": ["server", "network_device"]}`), not SQL strings. The adapter translates these to parameterized SQL.

4. **Read-only connections.** All adapter connections are configured with read-only database users. Even if a constraint is somehow malformed, it cannot modify data.

### REST API Adapter

The REST adapter applies scope as parameter constraints and endpoint allowlisting. Each source declares allowed endpoints and allowed parameter values. The adapter rejects any request that targets an endpoint or parameter not in the allowlist.

---

## Source Registry

```yaml
# nautilus.yaml
sources:
  - id: nvd_db
    type: postgres
    description: "National Vulnerability Database mirror"
    classification: unclassified
    data_types: [cve, vulnerability, patch]
    allowed_columns: [cve_id, description, severity, published_date, affected_product]
    connection: ${NVD_DB_URL}

  - id: internal_vulns
    type: pgvector
    description: "Internal vulnerability assessments and scan results"
    classification: cui
    data_types: [vulnerability, scan_result, remediation]
    allowed_purposes: [threat-analysis, compliance-audit]
    connection: ${INTERNAL_VULN_URL}

  - id: cmdb
    type: servicenow
    description: "Configuration Management Database"
    classification: cui
    data_types: [asset, configuration, relationship]
    allowed_purposes: [threat-analysis, asset-management, incident-response]
    connection: ${SNOW_INSTANCE_URL}

  - id: hr_records
    type: postgres
    description: "Human resources personnel data"
    classification: pii
    data_types: [employee, role, clearance]
    allowed_purposes: [hr-operations, insider-threat]
    allowed_columns: [employee_id, department, role, clearance_level]
    connection: ${HR_DB_URL}

  - id: threat_intel
    type: rest_api
    description: "External threat intelligence feed"
    classification: unclassified
    data_types: [ioc, threat_actor, campaign]
    allowed_endpoints: [/indicators, /actors, /campaigns]
    connection: ${THREAT_INTEL_API}
    rate_limit: 100/hour
```

---

## Classification Hierarchy

```yaml
# classification.yaml
hierarchy:
  - level: unclassified
    rank: 0
  - level: cui
    rank: 1
    sub_categories: [cui-sp-cti, cui-sp-prvcy, cui-sp-tax]
  - level: confidential
    rank: 2
  - level: secret
    rank: 3
  - level: top-secret
    rank: 4
    compartments: [sci-a, sci-b, sci-c]

custom_hierarchy:
  - level: public
    rank: 0
  - level: internal
    rank: 1
  - level: confidential
    rank: 2
  - level: restricted
    rank: 3
```

---

## Agent Interface

### Python SDK

```python
from nautilus import Broker

broker = Broker.from_config("nautilus.yaml")

# Natural language request
response = broker.request(
    agent_id="agent-alpha",
    intent="What systems are affected by CVE-2026-1234?",
    context={"clearance": "secret", "purpose": "incident-response"}
)

# Structured request (skip intent analysis)
response = broker.query(
    agent_id="agent-alpha",
    data_types=["vulnerability", "asset"],
    filters={"cve_id": "CVE-2026-1234"},
    context={"clearance": "secret", "purpose": "incident-response"}
)

# Close a session
broker.close_session("incident-response-42")
```

### REST API

```
POST /v1/request
{
    "agent_id": "agent-alpha",
    "intent": "What systems are affected by CVE-2026-1234?",
    "context": {
        "clearance": "secret",
        "purpose": "incident-response"
    }
}

Response:
{
    "data": { ... },
    "suggestions": [],
    "sources_queried": ["nvd_db", "internal_vulns", "cmdb"],
    "sources_denied": ["hr_records"],
    "sources_skipped": ["marketing_db"],
    "sources_failed": [],
    "routing_trace": [ ... ],
    "exposure_summary": {
        "session_id": "sess-001",
        "cumulative_classification": "cui",
        "data_types_accessed": ["cve", "vulnerability", "asset"],
        "exposure_flags": []
    },
    "attestation_token": "eyJhbG...",
    "duration_ms": 230
}
```

### MCP Tool

```python
from nautilus.integrations.mcp import NautilusMCPServer

server = NautilusMCPServer(broker)
server.serve()
```

---

## Query Executors (Adapters)

### v1

| Source Type | Adapter | Scope Enforcement |
|-------------|---------|-------------------|
| PostgreSQL | `nautilus.adapters.postgres` | Parameterized WHERE clause injection, column filtering, allowlisted columns |
| pgvector | `nautilus.adapters.pgvector` | Metadata filtering on similarity search |

### v2

| Source Type | Adapter | Scope Enforcement |
|-------------|---------|-------------------|
| Elasticsearch | `nautilus.adapters.elastic` | Query DSL filter injection |
| REST API | `nautilus.adapters.rest` | Parameter constraints, endpoint allowlisting |
| ServiceNow | `nautilus.adapters.servicenow` | GlideRecord encoded query scoping, ACL passthrough |
| S3/Document Store | `nautilus.adapters.documents` | Prefix/tag-based access, classification label filtering |

### Custom Adapters

```python
from nautilus.adapters import BaseAdapter

class MyAdapter(BaseAdapter):
    source_type = "my_database"

    def connect(self, config):
        ...

    def execute(self, query_intent, scope_constraints):
        ...

    def apply_scope(self, base_query, constraints):
        ...

    def health_check(self) -> bool:
        ...
```

---

## Deployment Models

### Standalone (development/small teams)

```bash
uv add nautilus-broker
nautilus serve --config nautilus.yaml
```

Uses SQLite by default. Single process, single CLIPS instance.

### Container (production)

```bash
docker run -p 8080:8080 \
  -v ./config:/config \
  -v ./rules:/rules \
  -e DATABASE_URL=postgres://... \
  kraken/nautilus:latest
```

### Air-gapped (classified environments, v2)

```bash
nautilus serve --config nautilus.yaml --air-gapped
```

Air-gapped mode disables: LLM knowledge engineer, external API adapters, telemetry. Enables: pattern-matching intent analyzer, meta-rules-only knowledge retention, SQLite persistence. All data stays local. Container image available for offline registries.

---

## Scaling Architecture (v2)

CLIPS RETE performance degrades as working memory grows beyond tens of thousands of facts. For large deployments, Nautilus uses a Blackboard architecture with specialized workers.

```
┌──────────────────────────────────────────────────┐
│                  Coordinator                      │
│  Routes requests to appropriate specialist        │
│  Merges results from multiple specialists         │
│  Maintains global session state                   │
└───────┬──────────┬──────────┬────────────────────┘
        │          │          │
   ┌────▼───┐ ┌───▼────┐ ┌───▼────┐
   │Worker A│ │Worker B│ │Worker C│
   │        │ │        │ │        │
   │Security│ │Business│ │  Ops   │
   │sources │ │sources │ │sources │
   │        │ │        │ │        │
   │Own CLIPS│ │Own CLIPS│ │Own CLIPS│
   │instance│ │instance│ │instance│
   │        │ │        │ │        │
   │Bounded │ │Bounded │ │Bounded │
   │working │ │working │ │working │
   │memory  │ │memory  │ │memory  │
   └────────┘ └────────┘ └────────┘
```

Each worker maintains CLIPS expertise over a bounded domain. Working memory stays small per worker. RETE stays fast. The coordinator handles cross-domain requests by querying multiple workers and merging results.

Cross-worker relationship facts live in the coordinator's CLIPS instance, enabling cross-domain pattern discovery without blowing up any single worker's memory.

This is a v2 concern. Single-instance CLIPS handles v1 deployment scale.

---

## Observability

### v1 Metrics

Nautilus exposes Prometheus-compatible metrics at `/metrics`:

- `nautilus_requests_total` — counter by agent_id, purpose, outcome (success/denied/error)
- `nautilus_clips_evaluation_ms` — histogram of CLIPS engine run duration
- `nautilus_adapter_query_ms` — histogram by adapter type and source_id
- `nautilus_adapter_errors_total` — counter by adapter type and error class
- `nautilus_session_exposure_flags_total` — counter by flag type
- `nautilus_working_memory_facts` — gauge of current fact count
- `nautilus_clips_lock_wait_ms` — histogram of time spent waiting for CLIPS lock

### v2 Metrics

- `nautilus_rule_proposals_total` — counter by proposer (meta-rule, llm-engineer, human)
- `nautilus_rule_promotions_total` — counter by promotion method (auto, human)
- `nautilus_rule_rejections_total` — counter by rejection reason
- `nautilus_sandbox_evaluation_ms` — histogram of sandbox run duration

### Structured Logging

All log entries include: request_id, session_id, agent_id, and a trace_id that correlates with the routing trace in the response. Log format is JSON for machine parsing.
