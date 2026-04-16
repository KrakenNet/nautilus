# Nautilus — Intelligent Data Broker for AI Agents

> Agents don't query databases. They tell Nautilus what they need. Nautilus reasons about where to find it, what they're allowed to see, and how to bring it back — deterministically, with a full audit trail.

**Status:** Design Draft
**License:** MIT (open source, built on Fathom)
**Language:** Python
**Package Manager:** uv
**Maintained by:** Kraken Networks

---

## The Problem

AI agents need data from multiple sources. Today, agents get direct access to databases via tools — MCP servers, function calls, RAG pipelines. The agent decides what to query, where to query it, and what to do with the results.

This creates three problems that get worse as organizations scale:

**1. Agents can't reason about what they don't know exists.**
An agent with tools for 3 of your 10 databases will never find relevant data in the other 7. Adding tools for all 10 means the agent must reason about which sources are relevant — a task LLMs handle unreliably, especially for unfamiliar schemas.

**2. Access control is bolted on, not reasoned about.**
Current solutions (Auth0 FGA, Permit.io, Oso) apply RBAC/ABAC filters at the query layer. They answer "is this agent allowed to access this table?" They don't answer "given this agent's clearance, purpose, and what it has already accessed this session, which sources should it see, what scope should each query have, and does the combination of accessed data create a classification escalation?"

**3. Nobody tracks cumulative data exposure.**
Agent A reads PII from HR. Agent A's output goes into Agent B's context. Agent B queries finance. The combined knowledge now represents a data profile that neither agent was individually authorized to construct. No existing tool tracks this because no existing tool maintains state across queries.

---

## What Nautilus Does

Nautilus sits between agents and data sources. Instead of giving agents direct database access, agents submit **intents** to Nautilus. A Fathom expert system engine reasons about the intent and returns scoped, policy-compliant results.

```
┌─────────┐     ┌───────────────────────────────────────┐     ┌──────────┐
│  Agent   │────▶│              Nautilus                  │────▶│ Postgres │
│          │     │                                       │────▶│ pgvector │
│  "I need │     │  1. Parse intent                      │────▶│ Neo4j    │
│  threat  │     │  2. Assert facts (agent, intent,      │────▶│ Elastic  │
│  intel   │     │     classification, session history)  │────▶│ S3/docs  │
│  on CVE- │     │  3. Fathom evaluates routing rules    │     │ REST APIs│
│  2026-   │     │  4. Engine selects sources + scopes   │     └──────────┘
│  1234"   │     │  5. Execute scoped queries            │
│          │◀────│  6. Synthesize + return with           │
│          │     │     attestation token                  │
└─────────┘     └───────────────────────────────────────┘
```

The agent never touches a database directly. Nautilus handles:
- **Source selection:** Which of N data sources are relevant to this intent?
- **Policy evaluation:** What is this agent allowed to see from each source?
- **Scope enforcement:** Rewrite/constrain queries to match policy boundaries.
- **Cumulative tracking:** Update working memory with what this agent has accessed.
- **Synthesis:** Combine results from multiple sources into a coherent response.
- **Attestation:** Sign the response with a token proving it was policy-checked.

---

## Core Concepts

### Intents

Agents don't write queries. They express what they need.

```python
from nautilus import Broker

broker = Broker.from_config("nautilus.yaml")

response = broker.request(
    agent_id="agent-alpha",
    intent="Find all known vulnerabilities, patches, and affected systems for CVE-2026-1234",
    context={
        "clearance": "secret",
        "purpose": "threat-analysis",
        "workflow": "incident-response-42",
        "session_id": "sess-001"
    }
)

print(response.sources_queried)    # ["nvd_db", "internal_vulns", "cmdb"]
print(response.sources_denied)     # ["hr_records", "finance_db"]
print(response.sources_skipped)    # ["marketing_db", "sales_crm"] (not relevant)
print(response.scope_restrictions) # {"cmdb": "asset_type IN ('server', 'network_device')"}
print(response.attestation_token)  # "eyJhbG..."
print(response.data)               # Synthesized results
```

### Source Registry

Nautilus maintains a registry of available data sources with metadata Fathom uses for reasoning.

```yaml
# nautilus.yaml
sources:
  - id: nvd_db
    type: postgres
    description: "National Vulnerability Database mirror"
    classification: unclassified
    data_types: [cve, vulnerability, patch]
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
    connection: ${HR_DB_URL}

  - id: threat_intel
    type: rest_api
    description: "External threat intelligence feed"
    classification: unclassified
    data_types: [ioc, threat_actor, campaign]
    connection: ${THREAT_INTEL_API}
    rate_limit: 100/hour
```

### Routing Rules

Fathom rules determine which sources get queried and how queries are scoped.

```yaml
# rules/routing.yaml
ruleset: nautilus-routing
version: 1.0

rules:
  - name: match-sources-by-data-type
    description: "Select sources that contain data types relevant to the intent"
    when:
      intent:
        data_types_needed: overlaps($source.data_types)
      source:
        as: $source
    then:
      action: route
      target: $source.id
      log: summary

  - name: deny-classification-mismatch
    description: "Exclude sources above agent clearance"
    when:
      agent:
        clearance: below($source.classification)
      source:
        as: $source
    then:
      action: skip
      reason: "Agent clearance insufficient for {$source.id}"
      log: full

  - name: deny-purpose-mismatch
    description: "Exclude sources not authorized for this purpose"
    when:
      agent:
        purpose: not_in($source.allowed_purposes)
      source:
        as: $source
        allowed_purposes: exists
    then:
      action: skip
      reason: "Purpose '{agent.purpose}' not authorized for {$source.id}"
      log: full

  - name: cumulative-pii-limit
    description: "Escalate if agent has accessed PII from 3+ sources this session"
    when:
      session:
        pii_sources_accessed: count_exceeds(2)
      source:
        classification: pii
    then:
      action: escalate
      reason: "Cumulative PII exposure threshold exceeded"
      notify: [security-team]
      log: full
```

### Intent Analysis

Nautilus uses a lightweight LLM call (or pattern matching for air-gapped environments) to extract structured intent metadata from the agent's natural language request:

```python
# Internal intent analysis output
{
    "raw_intent": "Find all known vulnerabilities, patches, and affected systems for CVE-2026-1234",
    "data_types_needed": ["cve", "vulnerability", "patch", "asset"],
    "entities": ["CVE-2026-1234"],
    "temporal_scope": null,
    "estimated_sensitivity": "cui"
}
```

This structured output becomes facts in Fathom's working memory, enabling deterministic routing based on the extracted metadata.

For classified/air-gapped environments where LLM calls aren't available, Nautilus supports a **pattern-matching fallback** using keyword extraction and predefined intent templates.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Nautilus Broker                     │
│                                                      │
│  ┌────────────┐  ┌─────────────┐  ┌──────────────┐  │
│  │   Intent   │  │   Source    │  │   Query      │  │
│  │  Analyzer  │  │  Registry   │  │  Executors   │  │
│  └─────┬──────┘  └──────┬──────┘  └──────┬───────┘  │
│        │                │                │           │
│        ▼                ▼                │           │
│  ┌─────────────────────────────────┐     │           │
│  │        Fathom Engine            │     │           │
│  │                                 │     │           │
│  │  Working Memory:                │     │           │
│  │  - Agent context                │     │           │
│  │  - Parsed intent                │     │           │
│  │  - Source metadata              │     │           │
│  │  - Session access history       │     │           │
│  │  - Classification hierarchy     │     │           │
│  │                                 │     │           │
│  │  Rules:                         │     │           │
│  │  - Routing rules                │     │           │
│  │  - Classification rules         │     │           │
│  │  - Cumulative exposure rules    │     │           │
│  │  - Purpose-binding rules        │     │           │
│  │                                 │     │           │
│  │  Output:                        │     │           │
│  │  - Source selection + scopes    │─────▶           │
│  │  - Denial reasons               │     │           │
│  │  - Attestation data             │     │           │
│  └─────────────────────────────────┘     │           │
│                                          │           │
│  ┌───────────────┐  ┌────────────────┐   │           │
│  │  Synthesizer  │◀─│  Scope         │◀──┘           │
│  │               │  │  Enforcer      │               │
│  └───────┬───────┘  └────────────────┘               │
│          │                                           │
│  ┌───────▼───────┐  ┌────────────────┐               │
│  │  Attestation  │  │   Audit Log    │               │
│  │  Service      │  │                │               │
│  └───────────────┘  └────────────────┘               │
└──────────────────────────────────────────────────────┘
```

### Components

**Intent Analyzer:** Extracts structured metadata from natural language intents. Pluggable — supports LLM-based analysis (default), pattern-matching (air-gapped), or direct structured input (API-to-API).

**Source Registry:** Maintains the catalog of available data sources with classification, data types, purpose constraints, and connection details. YAML-configured, hot-reloadable.

**Fathom Engine:** The core reasoning layer. Receives facts about the agent, intent, sources, and session history. Fires routing rules. Outputs source selections with scope constraints and denial reasons.

**Scope Enforcer:** Takes Fathom's routing decisions and translates scope constraints into query modifications for each data source. For SQL sources, this means adding WHERE clauses. For vector DBs, this means filtering metadata. For REST APIs, this means constraining request parameters.

**Query Executors:** Pluggable adapters for each data source type. Execute scoped queries and return structured results. Each executor handles connection management, retry logic, and error handling for its source type.

**Synthesizer:** Combines results from multiple sources into a coherent response. Can use simple concatenation, structured merging, or an LLM summarization pass depending on configuration.

**Attestation Service:** Inherited from Fathom. Signs the complete response with the routing decision, scope constraints, and source list. Proves the response was policy-checked.

**Audit Log:** Complete record of every request: intent, parsed metadata, routing decisions, queries executed, results returned, attestation token. Append-only, structured JSON.

---

## Query Executors (Adapters)

### Phase 1 Adapters

| Source Type | Adapter | Scope Enforcement |
|-------------|---------|-------------------|
| PostgreSQL | `nautilus.adapters.postgres` | WHERE clause injection, column filtering |
| pgvector | `nautilus.adapters.pgvector` | Metadata filtering on similarity search |
| Elasticsearch | `nautilus.adapters.elastic` | Query DSL filter injection |
| REST API | `nautilus.adapters.rest` | Parameter constraints, endpoint allowlisting |

### Phase 2 Adapters

| Source Type | Adapter | Scope Enforcement |
|-------------|---------|-------------------|
| Neo4j | `nautilus.adapters.neo4j` | Cypher pattern constraints, label filtering |
| ServiceNow | `nautilus.adapters.servicenow` | GlideRecord encoded query scoping, ACL passthrough |
| S3/Document Store | `nautilus.adapters.documents` | Prefix/tag-based access, classification label filtering |
| InfluxDB | `nautilus.adapters.influx` | Measurement/tag scoping, time range enforcement |

### Custom Adapters

```python
from nautilus.adapters import BaseAdapter

class MyAdapter(BaseAdapter):
    source_type = "my_database"

    def connect(self, config):
        # establish connection

    def execute(self, query_intent, scope_constraints):
        # run scoped query, return structured results

    def apply_scope(self, base_query, constraints):
        # modify query to enforce Fathom's scope decisions
```

---

## Classification Hierarchy

Nautilus ships with a configurable classification hierarchy that Fathom uses for clearance-based reasoning.

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

# Custom hierarchies for commercial use
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

Commercial users define their own classification schemes. The hierarchy is a Fathom configuration — the engine doesn't care whether levels are military classifications or internal sensitivity tiers.

---

## Cumulative Exposure Tracking

Nautilus's most novel capability: tracking what an agent has accessed across its entire session and reasoning about the *combination* of accessed data.

```yaml
# rules/cumulative-exposure.yaml
ruleset: cumulative-exposure
version: 1.0

rules:
  - name: cross-source-pii-aggregation
    description: "Deny when agent has gathered PII from enough sources to construct a profile"
    when:
      session:
        distinct_pii_sources: count_exceeds(2)
        pii_fields_accessed: contains_all([name, ssn, address])
    then:
      action: deny
      reason: "Cross-source PII aggregation detected — profile construction risk"
      notify: [privacy-officer]

  - name: classification-escalation
    description: "Flag when combining unclassified sources creates classified-equivalent knowledge"
    when:
      session:
        accessed_data_types: contains_all($escalation_rule.trigger_combination)
      escalation_rule:
        as: $escalation_rule
    then:
      action: escalate
      reason: "Data combination triggers classification escalation to {$escalation_rule.resulting_level}"
      notify: [security-team]

  - name: information-flow-violation
    description: "Detect when data accessed by one agent flows to another agent with lower clearance"
    when:
      data_handoff:
        source_agent_clearance: greater_than($receiving_agent.clearance)
        data_classification: greater_than($receiving_agent.clearance)
      agent:
        as: $receiving_agent
    then:
      action: deny
      reason: "Information flow violation: data at '{data_handoff.data_classification}' cannot flow to agent with '{$receiving_agent.clearance}' clearance"
```

---

## Agent Interface

### Python SDK

```python
from nautilus import Broker

broker = Broker.from_config("nautilus.yaml")

# Simple request
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
```

### REST API

```bash
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
    "sources_queried": ["nvd_db", "internal_vulns", "cmdb"],
    "sources_denied": ["hr_records"],
    "sources_skipped": ["marketing_db"],
    "routing_trace": [ ... ],
    "attestation_token": "eyJhbG...",
    "duration_ms": 230
}
```

### MCP Tool

```python
from nautilus.integrations.mcp import NautilusMCPServer

server = NautilusMCPServer(broker)
server.serve()
# Agents call nautilus.request as an MCP tool
```

---

## Deployment Models

### Standalone (development/small teams)

```bash
uv add nautilus-broker
nautilus serve --config nautilus.yaml
```

### Container (production)

```bash
docker run -p 8080:8080 \
  -v ./config:/config \
  -v ./rules:/rules \
  kraken/nautilus:latest
```

### Air-gapped (classified environments)

```bash
# No external dependencies, no LLM calls
# Uses pattern-matching intent analyzer
nautilus serve --config nautilus.yaml --air-gapped
```

All data stays local. No telemetry. No cloud dependencies. Container image available for offline registries.

---

## Relationship to Fathom and Bosun

```
Agent submits intent
        │
        ▼
   ┌─────────┐
   │ Nautilus │──── "What data does this agent need and what can it see?"
   │         │      Uses Fathom for routing + scoping decisions
   └────┬────┘
        │
        ▼
   Data returned to agent
        │
        ▼
   Agent takes action
        │
        ▼
   ┌─────────┐
   │  Bosun   │──── "Is this agent allowed to take this action?"
   │         │      Uses Fathom for governance decisions
   └─────────┘
```

Nautilus governs what agents **know**. Bosun governs what agents **do**. Both use Fathom as their reasoning engine. Together they provide complete governance over an agent's data access and actions.

---

## Development Roadmap

### Phase 1 — Core Broker (Weeks 1-6)
*Requires: Fathom Phase 1 complete*

- [ ] Source registry with YAML configuration
- [ ] Intent analyzer (pattern-matching mode)
- [ ] Fathom integration for routing decisions
- [ ] PostgreSQL adapter with scope enforcement
- [ ] pgvector adapter with metadata filtering
- [ ] Basic synthesizer (structured merge)
- [ ] Audit log
- [ ] Python SDK
- [ ] Test suite

### Phase 2 — Policy and API (Weeks 7-10)
- [ ] Classification hierarchy support
- [ ] Cumulative exposure tracking (session working memory)
- [ ] REST API (FastAPI)
- [ ] Elasticsearch adapter
- [ ] REST API adapter
- [ ] Attestation service integration
- [ ] MCP tool server
- [ ] Docker container image

### Phase 3 — Advanced Reasoning (Weeks 11-16)
- [ ] LLM-based intent analyzer (optional, non-air-gapped)
- [ ] Cross-agent information flow tracking
- [ ] Classification escalation rules
- [ ] Neo4j adapter
- [ ] ServiceNow adapter
- [ ] Purpose-bound temporal scoping
- [ ] Admin UI: source status, routing decisions, audit viewer

### Phase 4 — Ecosystem (Weeks 17+)
- [ ] InfluxDB adapter
- [ ] S3/document store adapter
- [ ] Custom adapter SDK with documentation
- [ ] Rule pack: data-routing-nist
- [ ] Rule pack: data-routing-hipaa
- [ ] Grafana dashboard templates
- [ ] Benchmarking suite

---

## Open Source Strategy

- **License:** MIT
- **Core principle:** Nautilus is fully open source. The value proposition for Kraken is professional services (deployment, custom adapters, classification policy development) and the Bosun governance layer that completes the picture.
- **Community:** Adapter contributions especially welcome — every new data source adapter increases Nautilus's value to the ecosystem.
- **Blog cadence:** Launch post explaining the concept, followed by adapter-specific tutorials and classification policy guides.
- **Demo:** Reference deployment with 5 data sources, multiple agent personas with different clearances, showing routing decisions in real time. This demo is the primary marketing asset.