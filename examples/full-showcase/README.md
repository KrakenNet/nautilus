# Nautilus Full Showcase

End-to-end demonstration of every Nautilus subsystem running together.

## What's Running

| Service | Port | Purpose |
|---------|------|---------|
| **Nautilus** | 8000 | Broker + Admin UI + REST API |
| **PostgreSQL** | 5432 | Vulnerability database (12 sample CVEs) |
| **InfluxDB** | 8086 | Time-series metrics (24h of server data) |
| **MinIO** | 9000/9001 | S3-compatible object store (5 compliance docs) |
| **Elasticsearch** | 9200 | Application log index (8 sample events) |
| **Neo4j** | 7474/7687 | Threat intelligence knowledge graph |
| **Grafana** | 3000 | Pre-provisioned dashboards |
| **Tempo** | 3200 | Distributed trace backend |
| **Prometheus** | 9090 | Metrics scraper |
| **Loki** | 3100 | Log aggregation |
| **Locust** *(profile)* | 8089 | Load testing UI (`--profile bench`) |
| **MkDocs** *(profile)* | 8001 | SDK documentation site (`--profile docs`) |

## Features Demonstrated

- **Intent-aware routing** — pattern-matching intent analyzer classifies queries by data type
- **Classification-based access control** — Fathom rules engine enforces agent clearance vs source classification (unclassified < cui-basic < cui-specified)
- **Five data adapters** — Postgres (SQL), InfluxDB (Flux time-series), S3/MinIO (object store with tag filtering), Elasticsearch (full-text log search), Neo4j (Cypher graph queries)
- **Audit trail** — every request produces a JSONL audit entry with rule trace, routing decisions, scope constraints, and denial records
- **Attestation** — Ed25519 JWT signing on every response; attestation payloads written to JSONL sink
- **Admin UI** — HTMX server-rendered dashboard: source status, decision viewer with detail modals, paginated audit log, attestation verifier
- **SSE live updates** — source status page streams real-time updates
- **OpenTelemetry** — 8 pipeline spans (broker.request through attestation.sign), 9 metrics (counters + histograms), OTLP export to Tempo
- **Grafana dashboards** — request rate, decision distribution, error rate, latency histograms (p50/p90/p99), per-adapter breakdown
- **API key auth** — X-API-Key header required on write endpoints; probes are unauthenticated
- **Three agent clearance levels** — intern (unclassified), analyst (cui-basic), auditor (cui-specified)

## Prerequisites

- Docker and Docker Compose (v2)
- ~6 GB free memory (for all 12 services)
- Ports 3000, 3100, 3200, 4317, 4318, 5432, 7474, 7687, 8000, 8086, 9000, 9001, 9090, 9200 available

## Quick Start

```bash
cd examples/full-showcase

# Start all services (first build takes ~2 min)
docker compose up --build -d

# Wait for seed data to load (~30s)
docker compose logs -f seed

# Once seed exits, run the demo
chmod +x demo.sh
./demo.sh
```

## Walkthrough

### 1. Health Probes

```bash
# Liveness (no auth, no broker dependency)
curl http://localhost:8000/healthz
# {"status":"ok"}

# Readiness (broker + session store healthy)
curl http://localhost:8000/readyz
# {"status":"ok"}
```

### 2. Source Metadata

```bash
# Lists configured sources — NEVER exposes connection DSNs
curl http://localhost:8000/v1/sources | python3 -m json.tool
```

Returns all five sources: `vuln_db` (postgres/cui-basic), `server_metrics` (influxdb/unclassified), `compliance_docs` (s3/cui-specified), `app_logs` (elasticsearch/cui-basic), and `threat_graph` (neo4j/cui-basic).

### 3. Broker Requests (Access Control in Action)

**Analyst (cui-basic) queries vulnerabilities — ALLOWED:**

```bash
curl -X POST http://localhost:8000/v1/request \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-key-2024" \
  -d '{
    "agent_id": "analyst",
    "intent": "Show me critical vulnerability CVEs",
    "context": {"purpose": "threat-analysis"}
  }'
```

The analyst has `cui-basic` clearance and can access `vuln_db` (cui-basic) and `server_metrics` (unclassified). The response includes:
- `sources_queried` — sources that returned data
- `sources_denied` — sources blocked by classification rules
- `attestation_token` — Ed25519 JWT proving the routing decision
- `duration_ms` — end-to-end pipeline timing

**Intern (unclassified) queries compliance docs — DENIED:**

```bash
curl -X POST http://localhost:8000/v1/request \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-key-2024" \
  -d '{
    "agent_id": "intern",
    "intent": "Show me the HIPAA compliance report",
    "context": {"purpose": "compliance-audit"}
  }'
```

The intern has `unclassified` clearance — the Fathom rules engine denies access to `vuln_db` (cui-basic) and `compliance_docs` (cui-specified). Check `sources_denied` in the response.

**Auditor (cui-specified) queries everything — ALLOWED:**

```bash
curl -X POST http://localhost:8000/v1/request \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-key-2024" \
  -d '{
    "agent_id": "auditor",
    "intent": "Pull the Q1 security audit report and vulnerability findings",
    "context": {"purpose": "compliance-audit"}
  }'
```

The auditor has `cui-specified` clearance — all three sources are accessible.

### 4. Admin Dashboard

Open your browser:

| Page | URL | What You See |
|------|-----|--------------|
| Sources | http://localhost:8000/admin/sources | Configured sources with type, classification, data types |
| Decisions | http://localhost:8000/admin/decisions | Request log with filters (agent, date range, outcome) |
| Decision detail | Click any row | Full rule trace, routing decisions, scope constraints, denial records |
| Audit log | http://localhost:8000/admin/audit | Paginated event log with cursor navigation |
| Attestation | http://localhost:8000/admin/attestation | JWT verification form |

The admin UI uses HTMX for partial page updates — filter changes swap just the table body without full page reloads.

**Try it:** On the Decisions page, filter by `agent_id = intern` and `outcome = denied` to see all blocked requests.

### 5. Observability

Open Grafana at http://localhost:3000 (no login required).

**Dashboards:**

- **Nautilus Overview** — request rate, decision distribution (pie chart), error rate, latency histogram (p50/p90/p99)
- **Adapters** — per-adapter query duration and error breakdown
- **Attestation** — signing latency and verification statistics

**Traces:**

After running demo.sh, open Tempo in Grafana (Explore > Tempo datasource). Search for `service.name = nautilus` to see full request traces spanning:

1. `broker.request` — top-level request span
2. `intent_analysis` — pattern matching
3. `fathom_routing` — rules engine evaluation
4. `adapter_fan_out` — parallel adapter execution
5. `synthesis` — result assembly
6. `audit_emit` — audit JSONL write
7. `attestation_sign` — Ed25519 JWT signing

### 6. Data Backends

**InfluxDB** — http://localhost:8086
- Username: `admin` / Password: `admin12345`
- Explore the `showcase` bucket — 24 hours of CPU, memory, disk, and network metrics across 4 hosts

**MinIO** — http://localhost:9001
- Username: `minioadmin` / Password: `minioadmin`
- Browse the `compliance-docs` bucket — 5 documents (reports, policies, audit trails) with S3 object tags

**PostgreSQL** — `psql postgresql://nautilus:nautilus@localhost:5432/nautilus`
- Table `vulnerabilities` — 12 CVEs with severity, description, patch status

### 7. Audit Trail

The audit JSONL file is written to the `audit-data` Docker volume. To inspect:

```bash
docker compose exec nautilus cat /data/audit/audit.jsonl | python3 -m json.tool
```

Each entry contains:
- `timestamp`, `request_id`, `agent_id`
- `intent_analysis` — parsed data types and entities
- `routing_decisions` — which sources were routed to and why
- `scope_constraints` — field-level access controls applied
- `denial_records` — which sources were blocked and by which rule
- `rule_trace` — ordered list of fired rules
- `attestation_token` — signed JWT
- `duration_ms` — pipeline timing

### 8. Elasticsearch

Query the `app-logs` index directly:

```bash
# All ERROR-level events
curl -s 'http://localhost:9200/app-logs/_search?q=level:ERROR' | python3 -m json.tool
```

The broker routes log/error intents to the `app_logs` source. The seed script loads 8 sample events (auth failures, rate limits, circuit breakers, storage timeouts).

### 9. Neo4j Knowledge Graph

Open the Neo4j Browser at http://localhost:7474 (login: `neo4j` / `nautilus2024`).

Run a Cypher query to explore the threat intelligence graph:

```cypher
MATCH (a:ThreatActor)-[r]->(t) RETURN a, r, t
```

The seed creates 2 threat actors (APT-29, APT-41), 3 MITRE ATT&CK techniques, 2 IOCs, and 1 campaign with relationships.

### 10. Load Testing (Optional)

Start the Locust service:

```bash
docker compose --profile bench up -d bench
```

Open http://localhost:8089. Configure target host as `http://nautilus:8000` and start a load test. The locustfile exercises health probes, source listing, and broker requests across all three agent types.

### 11. SDK Documentation (Optional)

Start the MkDocs service:

```bash
docker compose --profile docs up -d docs
```

Open http://localhost:8001 to browse the Nautilus Adapter SDK documentation — protocol reference, compliance test suite, and adapter development guide.

## Full Mode (ServiceNow + LLM Intent Analysis)

The base showcase uses pattern-matching intent analysis and 5 locally-containerized data sources. If you have an Anthropic API key and/or ServiceNow credentials, you can unlock the remaining features:

| Credential | Feature Unlocked |
|-----------|-----------------|
| `ANTHROPIC_API_KEY` | Claude-backed intent analysis (falls back to pattern matching on timeout/error) |
| `SNOW_INSTANCE` + `SNOW_USER` + `SNOW_PASS` | ServiceNow incident table as a 6th data source |

### Setup

```bash
# 1. Create .env from the template
cp .env.example .env

# 2. Fill in the credentials you have (leave others blank)
#    ANTHROPIC_API_KEY=sk-ant-...
#    SNOW_INSTANCE=dev12345       (just the subdomain)
#    SNOW_USER=admin
#    SNOW_PASS=your-password

# 3. Start with the full compose stack
docker compose -f docker-compose.yml -f docker-compose.full.yml up --build -d
```

This swaps `nautilus.yaml` for `nautilus.full.yaml`, which adds:
- A `snow_incidents` source (ServiceNow Table API, cui-basic classification)
- `analysis.mode: llm-first` with Anthropic provider (pattern matching as fallback)
- An `incident` keyword map entry for routing incident/outage/ticket intents

The LLM analyzer produces richer intent analysis (entity extraction, confidence scores, reasoning) compared to pattern matching. You'll see the difference in the audit trail and decision viewer.

### Partial Credentials

You don't need both — each works independently:
- **Only `ANTHROPIC_API_KEY`**: LLM analysis activates; ServiceNow source errors on startup (other 5 sources work fine)
- **Only ServiceNow creds**: Pattern matching stays active; ServiceNow source connects and serves incident data

## Features NOT Demonstrated Here

These features exist in the codebase but require configuration beyond this showcase:

### MCP Transport
Expose Nautilus as an MCP tool server alongside REST:
```bash
python -m nautilus serve --config nautilus.yaml --transport both --mcp-mode http
```

### Adapter SDK (Copier Template)
Scaffold a new adapter package:
```bash
copier copy templates/adapter/ my-adapter/
```
See `examples/custom-adapter/` for a complete walkthrough.

## Tear Down

```bash
docker compose down -v  # removes containers and volumes
```
