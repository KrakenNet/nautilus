# Nautilus

> Policy-first data broker for AI agents. One call plans, routes, enforces, attests, and audits.

[![PyPI](https://img.shields.io/pypi/v/nautilus.svg)](https://pypi.org/project/nautilus/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/se-jo-ma/nautilus/actions/workflows/ci.yml/badge.svg)](https://github.com/se-jo-ma/nautilus/actions/workflows/ci.yml)
[![Docs](https://github.com/se-jo-ma/nautilus/actions/workflows/docs-deploy.yml/badge.svg)](https://nautilus.krakn.ai)

**Current version:** 0.1.0
**License:** MIT
**Language:** Python 3.14+
**Package Manager:** uv
**Maintained by:** [se-jo-ma](https://github.com/se-jo-ma)

---

## Why Nautilus?

Every AI agent framework gives agents direct access to data. For most tasks, that's fine.

For some tasks, unchecked access is unacceptable:

- **Policy routing** — "Which databases should this query hit?" can't be the agent's choice.
- **Scope enforcement** — "What rows is this agent allowed to see?" needs provable constraints.
- **Audit** — "What data did this agent touch, and why?" requires a tamper-evident trail.
- **Attestation** — "Can we prove this routing decision happened?" needs a signed token.

Nautilus provides **deterministic, policy-first data brokering** using Fathom — a CLIPS-based expert system — to route, scope, and attest every request.

## Install

```bash
uv add nautilus
```

## Quick Start

```python
from nautilus import Broker

broker = Broker.from_config("nautilus.yaml")
try:
    response = broker.request(
        "agent-alpha",
        "Find vulnerabilities for CVE-2026-1234",
        {"clearance": "unclassified", "purpose": "threat-analysis", "session_id": "s1"},
    )
    print(response.data)                # {"main-db": [...]}
    print(response.sources_queried)     # ["main-db"]
    print(response.sources_denied)      # ["classified-db"]
    print(response.attestation_token)   # signed JWS
    print(response.duration_ms)         # 47
finally:
    broker.close()
```

See the [Getting Started guide](https://nautilus.krakn.ai/getting-started/) for a full walkthrough.

## What Ships Today

**Core runtime**
- `Broker` facade with sync/async APIs (`request`, `arequest`, `from_config`, `afrom_config`)
- Fathom-based policy router for intent-aware source selection and scope enforcement
- Per-source scope constraints (WHERE-clause fragments) with injection-safe field validation
- Ed25519 JWS attestation service for signed routing decisions
- JSONL audit sink with per-request, append-only entries (fsync'd)
- Pattern-matching and LLM-based intent analysis (Anthropic, OpenAI)
- Cross-agent handoff reasoning with session-backed escalation detection

**Adapters (8 built-in)**
- PostgreSQL, PgVector, Elasticsearch, Neo4j, REST, ServiceNow, InfluxDB, S3
- Pluggable via entry points and the [Adapter SDK](https://nautilus.krakn.ai/reference/adapter-sdk/)

**Transports**
- FastAPI REST server (`POST /v1/request`, health/readiness probes)
- MCP transport (stdio and HTTP modes)
- CLI: `nautilus serve`, `nautilus health`, `nautilus version`

**Rule packs**
- `data-routing-nist` — NIST clearance/classification routing rules
- `data-routing-hipaa` — HIPAA-compliant routing rules

## What You Get Per Request

| Step | What happens |
|------|-------------|
| **Intent analysis** | Classify intent into data types, entities, temporal scope, sensitivity |
| **Policy routing** | Fathom evaluates `(clearance, purpose, source)` — route, scope, or deny |
| **Adapter fan-out** | Routed sources execute concurrently with per-adapter error isolation |
| **Attestation** | Ed25519 JWS signed over routing decision, bound to `request_id` |
| **Audit** | JSONL entry appended per request — success, denial, or error |

## Key Differentiator: Session-Aware Routing

Unlike stateless policy engines, Nautilus maintains working memory across requests within a session:

- **Cumulative exposure** — "This agent accessed PII from 3 sources — deny the 4th."
- **Cross-agent handoffs** — "Agent A is passing `secret` data to Agent B who has `unclassified` clearance — deny."
- **Escalation detection** — "Anomalous access pattern detected — escalate for forensic review."

## Integration Shapes

**As a library**
```python
from nautilus import Broker
broker = Broker.from_config("nautilus.yaml")
response = broker.request("agent-id", "intent", context)
```

**As a REST sidecar**
```bash
nautilus serve --config nautilus.yaml --transport rest --bind 0.0.0.0:8000
curl -H "X-API-Key: $KEY" -X POST localhost:8000/v1/request \
  -d '{"agent_id": "agent-alpha", "intent": "...", "context": {...}}'
```

**As an MCP server**
```bash
nautilus serve --config nautilus.yaml --transport mcp
```

**Air-gapped mode**
```bash
nautilus serve --config nautilus.yaml --air-gapped
```

## Configuration

A `nautilus.yaml` declares sources, rules, analysis, audit, and attestation:

```yaml
sources:
  - id: main-db
    adapter: postgres
    dsn: ${DATABASE_URL}
    classification: confidential
    data_types: [users, orders]

rules:
  paths: [./rules/]

attestation:
  enabled: true

audit:
  sink: file
  path: ./audit.jsonl
```

## Documentation

Full documentation is available at [nautilus.krakn.ai](https://nautilus.krakn.ai).

- [Getting Started](https://nautilus.krakn.ai/getting-started/)
- [Concepts](https://nautilus.krakn.ai/concepts/)
- [How-to Guides](https://nautilus.krakn.ai/how-to/)
- [Reference](https://nautilus.krakn.ai/reference/)

## Related Projects

- **[Fathom](https://github.com/se-jo-ma/fathom)** — Deterministic reasoning runtime that powers Nautilus routing
- **Bosun** — Agent governance built on Fathom (fleet analysis, compliance attestation)

## Development

```bash
git clone https://github.com/se-jo-ma/nautilus.git
cd nautilus
uv sync
uv run pytest -m unit            # fast suite, no containers
uv run pytest -m integration     # full e2e, boots PostgreSQL via testcontainers
uv run ruff check && uv run ruff format --check && uv run pyright
uv run mkdocs serve              # docs preview
```

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT — see [LICENSE](LICENSE) for details.
