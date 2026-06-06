# Getting Started

Nautilus is a policy-first data broker built on Fathom. Define data sources
and routing rules in YAML, then call `broker.request(...)` to get
scope-enforced, attested results.

## Installation

Requires Python 3.14 or later.

```bash
uv add nautilus-rkm
```

## Configuration

Create a `nautilus.yaml`:

```yaml
sources:
  - id: main-db
    type: postgres
    description: "Primary application database"
    classification: confidential
    data_types: [users, orders]
    allowed_purposes: [support]
    connection: ${DATABASE_URL}
    table: orders

rules:
  user_rules_dirs: []

attestation:
  enabled: true

audit:
  path: ./audit.jsonl
```

## First request

```python
from nautilus import Broker

broker = Broker.from_config("nautilus.yaml")
try:
    response = broker.request(
        "agent-alpha",
        "Find recent orders for user 42",
        {"clearance": "confidential", "purpose": "support", "session_id": "s1"},
    )
    print(response.data)            # {"main-db": [...]}
    print(response.sources_queried) # ["main-db"]
    print(response.attestation_token)
finally:
    broker.close()
```

`response` is a `BrokerResponse`: `response.data` maps source IDs to result
rows, `response.attestation_token` is a signed JWS, and `response.request_id`
joins the response to its audit entry.

## Next steps

- [Architecture](concepts/architecture.md) — understand the broker pipeline
- [REST API](reference/rest-api.md) — run Nautilus as a service
- [Adapter SDK](reference/adapter-sdk.md) — build custom adapters
