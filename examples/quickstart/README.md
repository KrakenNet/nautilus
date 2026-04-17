# Nautilus Quickstart

Minimal setup: one Postgres source, pattern-matching analysis, file-backed audit.

## Prerequisites

- Python 3.14+
- A PostgreSQL database (or use `examples/full-showcase/` for a Docker-based setup)
- Nautilus installed: `uv sync` from the repo root

## Setup

1. Set your database connection string:

```bash
export PG_DSN="postgresql://user:pass@localhost:5432/mydb"
```

2. Start the broker:

```bash
python -m nautilus serve --config examples/quickstart/nautilus.yaml --bind 127.0.0.1:8000
```

## Usage

**Health check:**

```bash
curl http://localhost:8000/healthz
# {"status":"ok"}
```

**List sources (no auth required):**

```bash
curl http://localhost:8000/v1/sources
```

**Make a broker request:**

```bash
curl -X POST http://localhost:8000/v1/request \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-secret-key" \
  -d '{
    "agent_id": "analyst",
    "intent": "Show me recent critical vulnerabilities",
    "context": {}
  }'
```

The response includes:
- `data` — query results from matched sources
- `sources_queried` — sources that were accessed
- `sources_denied` — sources blocked by classification rules
- `attestation_token` — Ed25519 JWT proving the routing decision
- `duration_ms` — pipeline execution time

**View the audit trail:**

```bash
cat audit.jsonl | python3 -m json.tool
```

**Open the admin dashboard:**

Browse to http://localhost:8000/admin/sources to see the operator dashboard.

## What's Happening

1. Your `intent` is analyzed by the pattern-matching engine using `keyword_map`
2. The Fathom rules engine evaluates agent clearance vs source classification
3. Allowed sources are queried via their adapters (Postgres SQL in this case)
4. Results are synthesized and an audit entry is written
5. An Ed25519 attestation token is signed and returned

## Next Steps

- Add more sources with different classification levels to see denial rules in action
- Try the `full-showcase` example for a complete Docker-based demo with InfluxDB, MinIO, and Grafana
- Write a custom adapter using the SDK — see `examples/custom-adapter/`
