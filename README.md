# Nautilus

Nautilus is a policy-first data broker: a single `broker.request(...)` call
plans an intent, routes it to the right sources, enforces CLIPS-backed scope
rules, executes adapters concurrently, and emits a signed attestation plus a
complete audit entry per request.

See [`./specs/core-broker/design.md`](./specs/core-broker/design.md) for the
architecture and [`./specs/core-broker/requirements.md`](./specs/core-broker/requirements.md)
for the functional/non-functional requirements this implementation satisfies.

## Install

```bash
uv add nautilus
```

Python 3.12+ is required. PostgreSQL 16+ with the `pgvector` extension is
required only if you register `postgres` or `pgvector` sources.

## Quickstart

The snippet below is runnable verbatim against the repo's two-source test
fixture at [`tests/fixtures/nautilus.yaml`](./tests/fixtures/nautilus.yaml).
Export `TEST_PG_DSN` and `TEST_PGV_DSN` first (the fixture references them
via `${TEST_PG_DSN}` / `${TEST_PGV_DSN}`); any reachable PostgreSQL with
`pgvector` installed works.

```python
from nautilus import Broker

broker = Broker.from_config("tests/fixtures/nautilus.yaml")
try:
    response = broker.request(
        "agent-alpha",
        "Find vulnerabilities for CVE-2026-1234",
        {"clearance": "unclassified", "purpose": "threat-analysis", "session_id": "s1", "embedding": [0.1, 0.2, 0.3]},
    )
    print(response.data)
finally:
    broker.close()
```

`response` is a `BrokerResponse` (see design §4.8): `response.data` is a
`dict[source_id, list[row]]`, `response.sources_queried` lists successful
sources, `response.attestation_token` is the signed JWS, and
`response.request_id` is the UUID4 key that joins the response to the
per-request audit entry in `./audit.jsonl`.

## What you get per request

- **Planned routing** via the Fathom intent router — sources selected by
  intent + data types, never by the caller.
- **Scope enforcement** through a CLIPS rules engine over the
  `(clearance, purpose, source)` triple; denials are recorded, not
  swallowed.
- **Concurrent adapter execution** with per-adapter error isolation so one
  failing source never sinks the response.
- **Signed attestation** (JWS) bound to `request_id`, enabling external
  verification without replaying the query.
- **Complete audit entry** (design §4.9) appended to `./audit.jsonl` for
  every request — success, denial, or error.

## Configuration

A `nautilus.yaml` declares `sources`, `rules`, `analysis`, `audit`, and
`attestation` blocks. The test fixture is the minimal working example;
design §12 documents the full schema.

## Reasoning Engine

Phase 2 adds cross-agent handoff reasoning, a Postgres-backed session
store, optional LLM intent analysis, and REST/MCP transports. Install
with the provider extra you need:

```bash
uv add 'nautilus[llm-anthropic]'   # or llm-openai, llm-local, or no extra
```

Add an `agents:` block and a durable `session_store` to `nautilus.yaml`:

```yaml
agents:
  agent-alpha: { clearance: secret, compartments: [crypto], default_purpose: threat-analysis }
  agent-beta:  { clearance: unclassified, compartments: [],       default_purpose: reporting }
session_store:
  backend: postgres
  dsn: ${NAUTILUS_SESSION_DSN}
  on_failure: fallback_memory
analysis:
  mode: llm-first           # falls back to pattern on provider error
  provider: anthropic
api:
  keys: [${NAUTILUS_API_KEY}]
```

Declare a cooperative handoff from Python (zero adapter calls, one audit
entry, signed attestation):

```python
import asyncio
from nautilus import Broker

async def main() -> None:
    broker = await Broker.afrom_config("nautilus.yaml")
    try:
        decision = await broker.declare_handoff(
            source_agent_id="agent-alpha",
            receiving_agent_id="agent-beta",
            session_id="s-42",
            data_classifications=["secret"],
        )
        print(decision.action, decision.rule_trace)
    finally:
        await broker.aclose()

asyncio.run(main())
```

Run the REST + MCP transport via the stdlib-argparse CLI:

```bash
nautilus serve --config nautilus.yaml --transport both --bind 0.0.0.0:8000
nautilus serve --config nautilus.yaml --air-gapped   # force pattern analyzer
nautilus health --url http://localhost:8000/readyz
```

`--air-gapped` overrides `analysis.mode` to `pattern` and refuses any
configured LLM provider (design §3.15, AC-15.2). The REST surface is a
FastAPI app — `POST /v1/request` accepts a `BrokerRequest` and returns a
`BrokerResponse` with `attestation_token` and `request_id`; `/v1/query`
is a locked alias (D-9). Mount it under your own ASGI stack with
`create_app`:

```python
from nautilus.transport import create_app

app = create_app("nautilus.yaml")  # FastAPI; lifespan owns one Broker
```

See [`./specs/reasoning-engine/design.md`](./specs/reasoning-engine/design.md)
for the architecture and
[`./specs/reasoning-engine/requirements.md`](./specs/reasoning-engine/requirements.md)
for the user stories, FRs, and ACs this phase satisfies.

## Async usage

From inside a running event loop, call `await broker.arequest(...)` —
`broker.request()` deliberately raises `RuntimeError` in that context
(design §8, UQ-4) to prevent nested `asyncio.run` calls.

## Development

```bash
uv sync
uv run pytest -m unit            # fast suite, no containers
uv run pytest -m integration     # full e2e, boots PostgreSQL via testcontainers
uv run ruff check && uv run ruff format --check && uv run pyright
```

## License

See `LICENSE`.
