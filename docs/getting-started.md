# Getting Started

Nautilus is a policy-first data broker built on Fathom. Define data sources
and routing rules in YAML, then call `broker.request(...)` to get
scope-enforced, attested results.

## Installation

Requires Python 3.13 or later.

```bash
uv add nautilus-rkm
```

## Configuration

This walkthrough uses a self-contained, in-memory demo adapter so you can run
your first request with nothing but the repo — no database or external service
required. (For a real source, swap `type: demo-local` for `postgres` and point
`connection` at your database; see the [Adapter SDK](reference/adapter-sdk.md).)

Save this single-file adapter as `demo_adapter.py`:

```python
from typing import Any, ClassVar

from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint


class DemoLocalAdapter:
    source_type: ClassVar[str] = "demo-local"

    async def connect(self, config: SourceConfig) -> None:
        pass

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        return AdapterResult(
            source_id="main-db",
            rows=[
                {"order_id": 1001, "user_id": 42, "total": 19.99},
                {"order_id": 1002, "user_id": 42, "total": 7.50},
            ],
            duration_ms=0,
        )

    async def close(self) -> None:
        pass
```

Create a `nautilus.yaml` alongside it:

```yaml
sources:
  - id: main-db
    type: demo-local
    description: "In-memory demo source (no external service required)"
    classification: confidential
    data_types: [users, orders]
    allowed_purposes: [support]
    connection: "memory://"

adapters:
  - module_path: ./demo_adapter.py
    class: DemoLocalAdapter
    source_type: demo-local

rules:
  user_rules_dirs: []

analysis:
  keyword_map:
    orders: [order, orders]

attestation:
  enabled: true

audit:
  path: ./audit.jsonl
```

## First request

Run this from the directory containing `nautilus.yaml` and `demo_adapter.py`:

```python
from nautilus import Broker

with Broker.from_config("nautilus.yaml") as broker:
    response = broker.request(
        "agent-alpha",
        "Find recent orders for user 42",
        {"clearance": "confidential", "purpose": "support", "session_id": "s1"},
    )
    print(response.outcome)         # "allowed"
    print(response.data)            # {"main-db": [{"order_id": 1001, ...}, {"order_id": 1002, ...}]}
    print(response.sources_queried) # ["main-db"]
    print(response.attestation_token)
```

The `with` block runs `setup()` on the way in — which is what creates the
schema for the persistent session stores — and closes the broker on the way
out. In async code the same shape is `async with await Broker.afrom_config(...)`;
the two are genuinely different because `close()` refuses to run inside a
running event loop.

When a source is missing from `response.data`, the response says why:
`response.denial_records` carries the reason and the rule for anything
refused, `response.skip_records` for anything the intent never asked for, and
`response.rule_trace` is the rules that fired.

`response` is a `BrokerResponse`: `response.data` maps source IDs to result
rows, `response.attestation_token` is a signed JWS, and `response.request_id`
joins the response to its audit entry.

Note what the third argument is doing: this config declares no `agents:`, so
the caller's `clearance` and `purpose` are taken at face value. That is fine
for a first run and it is why the broker warns about it at startup — declare
agents in `nautilus.yaml` and those attributes come from the config instead.
See [Operator guide](how-to/operator-guide.md#2-configure-nautilusyaml).

## Next steps

- [Architecture](concepts/architecture.md) — understand the broker pipeline
- [REST API](reference/rest-api.md) — run Nautilus as a service
- [Adapter SDK](reference/adapter-sdk.md) — build custom adapters
