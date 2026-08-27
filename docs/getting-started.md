# Getting Started

Nautilus is a policy-first data broker built on Fathom. Define data sources
and routing rules in YAML, then call `broker.request(...)` to get
scope-enforced, attested results.

## Installation

Requires Python 3.13 or later.

```bash
uv add nautilus-rkm
```

## First run

Nothing to configure, nothing to install beyond the package:

```bash
nautilus demo
```

It declares two agent-to-agent handoffs and lets the broker decide each one:

```
  analyst (confidential) hands confidential data to chief (secret)
    handoff ALLOWED

  chief (secret) hands secret data to intern (unclassified)
    handoff DENIED
    reason: receiving agent clearance does not dominate declared classification
    rule:   information-flow-violation
```

That is the whole product in miniature: a decision made by a rule, with the
rule named, and an audit entry written for both outcomes. No database, no
adapter, no network.

## Configuration

```bash
nautilus init
```

writes a `nautilus.yaml` that runs as it stands. Its source has type `static`,
which serves rows declared in the config itself — so a first run needs no
database and no adapter code:

```yaml
sources:
  - id: orders
    type: static
    description: Sample order rows, served from this file.
    classification: unclassified
    data_types: [orders]
    allowed_purposes: [support]
    rows:
      - {order_id: 1001, user_id: 42, total: 19.99}
      - {order_id: 1002, user_id: 43, total: 7.50}

agents:
  agent-alpha:
    id: agent-alpha
    clearance: confidential
    allowed_purposes: [support]

attestation:
  enabled: true

audit:
  path: ./audit.jsonl
```

For a real source, swap the `static` block for the type that matches your data
— `postgres`, `elasticsearch`, `neo4j`, `rest`, `s3` and the rest are built in
— and point `connection` at it. To reach something with no built-in adapter,
`nautilus adapters new` scaffolds one; see the
[Adapter SDK](reference/adapter-sdk.md).

## First request

Run this from the directory containing `nautilus.yaml` and `demo_adapter.py`:

```python
from nautilus import Broker

with Broker.from_config("nautilus.yaml") as broker:
    response = broker.request(
        "agent-alpha",
        "Find recent orders",
        {"purpose": "support", "session_id": "s1"},
    )
    print(response.outcome)         # "allowed"
    print(response.data)            # {"orders": [{"order_id": 1001, ...}, {"order_id": 1002, ...}]}
    print(response.sources_queried) # ["orders"]
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

Note what the third argument is *not* doing: it names a purpose, not a
clearance. `agent-alpha` is declared in the config, so its clearance comes from
there. A config that declares no `agents:` takes the caller's word for both —
which the broker warns about at startup. See
[Operator guide](how-to/operator-guide.md#2-configure-nautilusyaml).

## Next steps

- [Architecture](concepts/architecture.md) — understand the broker pipeline
- [REST API](reference/rest-api.md) — run Nautilus as a service
- [Adapter SDK](reference/adapter-sdk.md) — build custom adapters
