# Add a Postgres Source

Wire a PostgreSQL table into the broker as a routed, scope-enforced
source.

## 1. Declare the source

```yaml
sources:
  - id: orders_db
    type: postgres
    description: "Order history (production replica)"
    classification: confidential
    data_types: [orders, customers]
    allowed_purposes: [support, fraud-investigation]
    connection: ${ORDERS_DSN}
    table: orders
```

- `connection` is a Postgres DSN, interpolated from the environment —
  never commit credentials.
- `classification` is checked against the requesting agent's clearance
  by the default classification rule (deny unless clearance dominates).
- `allowed_purposes` — a request whose `purpose` is not listed is denied
  by the default purpose-mismatch rule. An empty list allows any purpose.
- `data_types` drive both routing (intent analysis matches requested
  data types to sources) and the auto-generated intent vocabulary.

## 2. Restart and verify routing

```bash
nautilus serve --config nautilus.yaml &
curl -s -X POST http://127.0.0.1:8000/v1/request \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-alpha",
    "intent": "recent orders for customer 42",
    "context": {"clearance": "confidential", "purpose": "support", "session_id": "s1"}
  }' | python -m json.tool
```

`sources_queried` should include `orders_db`. Scope constraints emitted
by your rules arrive at the adapter as WHERE-clause fragments with
injection-safe field validation.

## 3. Confirm the denial path

Re-send with `"purpose": "marketing"` — the response's `sources_denied`
should list `orders_db` with the purpose-mismatch reason, and the audit
entry (`GET /v1/audit/{request_id}`) records the denying rule.
