# Developing Adapters

An adapter is the only code that touches your data. This page is the whole
path, once: empty directory → scaffolded package → a real CSV adapter →
installed → declared in `nautilus.yaml` → a served, scoped request → the
compliance suite green.

Every command below is a real command and every block of output is what it
actually printed. Substitute your own name for `my-csv-adapter` and the outputs
change only where the name appears.

For the protocol, the types, the helper API and the full error catalogue, see
the [Adapter SDK reference](../reference/adapter-sdk.md).

**Before you start:** Python 3.13+, `nautilus-rkm` installed in the environment
you will run the broker from, and `copier` (`pip install copier`) for the
scaffolder.

## 1. Scaffold

```bash
mkdir ~/work && cd ~/work
nautilus adapters new my-csv-adapter --dir .
```

```
OK: scaffolded adapter package at my-csv-adapter
  source type : my-csv
  class       : my_csv_adapter.MyCsvAdapter
  next steps  :
    cd my-csv-adapter
    pip install -e ".[test]" && pytest -v
    nautilus adapters list   # confirm discovery once installed
```

Four files:

```
my-csv-adapter/pyproject.toml
my-csv-adapter/README.md
my-csv-adapter/src/my_csv_adapter/__init__.py
my-csv-adapter/tests/test_compliance.py
```

Names are derived from the distribution name, which must match
`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`: `my-csv-adapter` → package `my_csv_adapter`,
class `MyCsvAdapter`, source type `my-csv`. A trailing `-adapter` token is
dropped from the class name and the source type, not from the package name.

The generated `__init__.py` is a working adapter over two hard-coded rows —
enough to install, register and serve before you have written anything.

## 2. Prove the loop before you write code

```bash
cd my-csv-adapter
pip install -e ".[test]"
pytest -q
```

```
.....                                                                    [100%]
5 passed in 0.50s
```

Five checks, one per compliance method — lifecycle, valid operator, invalid
operator, idempotent close, error path. They are described member by member in
the [reference](../reference/adapter-sdk.md#compliance-suite). Green now; keep
them green as you replace the stub.

## 3. Implement it

Replace `src/my_csv_adapter/__init__.py`. This one reads a CSV named by
`config.connection` and applies every scope constraint it is given, refusing
the operators a flat file cannot express:

```python
"""MyCsvAdapter — Nautilus adapter for the 'my-csv' source type."""

from __future__ import annotations

import csv
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from nautilus.adapters.base import AdapterError, ScopeEnforcementError, validate_field
from nautilus.adapters.schema import AdapterField, AdapterSchema, AdapterTable
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# The operators a CSV scan can express. Everything else must fail closed.
_SUPPORTED: frozenset[str] = frozenset({"=", "!=", "IN", "NOT IN", "IS NULL"})


def _matches(cell: str | None, operator: str, value: Any) -> bool:
    if operator == "IS NULL":
        return not cell
    if operator in {"IN", "NOT IN"}:
        wanted = {str(v) for v in (value if isinstance(value, list) else [value])}
        return (cell in wanted) if operator == "IN" else (cell not in wanted)
    return (cell == str(value)) if operator == "=" else (cell != str(value))


class MyCsvAdapter:
    """Serves the rows of one CSV file, scoped."""

    source_type: ClassVar[str] = "my-csv"

    def __init__(self) -> None:
        self._config: SourceConfig | None = None
        self._rows: list[dict[str, str]] = []
        self._closed = False

    async def connect(self, config: SourceConfig) -> None:
        path = Path(config.connection)
        try:
            with path.open(newline="", encoding="utf-8") as handle:
                self._rows = [dict(row) for row in csv.DictReader(handle)]
        except OSError as exc:
            raise AdapterError(f"source '{config.id}': cannot read {path}: {exc}") from exc
        self._config = config

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        if self._config is None:
            raise AdapterError("MyCsvAdapter.execute() called before connect()")
        started = time.perf_counter()
        rows = self._rows
        for constraint in scope:
            if constraint.operator not in _SUPPORTED:
                raise ScopeEnforcementError(
                    f"MyCsvAdapter: cannot enforce '{constraint.operator}' over a CSV "
                    f"(supported: {sorted(_SUPPORTED)})"
                )
            validate_field(constraint.field)
            rows = [
                row
                for row in rows
                if _matches(row.get(constraint.field), constraint.operator, constraint.value)
            ]
        return AdapterResult(
            source_id=self._config.id,
            rows=list(rows),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    async def get_schema(self) -> AdapterSchema:
        if self._config is None:
            raise AdapterError("MyCsvAdapter.get_schema() called before connect()")
        columns = tuple(self._rows[0]) if self._rows else ()
        return AdapterSchema(
            adapter_id=self._config.id,
            source_type=self.source_type,
            tables=(
                AdapterTable(
                    name=Path(self._config.connection).name,
                    fields=tuple(
                        AdapterField(name=c, type="string", nullable=True) for c in columns
                    ),
                ),
            ),
            capability_flags={"scope_pushdown": False},
            fetched_at=datetime.now(UTC),
        )

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._rows = []


__all__ = ["MyCsvAdapter"]
```

Four things in there are the contract, not style:

- **Every constraint is applied or refused.** The loop narrows `rows` for each
  one; an operator outside `_SUPPORTED` raises before any row is returned.
  Nothing downstream re-checks your rows against `scope`, so an ignored
  constraint is a silent over-scope that the audit log will report as enforced.
- **`source_id` comes from `config.id`.** The broker files rows under it, and
  `scope` may be empty, so it is not a source of the id.
- **`close()` is idempotent.** The `_closed` flag is what makes the second call
  a no-op.
- **`connect` raises `AdapterError`, not `FileNotFoundError`.** Typed failures
  become one clean `sources_errored` entry instead of a driver exception with
  no source name in it.

Your compliance fixture now needs a file to read. In
`tests/test_compliance.py`, give the fixture a real CSV:

```python
@pytest.fixture
def source_config(tmp_path) -> SourceConfig:
    csv_file = tmp_path / "orders.csv"
    csv_file.write_text("order_id,region\n1001,emea\n1002,apac\n")
    return SourceConfig(
        id="test-my-csv",
        type="my-csv",
        connection=str(csv_file),
        description="Test my-csv source",
        classification="unclassified",
        data_types=["generic"],
    )
```

```bash
pytest -q
```

```
.....                                                                    [100%]
5 passed in 0.50s
```

## 4. Register it

The scaffold already declared the entry point — this is the whole of the
registration surface:

```toml
[project.entry-points."nautilus.adapters"]
my-csv = "my_csv_adapter:MyCsvAdapter"
```

The entry-point **name** is the `type:` key sources will use; the **target**
must be `module:Class`, not a module. Reinstall after any change to
`pyproject.toml`, then check the broker can see it:

```bash
cd ~/work
cat > orders.csv <<'CSV'
order_id,region,total
1001,emea,19.99
1002,apac,7.50
1003,emea,42.00
CSV

cat > nautilus.yaml <<'YAML'
sources:
  - id: orders
    type: my-csv
    description: Order rows from a CSV export.
    classification: unclassified
    data_types: [orders]
    allowed_purposes: [support]
    connection: ./orders.csv

rules:
  user_rules_dirs: [./rules]

agents:
  agent-alpha:
    id: agent-alpha
    clearance: confidential
    allowed_purposes: [support]

audit:
  path: ./audit.jsonl

api:
  keys:
    - deadbeefdeadbeefdeadbeefdeadbeef
YAML

nautilus adapters list --config nautilus.yaml
```

```
  orders  type=my-csv  status=configured
```

`configured`, not `active`: this process is not the one serving requests, so it
cannot know whether the source is connected or quarantined. `nautilus adapters
list --url http://127.0.0.1:8000 --api-key <key>` asks a running broker for
live status.

Replace the generated API key before anything else can reach the port.

## 5. Give the router something to scope on

An adapter that never receives a constraint has never had its enforcement
exercised. Add one rule so `support` may read EMEA rows only:

```bash
mkdir -p rules
cat > rules/scope.yaml <<'YAML'
module: nautilus-routing
ruleset: emea-only
version: "1.0"
rules:
  - name: scope-orders-to-emea
    description: "Support may read EMEA order rows only."
    salience: 50
    when:
      - template: routing_decision
        conditions:
          - slot: source_id
            bind: ?sid
    then:
      action: route
      reason: "support is scoped to EMEA"
      assert:
        - template: scope_constraint
          slots:
            source_id: "?sid"
            field: "region"
            operator: "="
            value: "emea"
YAML
```

`module:` must name a module the engine already registered — `nautilus-routing`
is the built-in routing module. Matching `routing_decision` in the `when:`
block makes the rule fire *after* routing, which is what the default
`rules.consistency_checks` requires: a scope constraint on a source that was
never routed is an error, not a no-op.

## 6. Serve, and make a request that reaches your adapter

```bash
nautilus serve --config nautilus.yaml --bind 127.0.0.1:8000
```

```
INFO:nautilus.core.broker:discovered adapter entry-point 'my-csv' -> MyCsvAdapter (from 'my-csv-adapter')
INFO:     Started server process [2687371]
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

One INFO line per discovered entry point — that is how you confirm the broker
loaded *your* class from *your* distribution. From another shell:

```bash
curl -s -X POST http://127.0.0.1:8000/v1/request \
  -H 'X-API-Key: deadbeefdeadbeefdeadbeefdeadbeef' \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"agent-alpha","intent":"list recent orders","context":{"purpose":"support"}}'
```

```json
{
  "data": {"orders": [
    {"order_id": "1001", "region": "emea", "total": "19.99"},
    {"order_id": "1003", "region": "emea", "total": "42.00"}
  ]},
  "sources_queried": ["orders"],
  "sources_errored": [],
  "scope_restrictions": {"orders": [
    {"source_id": "orders", "field": "region", "operator": "=",
     "value": "emea", "expires_at": null, "valid_from": null}
  ]},
  "rule_trace": [
    "nautilus-routing::match-sources-by-data-type",
    "nautilus-routing::scope-orders-to-emea"
  ],
  "truncated_sources": [],
  "attestation_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ..."
}
```

Row `1002` is in the file and not in the answer: your `execute` applied the
constraint. `scope_restrictions` is what the router issued and what the
attestation signs — it is *not* evidence that you enforced it. That evidence is
the diff between the CSV and `data`, and your own tests.

## 7. Schema and drift

`get_schema` is what makes the source visible to drift detection:

```bash
nautilus adapters schema orders --config nautilus.yaml
```

```
  adapter_id: orders
  source_type: my-csv
  tables: ({'name': 'orders.csv', 'fields': ({'name': 'order_id', 'type': 'string', 'nullable': True, 'description': ''}, {'name': 'region', 'type': 'string', 'nullable': True, 'description': ''}, {'name': 'total', 'type': 'string', 'nullable': True, 'description': ''}), 'indexes': (), 'primary_key': ()},)
  capability_flags: {'scope_pushdown': False}
  fetched_at: 2026-09-01T01:57:54.800723+00:00
```

```bash
nautilus adapters schema-fingerprint orders --config nautilus.yaml
nautilus adapters schema-diff orders --config nautilus.yaml
```

```
sha256:b9fe2c8b9b7cb182205875423f5dbd46eb6c659e168a0baac47a38c5674f30de
WARN: no stored fingerprint for 'orders'; treating as new
  no baseline fingerprint for 'orders'
  current: sha256:b9fe2c8b9b7cb182205875423f5dbd46eb6c659e168a0baac47a38c5674f30de
```

Once a baseline exists, a changed fingerprint quarantines the source until an
operator runs `nautilus adapters schema-ack <id> --config … --reason '…' --yes`
with `NAUTILUS_REVIEWER` set. Skip `get_schema` and you get
`NotImplementedError: AC-21.b: this adapter must implement get_schema()
(task-006)` from these three commands and no drift detection at all. Returning
`AdapterSchema.unknown(...)` is the honest answer only for a backend with no
schema to read.

## Loading without packaging

For a single-file adapter you do not want to publish, point the config at the
file instead of installing a distribution:

```yaml
adapters:
  - module_path: ./adapters/csv_adapter.py   # relative to the config file
    class: MyCsvAdapter
    source_type: my-csv

sources:
  - id: orders
    type: my-csv
    # ...
```

The difference that matters: entry-point discovery is best-effort — a broken
third-party package is logged and skipped — while `adapters:` entries are
explicit operator config and **fail closed**. A missing file, an import error,
a missing class, a protocol gap or a `source_type` mismatch refuses to start
the broker, and every module loaded so far is rolled back out of `sys.modules`.

When the same `source_type` is declared more than once, the order is
**built-ins < entry points < local paths**. An entry point may not take over a
built-in type at all; use `adapters:` if you deliberately want to replace one.

!!! warning "Trust boundary"
    A local-path module is executed at broker start with the broker's
    privileges — `adapters:` entries carry the same trust as installed
    packages. The config file must only be writable by the operator.

## When your rows come back short

Two caps can shorten a result and both are reported. If you cap the row set
yourself, set `AdapterResult.truncated=True`. Whatever you return is then held
to the source's `max_response_bytes` (default 8 MiB, per source):

```yaml
sources:
  - id: orders
    type: my-csv
    max_response_bytes: 40   # deliberately tiny, to show the bound
```

```
WARNING:nautilus.core.broker:source 'orders' returned more than max_response_bytes (40); kept 1 of 2 rows
```

```json
"data": {"orders": [{"order_id": "1001", "region": "emea", "total": "19.99"}]},
"truncated_sources": ["orders"]
```

Whole rows only, never fewer than one, and the source id lands in
`truncated_sources` so the caller can tell a partial answer from a complete
one. The trim happens *after* your rows exist — if your backend can stop
reading early, do that too; `bounded_rows(rows, budget)` from
`nautilus.adapters.base` is the same helper the broker uses.

Returning more than the **scope** allows is not truncation and has no backstop:
nothing trims it, nothing detects it. See
[Honouring a `ScopeConstraint`](../reference/adapter-sdk.md#honouring-a-scopeconstraint).

## When it does not work

The five you are most likely to hit while following this page. Every string the
broker can emit about an extension is in the
[failure catalogue](../reference/adapter-sdk.md#failure-catalogue).

| Symptom | What it means | Do this |
| --- | --- | --- |
| `adapter entry-point 'my-csv' resolved to non-class module; skipping` then `ERROR: could not load nautilus.yaml: Unsupported source type 'my-csv' for id='orders'` | Your entry point points at the module | Use `module:Class`, reinstall |
| `ERROR: could not load nautilus.yaml: Unsupported source type='my-csvv' for id='orders' (supported: [...])` | Typo, or the package is not installed in *this* environment | Compare `type:` with the printed list; `pip show my-csv-adapter` |
| `adapter entry-point 'my-csv' resolved to MyCsvAdapter, which is missing Adapter protocol members ['close']` | A method or `source_type` is absent | Add the listed members and reinstall |
| `sources_errored: [{"error_type": "AdapterContractError", "message": "adapter returned dict, expected AdapterResult"}]` | `execute` returned something else | Return `AdapterResult`; other sources in the request were unaffected |
| `E   AssertionError: an unsupported scope operator must raise ScopeEnforcementError` | `execute` accepted an operator it does not implement | Raise `ScopeEnforcementError` instead of falling through |

## Before you ship

- [ ] All five compliance checks pass against your real implementation, not the stub.
- [ ] Every operator in `_SUPPORTED` (or its equivalent) is covered by a test that asserts the *rows*, not just the type.
- [ ] Every operator outside it raises `ScopeEnforcementError`.
- [ ] `close()` twice is a no-op; `execute` before `connect` raises `AdapterError`.
- [ ] Values from `ScopeConstraint.value` are parameterised, never interpolated; identifiers go through `validate_field` / `quote_identifier` / `render_field`.
- [ ] `get_schema` reflects something real, or the backend genuinely has no schema.
- [ ] Non-reproducible sources declare `capabilities = frozenset({"non_deterministic"})`.
- [ ] Driver exceptions are wrapped — decorate `execute` with `@wrap_execute` or raise `AdapterError` yourself.
