# Developing Adapters

How to build, test, and load a custom source adapter. For the protocol
and type reference, see the [Adapter SDK](../reference/adapter-sdk.md).

## Scaffold a new adapter

```bash
nautilus adapters new my-csv-adapter --dir .
```

generates a pip-installable package:

```
my-csv-adapter/
├── pyproject.toml          # entry point + test extras pre-wired
├── README.md
├── src/my_csv_adapter/
│   └── __init__.py         # MyCsvAdapter stub (source_type "my-csv")
└── tests/
    └── test_compliance.py  # SDK compliance suite, ready to run
```

Names derive from the package name: `my-csv-adapter` → package
`my_csv_adapter`, class `MyCsvAdapter`, source type `my-csv` (a trailing
`-adapter` token is dropped from the class and source type). Names must
be lowercase kebab-case.

The stub implements the full `Adapter` protocol with sample rows and
fail-closed scope enforcement — replace `execute()`'s internals with
your real data access, keeping the operator/field validation.

## Run the compliance suite

```bash
cd my-csv-adapter
pip install -e ".[test]"
pytest
```

The generated `test_compliance.py` runs the SDK's five-part suite:
protocol conformance, scope-constraint enforcement (unknown operators
must raise, never silently pass), lifecycle (connect → execute → close,
idempotent close), error surfacing, and result shape. A scaffolded
adapter passes out of the box; keep it passing as you implement.

## Load your adapter

### Option A — entry point (installed package)

The scaffold pre-declares it in `pyproject.toml`:

```toml
[project.entry-points."nautilus.adapters"]
my-csv = "my_csv_adapter:MyCsvAdapter"
```

Install the package next to `nautilus-rkm` and the broker discovers it
at startup. The entry-point *name* is the source `type` key and must
resolve to the adapter **class** (not its module). Discovery is
best-effort: a broken third-party package is logged and skipped, never
fatal.

### Option B — local path (no packaging)

Point the broker config at the file:

```yaml
adapters:
  - module_path: ./adapters/csv_adapter.py   # relative to the config file
    class: MyCsvAdapter
    source_type: my-csv

sources:
  - id: local_rows
    type: my-csv
    # ...
```

Unlike entry-point discovery, local-path entries are explicit operator
config and **fail closed**: a missing file, import error, missing class,
protocol gap, or `source_type` mismatch refuses to start the broker.

!!! warning "Trust boundary"
    A local-path module is executed with the broker's privileges —
    `adapters:` entries carry the same trust as installed packages. The
    config file must only be writable by the operator.

Registry precedence when the same `source_type` is declared more than
once: built-ins < entry points < local paths.

## Implementing `execute()` safely

```python
from nautilus_adapter_sdk import validate_operator, validate_field

async def execute(self, intent, scope, context):
    for constraint in scope:
        validate_operator(constraint.operator)   # raises ScopeEnforcementError
        validate_field(constraint.field)
    ...
```

- Validate **every** constraint before touching the backend — scope
  violations must fail before any data access.
- An operator your backend can't translate must *raise*, not be ignored:
  silently dropping a constraint returns over-scoped data.
- Use parameterized queries / identifier quoting for anything derived
  from constraint values.

## Schema fingerprinting

Implement `get_schema()` to opt into drift detection: the broker
fingerprints the schema at connect and quarantines the source when the
fingerprint changes unexpectedly (see `nautilus adapters schema-diff` /
`schema-ack` in the [operator guide](operator-guide.md)). Returning a
static capability-only schema is fine for backends without
introspectable schemas (REST and LLM adapters do this).
