# Custom Adapter

Build a data-source adapter from scratch. This example implements a CSV file adapter.

## What Nautilus Provides

Everything an adapter needs is in the `nautilus-rkm` package you already have:

- **`Adapter` protocol** — the interface your adapter must satisfy: `connect()`, `execute()`, `close()`
- **Pydantic types** — `IntentAnalysis`, `ScopeConstraint`, `AdapterResult`, `ErrorRecord`
- **`SourceConfig`** — configuration model with `extra="allow"` for custom fields
- **Exception hierarchy** — `AdapterError`, `ScopeEnforcementError`
- **Scope validators** — `validate_operator()`, `validate_field()`, `render_field()`
- **Compliance test suite** — `AdapterComplianceSuite` with 5 standard tests

## The CSV Adapter

`csv_adapter.py` implements a simple adapter that:

1. **`connect(config)`** — reads a CSV file into memory
2. **`execute(intent, scope, context)`** — filters rows by scope constraints (`=`, `!=`, `IN`, `NOT IN`, `LIKE`, `IS NULL`)
3. **`close()`** — releases resources (idempotent)

## Project Structure

```
custom-adapter/
├── csv_adapter.py         # The adapter implementation
├── test_compliance.py     # SDK compliance suite + adapter-specific tests
├── sample.csv             # Sample data file
└── README.md
```

## Running the Tests

```bash
# From the repo root
cd examples/custom-adapter

# Run compliance + adapter tests
pytest test_compliance.py -v
```

## How It Works

### 1. Implement the Adapter Protocol

```python
from typing import Any, ClassVar

from nautilus.adapters.base import Adapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

class CsvAdapter:
    source_type: ClassVar[str] = "csv"

    async def connect(self, config: SourceConfig) -> None:
        # Load data from config.connection (file path)
        ...

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        # Filter data by scope constraints, return AdapterResult
        ...

    async def close(self) -> None:
        # Cleanup — must be idempotent
        ...
```

### 2. Handle Scope Constraints

The broker sends scope constraints based on Fathom rules. Your adapter maps them to your data source's query language:

| Operator | CSV Mapping |
|----------|-------------|
| `=` | Exact string match |
| `!=` | Exclude match |
| `IN` | Match any in list |
| `NOT IN` | Exclude any in list |
| `LIKE` | Case-insensitive substring |
| `IS NULL` | Empty or missing field |

Unsupported operators must raise `ScopeEnforcementError`.

### 3. Run the Compliance Suite

The SDK provides `AdapterComplianceSuite` with 5 standard tests:

- **Lifecycle** — `connect` -> `execute` -> `close` completes without error
- **Valid operator** — standard operators are accepted
- **Invalid operator** — `ScopeEnforcementError` raised for unknown operators
- **Idempotent close** — calling `close()` twice doesn't raise
- **Error path** — adapter handles impossible queries gracefully

### 4. Register as an Entry Point

To make your adapter discoverable by the Nautilus broker, add to your `pyproject.toml`:

```toml
[project.entry-points."nautilus.adapters"]
csv = "my_package.csv_adapter:CsvAdapter"
```

Then configure it in `nautilus.yaml`:

```yaml
sources:
  - id: employee_data
    type: csv
    description: "Employee directory"
    classification: unclassified
    data_types: [employee, directory]
    connection: /data/employees.csv
```

## Scaffold with Copier

For a complete adapter package with CI, use the Copier template:

```bash
nautilus adapters new my-adapter
```

This generates a full Python package with:
- `pyproject.toml` with entry-point registration
- Adapter skeleton implementing the protocol
- Compliance test wiring
- GitHub Actions CI workflow
