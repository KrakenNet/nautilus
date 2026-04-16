# Write Your First Adapter

This tutorial walks through building a complete Nautilus adapter from scratch — from installing the SDK to passing the compliance suite.

## Prerequisites

- Python >= 3.11
- A virtual environment (recommended)

## Step 1: Install the SDK

```bash
pip install nautilus-adapter-sdk
```

This installs the protocol definitions, Pydantic models, and the compliance test suite.

## Step 2: Create the project

Set up a minimal package structure:

```
my-nautilus-adapter/
├── pyproject.toml
├── src/
│   └── my_adapter/
│       ├── __init__.py
│       └── adapter.py
└── tests/
    └── test_compliance.py
```

Your `pyproject.toml`:

```toml
[project]
name = "my-nautilus-adapter"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "nautilus-adapter-sdk",
]

[project.entry-points."nautilus.adapters"]
my_source = "my_adapter:MyAdapter"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

## Step 3: Implement the Adapter Protocol

Create `src/my_adapter/adapter.py`:

```python
from typing import Any, ClassVar

from nautilus_adapter_sdk.config import SourceConfig
from nautilus_adapter_sdk.types import (
    AdapterResult,
    DataRecord,
    IntentAnalysis,
    ScopeConstraint,
)


class MyAdapter:
    """Adapter for the 'my_source' data source type."""

    source_type: ClassVar[str] = "my_source"

    def __init__(self) -> None:
        self._client = None

    async def connect(self, config: SourceConfig) -> None:
        """Initialize the client connection.

        Called once before any execute() calls. Store whatever client
        or session state you need for subsequent queries.
        """
        self._config = config
        # Replace with your real client initialization:
        self._client = {"connected": True, "dsn": config.connection}

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Fetch records from the data source.

        Args:
            intent: The parsed intent from the reasoning engine.
            scope: Operator-defined scope constraints for this query.
            context: Additional routing context from the broker.

        Returns:
            AdapterResult containing the fetched DataRecord list.
        """
        if self._client is None:
            return AdapterResult(
                records=[],
                error="Not connected — call connect() first",
            )

        # Replace with your real data-fetch logic:
        records = [
            DataRecord(
                source_id=self._config.id,
                data={"sample": "record"},
            )
        ]
        return AdapterResult(records=records)

    async def close(self) -> None:
        """Release resources. Must be idempotent.

        The broker may call close() multiple times (e.g., on error
        recovery). Subsequent calls after the first must be no-ops.
        """
        self._client = None
```

Re-export the adapter from `src/my_adapter/__init__.py`:

```python
from my_adapter.adapter import MyAdapter

__all__ = ["MyAdapter"]
```

### Key rules

1. **`source_type` must be a `ClassVar[str]`** — this is the identifier the broker uses to match adapters to source configurations.
2. **`connect()` is called once** before any `execute()` calls.
3. **`close()` must be idempotent** — calling it multiple times must not raise.
4. **Errors** — return an `AdapterResult` with the `error` field set, or raise `AdapterError` / `ScopeEnforcementError` from `nautilus_adapter_sdk.exceptions`.

## Step 4: Register the entry point

The `[project.entry-points."nautilus.adapters"]` section in your `pyproject.toml` (shown in Step 2) tells the broker how to discover your adapter at startup.

The key (`my_source`) must match your adapter's `source_type`. The value is the dotted import path to the adapter class.

After installation (`pip install -e .`), verify the entry point is registered:

```python
from importlib.metadata import entry_points

eps = entry_points(group="nautilus.adapters")
for ep in eps:
    print(f"{ep.name} -> {ep.value}")
# my_source -> my_adapter:MyAdapter
```

See the [Discovery guide](discovery.md) for full details on entry-point mechanics.

## Step 5: Run the compliance suite

Create `tests/test_compliance.py`:

```python
import pytest
from nautilus_adapter_sdk.testing.compliance import AdapterComplianceSuite
from nautilus_adapter_sdk.config import SourceConfig
from my_adapter import MyAdapter


class TestMyAdapter(AdapterComplianceSuite):
    """Validate MyAdapter against the Nautilus Adapter Protocol."""

    @pytest.fixture
    def adapter(self):
        return MyAdapter()

    @pytest.fixture
    def source_config(self):
        return SourceConfig(
            id="test-1",
            type="my_source",
            connection="my://localhost:5000",
        )
```

Run the tests:

```bash
pytest tests/test_compliance.py -v
```

The compliance suite validates:

| Test | What it checks |
|------|---------------|
| `test_connect_execute_close_lifecycle` | Full happy-path lifecycle |
| `test_scope_enforcement_valid_operator` | Accepts valid operator scopes |
| `test_scope_enforcement_invalid_operator` | Rejects invalid operator scopes |
| `test_idempotent_close` | `close()` can be called multiple times |
| `test_error_path_returns_error_record` | Error conditions produce proper error results |

All five tests must pass for the adapter to be considered protocol-compliant.

## Next steps

- [Discovery](discovery.md) — deep dive into entry-point registration and how the broker discovers adapters
- [API Reference](reference/protocol.md) — full protocol and type documentation
