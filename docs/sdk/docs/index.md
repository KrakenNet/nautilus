# Nautilus Adapter SDK

Build third-party data adapters for the Nautilus routing platform.

## Overview

The Nautilus Adapter SDK provides the protocols, types, and testing utilities needed to create adapters that plug into the Nautilus data-routing broker. Adapters connect external data sources (databases, object stores, APIs) to the reasoning pipeline.

Key components:

- **`Adapter` Protocol** — the runtime contract every adapter must satisfy (`connect`, `execute`, `close`)
- **Pydantic models** — `SourceConfig`, `AdapterResult`, `IntentAnalysis`, `ScopeConstraint` and related types
- **`AdapterComplianceSuite`** — a pytest-based test harness that validates your adapter against the protocol contract
- **Entry-point discovery** — register your adapter under the `nautilus.adapters` group so the broker discovers it automatically

## Installation

```bash
pip install nautilus-adapter-sdk
```

The SDK requires **Python >= 3.11** and depends only on `pydantic >= 2.0`.

## Quickstart

### 1. Implement the Adapter Protocol

```python
from typing import Any, ClassVar
from nautilus_adapter_sdk.protocols import Adapter
from nautilus_adapter_sdk.config import SourceConfig
from nautilus_adapter_sdk.types import AdapterResult, IntentAnalysis, ScopeConstraint


class MyAdapter:
    source_type: ClassVar[str] = "my_source"

    async def connect(self, config: SourceConfig) -> None:
        # Initialize your client connection
        ...

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        # Fetch and return data records
        ...

    async def close(self) -> None:
        # Release resources (must be idempotent)
        ...
```

### 2. Register the entry point

In your `pyproject.toml`:

```toml
[project.entry-points."nautilus.adapters"]
my_source = "my_adapter_package:MyAdapter"
```

### 3. Run the compliance suite

```python
# tests/test_compliance.py
from nautilus_adapter_sdk.testing.compliance import AdapterComplianceSuite
from nautilus_adapter_sdk.config import SourceConfig
from my_adapter_package import MyAdapter


class TestMyAdapter(AdapterComplianceSuite):
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

```bash
pytest tests/test_compliance.py -v
```

## Next steps

- [Tutorial](tutorial.md) — full walkthrough of building an adapter from scratch
- [Discovery](discovery.md) — detailed entry-point registration guide
- [API Reference](reference/protocol.md) — auto-generated protocol and type docs
