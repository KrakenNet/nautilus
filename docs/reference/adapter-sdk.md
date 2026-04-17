# Adapter SDK

The Nautilus Adapter SDK (`nautilus-adapter-sdk`) enables third-party adapter
development. Full SDK documentation is available in the
[Adapter SDK docs](../sdk/docs/index.md).

## Install

```bash
uv add nautilus-adapter-sdk
```

## Quick start

```python
from nautilus_adapter_sdk import Adapter, AdapterResult, IntentAnalysis, ScopeConstraint

class MyAdapter(Adapter):
    async def connect(self) -> None: ...
    async def execute(
        self, intent: IntentAnalysis, scope: list[ScopeConstraint]
    ) -> AdapterResult: ...
    async def close(self) -> None: ...
```

## Registration

Register your adapter via entry points in `pyproject.toml`:

```toml
[project.entry-points."nautilus.adapters"]
my-adapter = "my_package.adapter"
```

## Compliance testing

The SDK includes `AdapterComplianceSuite` for validating adapter implementations.
See the [SDK testing docs](../sdk/docs/reference/testing.md) for details.
