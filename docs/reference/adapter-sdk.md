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
from typing import Any

from nautilus_adapter_sdk import (
    Adapter,
    AdapterResult,
    IntentAnalysis,
    ScopeConstraint,
    SourceConfig,
)

class MyAdapter(Adapter):
    async def connect(self, config: SourceConfig) -> None: ...
    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult: ...
    async def close(self) -> None: ...
```

`connect` receives the source's own YAML block, so the adapter reads its
connection string and options from `config` rather than from the environment.
`context` carries the request's session token and purpose; forward the token to
downstream services with `session_token_headers(context)`.

## Registration

Register your adapter via entry points in `pyproject.toml`:

```toml
[project.entry-points."nautilus.adapters"]
my-adapter = "my_package.adapter:MyAdapter"
```

The target must be the adapter **class**, not the module: an entry point that
resolves to a module is skipped with a warning at startup, so the source type
never registers and every source declaring it fails config load.

## Compliance testing

The SDK includes `AdapterComplianceSuite` for validating adapter implementations.
See the [SDK testing docs](../sdk/docs/reference/testing.md) for details.
