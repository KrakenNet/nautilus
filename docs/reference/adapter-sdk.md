# Adapter SDK

Third-party adapters are written against the `nautilus-rkm` package itself —
the protocol, the types, the scope validators and the compliance suite all
ship with the broker, so an adapter package needs one dependency.

## Install

```bash
uv add nautilus-rkm
```

`nautilus adapters new my-csv-adapter` scaffolds a working package with this
already wired up.

## Quick start

```python
from typing import Any

from nautilus.adapters.base import Adapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

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

`nautilus.adapters.testing.AdapterComplianceSuite` runs the five checks every
adapter has to pass — lifecycle, scope enforcement in both directions,
idempotent close, and the error path. The scaffolded package wires it up:

```python
from nautilus.adapters.testing import AdapterComplianceSuite
from nautilus.config.models import SourceConfig

suite = AdapterComplianceSuite(
    adapter_factory=MyAdapter,
    source_config=SourceConfig(
        id="s1", type="mytype", classification="unclassified", data_types=["generic"]
    ),
)
await suite.test_connect_execute_close_lifecycle()
```
