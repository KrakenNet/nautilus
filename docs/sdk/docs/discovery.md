# Entry-Point Discovery

Nautilus uses Python's standard [entry-point mechanism](https://packaging.python.org/en/latest/specifications/entry-points/) to discover third-party adapters at runtime. This guide covers how registration works and how the broker loads your adapter.

## The `nautilus.adapters` group

All Nautilus adapters are registered under the `nautilus.adapters` entry-point group. When the broker starts, it queries this group to find and load every installed adapter.

### Registering your adapter

Add the following to your package's `pyproject.toml`:

```toml
[project.entry-points."nautilus.adapters"]
my_source = "my_adapter_package:MyAdapter"
```

Where:

- **`my_source`** — the entry-point name. Must match your adapter's `source_type` class variable.
- **`my_adapter_package:MyAdapter`** — the dotted module path and class name, separated by a colon.

### Multiple adapters in one package

A single package can register multiple adapters:

```toml
[project.entry-points."nautilus.adapters"]
redis = "my_adapters.redis:RedisAdapter"
mongodb = "my_adapters.mongo:MongoAdapter"
```

## How the broker discovers adapters

At startup, the broker calls `importlib.metadata.entry_points()` to enumerate all installed adapters:

```python
from importlib.metadata import entry_points

discovered = entry_points(group="nautilus.adapters")
for ep in discovered:
    adapter_class = ep.load()  # imports the module and resolves the class
    ADAPTER_REGISTRY[ep.name] = adapter_class
```

The broker merges discovered adapters with its static `ADAPTER_REGISTRY`. Entry-point adapters take precedence over built-in adapters with the same `source_type`, allowing operators to override default behavior.

### Discovery flow

```
Broker startup
  │
  ├─ Load static ADAPTER_REGISTRY (built-in adapters)
  │
  ├─ Call entry_points(group="nautilus.adapters")
  │   │
  │   └─ For each entry point:
  │       ├─ ep.load() → import module, resolve class
  │       ├─ Validate: class satisfies Adapter Protocol (runtime_checkable)
  │       └─ Register: ADAPTER_REGISTRY[ep.name] = adapter_class
  │
  └─ Ready to route
```

## Verifying registration

After installing your package (`pip install -e .`), confirm the entry point is visible:

```python
from importlib.metadata import entry_points

eps = entry_points(group="nautilus.adapters")
names = [ep.name for ep in eps]
print(names)
# ['my_source', 'influxdb', 's3', ...]
```

### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Adapter not in `entry_points()` | Package not installed in the active environment | Run `pip install -e .` in the correct venv |
| `ModuleNotFoundError` on broker start | Entry-point value has wrong module path | Check the colon-separated path in `pyproject.toml` |
| Adapter ignored by broker | `ep.name` does not match `source_type` | Ensure the entry-point key matches the `source_type` ClassVar |
| `TypeError: not a runtime checkable Protocol` | Class missing required methods | Implement all methods: `connect`, `execute`, `close` |

## `importlib.metadata` reference

The SDK relies on `importlib.metadata` from the Python standard library (3.9+). Key functions:

```python
from importlib.metadata import entry_points

# Get all adapters
adapters = entry_points(group="nautilus.adapters")

# Get a specific adapter
eps = entry_points(group="nautilus.adapters", name="my_source")

# Load the class
adapter_class = list(eps)[0].load()
```

!!! note
    On Python 3.11+, `entry_points()` supports the `group` and `name` keyword filters directly. The SDK requires Python >= 3.11.

## Related

- [Tutorial](tutorial.md) — end-to-end adapter walkthrough including entry-point setup
- [API Reference — Protocol](reference/protocol.md) — the `Adapter` protocol your class must satisfy
