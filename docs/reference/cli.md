# CLI Reference

Nautilus provides a CLI via `nautilus` (or `python -m nautilus`).

## `nautilus serve`

Start the broker transport.

```
nautilus serve --config nautilus.yaml [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `nautilus.yaml` | Path to configuration file |
| `--transport` | `rest` | Transport mode: `rest`, `mcp`, or `both` |
| `--bind` | `0.0.0.0:8000` | Bind address for REST transport |
| `--air-gapped` | — | Force pattern analyzer, refuse LLM providers |

## `nautilus health`

Probe a running instance.

```
nautilus health --url http://localhost:8000/readyz
```

## `nautilus version`

Print the installed version.

```
nautilus version
```
