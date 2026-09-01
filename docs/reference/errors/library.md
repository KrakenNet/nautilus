# Embedding Nautilus as a library

Errors that only appear when you construct a `Broker`, an app, or an adapter yourself. Over
HTTP these are unreachable — the transport owns the lifecycle.

## Sync and async

### `Broker.request() called inside a running event loop. Use Broker.arequest() (async) from async contexts.`

**`RuntimeError`**, `nautilus/core/broker.py:1542-1546`.

**Means.** The synchronous facade was called from inside a coroutine. It would need to drive an
event loop that is already running.

**Fix.** `await broker.arequest(...)`. `Broker.request` is for synchronous callers only.

### `Broker.close() called inside a running event loop. Use Broker.aclose() (async) from async contexts.`

**`RuntimeError`**, `nautilus/core/broker.py:3392-3396`. Same rule for shutdown: `await
broker.aclose()`.

### `Broker.{method}() called after close(); the attestation sink and session store are already shut down, so this request could not be receipted. Build a new Broker.`

**`RuntimeError`**, `nautilus/core/broker.py:2021-2026`. `{method}` is the method you called.

**Means.** The broker is closed. It is not reusable: the sink and the session store are gone, so
the request could not be receipted, and an unreceipted decision is not served.

**Fix.** Construct a new `Broker`. A common cause is a `with Broker.from_config(...) as broker:`
block whose reference escaped the block.

```bash
python - <<'PY'
import pathlib, tempfile
from nautilus.core.broker import Broker
d = pathlib.Path(tempfile.mkdtemp())
cfg = d / "nautilus.yaml"
cfg.write_text(f"""
sources:
  - id: notes
    type: static
    classification: unclassified
    data_types: [note]
    allowed_purposes: [research]
    rows:
      - {{id: 1, body: hello}}
agents:
  analyst:
    id: analyst
    clearance: unclassified
    compartments: []
    default_purpose: research
audit:
  path: {d}/audit.jsonl
""")
broker = Broker.from_config(str(cfg))
broker.close()
try:
    broker.request("analyst", "list notes")
except RuntimeError as exc:
    print(exc)
PY
```

### `Broker.declare_handoff() failed for source={source_agent_id!r} receiving={receiving_agent_id!r}: {exc}`

**`PolicyEngineError`**, `nautilus/core/broker.py:1802-1806`. The handoff could not be recorded.
`{exc}` is the engine failure underneath — most often an agent id with no entry under `agents:`.

## Building transports

### `create_app requires either config_path or existing_broker`

**`ValueError`**, `nautilus/transport/fastapi_app.py:441-445`. Both `config_path` (positional)
and `existing_broker` were `None`. Pass a config path, or a broker you already built.

### `create_server requires either config_path or existing_broker`

**`ValueError`**, `nautilus/transport/mcp_server.py:314-318`. The MCP equivalent, same
signature: `create_server(config_path, *, existing_broker=None)`.

```bash
python - <<'PY'
from nautilus.transport.fastapi_app import create_app
try:
    create_app(None, existing_broker=None)
except ValueError as exc:
    print(exc)
PY
```

## Writing an adapter

### `AC-21.b: this adapter must implement get_schema() (task-006)`

**`NotImplementedError`**, `nautilus/adapters/base.py:319`. The default `get_schema()` on the
adapter base. Implement it, or accept that
`GET /v1/adapters/{name}/schema` answers **501** for your source — see
[transport.md](transport.md).

### `adapter id {adapter_id!r} is not usable as a fingerprint filename`

**`ValueError`**, `nautilus/adapters/schema.py:325-328`. Schema fingerprints are cached one file
per adapter id, so the id must be filename-safe. Path separators and `..` are rejected. Rename
the source id.

Adapters must also satisfy the `Adapter` protocol at load time — see the `adapters[{i}]:` block
in [config.md](config.md) for what the loader checks and what it says when a class falls short.
