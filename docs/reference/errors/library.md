# Embedding Nautilus as a library

Errors that only appear when you construct a `Broker`, an app, or an adapter yourself. Over
HTTP these are unreachable — the transport owns the lifecycle.

## Sync and async

### `Broker.request() called inside a running event loop. Use Broker.arequest() (async) from async contexts.`

**`RuntimeError`**, `nautilus/core/broker.py:1586-1590`.

**Means.** The synchronous facade was called from inside a coroutine. It would need to drive an
event loop that is already running.

**Fix.** `await broker.arequest(...)`. `Broker.request` is for synchronous callers only.

**Status.** No transport reaches this: `nautilus/transport/fastapi_app.py` and
`nautilus/transport/mcp_server.py` both await `arequest`. Uncaught in your own process it is a
`RuntimeError` traceback and exit **1**.

```bash
python - <<'PY'
import asyncio, pathlib, tempfile
from nautilus.core.broker import Broker
d = pathlib.Path(tempfile.mkdtemp())
cfg = d / "nautilus.yaml"
cfg.write_text(f'''
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
''')
async def main():
    broker = Broker.from_config(str(cfg))
    try:
        broker.request("analyst", "list notes")
    except RuntimeError as exc:
        print(f"RuntimeError: {exc}")
    await broker.aclose()
asyncio.run(main())
PY
```

```text
RuntimeError: Broker.request() called inside a running event loop. Use Broker.arequest() (async) from async contexts.
```

### `Broker.close() called inside a running event loop. Use Broker.aclose() (async) from async contexts.`

**`RuntimeError`**, `nautilus/core/broker.py:3532-3536`. Same rule for shutdown: `await
broker.aclose()`. No interpolation.

**Means.** `close()` drains the attestation sink and the session store synchronously; from inside a
coroutine it would have to drive the loop it is already running on.

**Status.** Library only, as above: uncaught it is a `RuntimeError` traceback and exit **1**. The
usual sighting is a `with Broker.from_config(...) as broker:` block inside an `async def` — the
context manager calls `close()` on the way out, so the failure lands on the closing brace, not on a
line you wrote.

**Fix.** `await broker.aclose()`, or use `async with`.

```bash
python - <<'PY'
import asyncio, pathlib, tempfile
from nautilus.core.broker import Broker
d = pathlib.Path(tempfile.mkdtemp())
cfg = d / "nautilus.yaml"
cfg.write_text(f'''
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
''')
async def main():
    broker = Broker.from_config(str(cfg))
    try:
        broker.close()
    except RuntimeError as exc:
        print(f"RuntimeError: {exc}")
    await broker.aclose()
asyncio.run(main())
PY
```

```text
RuntimeError: Broker.close() called inside a running event loop. Use Broker.aclose() (async) from async contexts.
```

### `Broker.{method}() called after close(); the attestation sink and session store are already shut down, so this request could not be receipted. Build a new Broker.`

**`RuntimeError`**, `nautilus/core/broker.py:2065-2070`. `{method}` is the method you called.

**Means.** The broker is closed. It is not reusable: the sink and the session store are gone, so
the request could not be receipted, and an unreceipted decision is not served.

**Status.** Library only — a served broker is closed by the transport's lifespan, after the last
request. Uncaught it is a `RuntimeError` traceback and exit **1**. `{method}` interpolates the
method you called: `request`, `arequest`, `declare_handoff`.

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

```text
Broker.arequest() called after close(); the attestation sink and session store are already shut down, so this request could not be receipted. Build a new Broker.
```

Note the method name in the rendered text: the synchronous `request()` delegates to `arequest()`,
and the guard fires inside the async one, so `{method}` reads `arequest` even when you called
`request`.

### `Broker.declare_handoff() failed for source={source_agent_id!r} receiving={receiving_agent_id!r}: {exc}`

**`PolicyEngineError`**, `nautilus/core/broker.py:1846-1850`. The handoff could not be recorded.
`{source_agent_id!r}` and `{receiving_agent_id!r}` are the two agent ids with `repr()`, so they
arrive quoted; `{exc}` is the exception the rules engine raised, with its own message.

**Means.** `declare_handoff` clears the shared engine, asserts one `data_handoff` fact per declared
classification, evaluates, and queries `denial_record` (`nautilus/core/broker.py:1844-1860`). Any
exception from those four calls is re-wrapped here. It is the engine failing, not the handoff being
denied — a *denied* handoff returns a `HandoffDecision` carrying `DenialRecord`s, and an unknown
agent id likewise returns a decision, not this error.

**Status.** No REST route reaches this. MCP does, when `mcp.expose_declare_handoff: true`
(`nautilus/transport/mcp_server.py:447-527`): the tool call fails and the client receives the
sentence as the tool error. In-process it is a `PolicyEngineError` and, uncaught, exit **1**.

**Fix.** Read `{exc}` — it is the engine's own message. The same wrapper guards `arequest`, so an
engine that fails here fails every request too; check the loaded ruleset before suspecting the
handoff call.

```bash
python - <<'PY'
import asyncio, pathlib, tempfile
from nautilus.core.broker import Broker
d = pathlib.Path(tempfile.mkdtemp())
cfg = d / "nautilus.yaml"
cfg.write_text(f'''
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
  reviewer:
    id: reviewer
    clearance: unclassified
    compartments: []
    default_purpose: research
audit:
  path: {d}/audit.jsonl
''')
async def main():
    broker = Broker.from_config(str(cfg))
    engine = broker._router.engine
    # Stand in for an engine that has failed -- a driver fault, an OOM, a
    # rule that raises. Everything else about the broker is real.
    engine.evaluate = lambda: (_ for _ in ()).throw(RuntimeError("engine environment is not loaded"))
    try:
        await broker.declare_handoff(
            source_agent_id="analyst",
            receiving_agent_id="reviewer",
            session_id="s1",
            data_classifications=["unclassified"],
        )
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}")
    await broker.aclose()
asyncio.run(main())
PY
```

```text
PolicyEngineError: Broker.declare_handoff() failed for source='analyst' receiving='reviewer': engine environment is not loaded
```

## Building transports

### `create_app requires either config_path or existing_broker`

**`ValueError`**, `nautilus/transport/fastapi_app.py:504-508`. No interpolation. Both
`config_path` (positional) and `existing_broker` were `None`.

**Means.** `create_app` builds the ASGI app around a broker. With neither argument there is nothing
to build one from, and an app with no broker would pass its probes and fail every request.

**Status.** Raised before the app object exists, so there is no HTTP status: it is a `ValueError`
at import or startup time. `nautilus serve` always passes a config path, so this is a library-only
failure; uncaught it is exit **1**.

**Fix.** Pass a config path, or a broker you already built.

### `create_server requires either config_path or existing_broker`

**`ValueError`**, `nautilus/transport/mcp_server.py:314-318`. No interpolation. The MCP
equivalent of the message above, same signature:
`create_server(config_path, *, existing_broker=None)`.

**Status.** No MCP session exists yet, so there is no tool error either — it is a `ValueError` from
the constructor, exit **1** uncaught.

**Fix.** Pass a config path, or an already-built broker. The repro below shows the FastAPI twin;
the MCP one is the same call shape.

```bash
python - <<'PY'
from nautilus.transport.fastapi_app import create_app
try:
    create_app(None, existing_broker=None)
except ValueError as exc:
    print(exc)
PY
```

```text
create_app requires either config_path or existing_broker
```

## Writing an adapter

### `AC-21.b: this adapter must implement get_schema() (task-006)`

**`NotImplementedError`**, `nautilus/adapters/base.py:378`. No interpolation. The default
`get_schema()` inherited from the `Adapter` protocol.

**Means.** Registration succeeds at import time and the gap only shows when something asks for the
schema, which is deliberate: an adapter is usable for queries before it can describe itself.

**Status.** `GET /v1/adapters/{name}/schema` answers **501** with
`{"detail": "Adapter '<name>' does not support schema introspection"}`
(`nautilus/transport/fastapi_app.py:1152-1157`) — a permanent refusal, not a retryable one, which
is why it is not the 503 the other schema failures get. Inside a request the drift gate treats a
raising `get_schema` as "cannot check" and the request still answers **200**.

**Fix.** Implement `get_schema()` on your adapter — see
[the adapter SDK reference](../adapter-sdk.md) — or accept the 501.

```bash
python - <<'PY'
import asyncio
from nautilus.adapters.base import Adapter
class MyAdapter(Adapter):
    source_type = "mine"
    async def connect(self, config): ...
    async def close(self): ...
    async def execute(self, intent, scope, context): ...
try:
    asyncio.run(MyAdapter().get_schema())
except NotImplementedError as exc:
    print(f"NotImplementedError: {exc}")
PY
```

```text
NotImplementedError: AC-21.b: this adapter must implement get_schema() (task-006)
```

### `adapter id {adapter_id!r} is not usable as a fingerprint filename`

**`ValueError`**, `nautilus/adapters/schema.py:325-328`, from
`SchemaFingerprintStore._path_for()`. `{adapter_id!r}` is the source id with `repr()`, so it
arrives quoted.

**Means.** Schema fingerprints are cached one file per adapter id under
`<root>/.nautilus/adapters/fingerprints/<id>.json`, so the id becomes a filename. A separator or a
`..` in it would write the baseline outside the store — the check is a path-traversal guard, not a
style rule. It only fires when the store is rooted on disk; an in-memory store returns `None` from
`_path_for` before reaching it.

**Status.** Raised in the request path, where the broker records or reads a baseline. Uncaught it
is a `ValueError`, exit **1** in your own process.

**Fix.** Rename the source id to something filename-safe.

```bash
python - <<'PY'
from nautilus.adapters.schema import SchemaFingerprintStore
try:
    SchemaFingerprintStore(root="/var/lib/nautilus")._path_for("../../etc/passwd")
except ValueError as exc:
    print(f"ValueError: {exc}")
PY
```

```text
ValueError: adapter id '../../etc/passwd' is not usable as a fingerprint filename
```

Adapters must also satisfy the `Adapter` protocol at load time — see the `adapters[{i}]:` block
in [config.md](config.md) for what the loader checks and what it says when a class falls short.
