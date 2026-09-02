# Sessions, the exposure ledger and the session store

One session accumulates what an agent has already seen. Reading and writing that ledger is
serialised per caller, and it lives in the session store — so most failures here are either
"this session is not yours" or "the store did not answer".

## Ownership

### `session_not_yours: session {state.session_id!r} belongs to another principal. A session id is not a credential — either use your own, or have its owner declare a handoff to agent_id={agent_id!r} in it first.`

**`SessionNotOwnedError`** (`nautilus/core/__init__.py:32`), raised at
`nautilus/core/broker.py:2927-2932`. **HTTP 403** via
`nautilus/transport/fastapi_app.py:713-720`.

**Interpolates.** `{state.session_id!r}` — the session named in the request.
`{agent_id!r}` — the caller that tried to use it.

**Means.** The session id exists and is owned by a different principal. Naming someone else's
session would fold their accumulated exposure into your request; the id alone proves nothing.

**Happens when.** A session id is reused across agents; a client caches one id globally; or a
handoff was performed downstream without being declared to the broker.

**Fix.** Use a session id of your own — omitting `session_id` lets the broker pick one — or have
the current owner declare the transfer before the receiving agent asks —
`await broker.declare_handoff(source_agent_id=…, receiving_agent_id=…, session_id=…,
data_classifications=[…])` (`nautilus/core/broker.py:2141`, keyword-only and async).

## Contention

### `Broker busy: waited {budget}s to take the exposure ledger on {what!r} and did not get it. Either another request from this caller still holds it — requests from one caller are served one at a time so cumulative exposure is counted once — or the session store is slow or unreachable. This timeout does not tell the two apart: the session store is {endpoint}, so reach it from here to rule that one out. Retry, or raise session_store.lock_timeout_s.`

**`BrokerBusyError`** (`nautilus/core/__init__.py:46`), built by `_busy_message`
(`nautilus/core/broker.py:463-494`) and raised at `:2556` and `:2560`. **HTTP 503** with
`Retry-After: 1` (`nautilus/transport/fastapi_app.py:701-712`).

**Interpolates.** `{budget}` — `session_store.lock_timeout_s`. `{what!r}` — which ledger was
being taken (the session key or the principal key). `{endpoint}` — the session store as
`scheme://host[:port]`, rebuilt from `session_store.dsn` by `redact_connection`
(`nautilus/config/models.py:797-827`), so it never carries the DSN's password. With no dialable
store — `backend: memory`, `backend: sqlite`, or a libpq keyword DSN with no host in it — the
clause reads `this store publishes no address to dial — see session_store in nautilus.yaml`
instead.

**Means.** The timeout expired while waiting for the exposure ledger. The wait covers two
different things and the message deliberately does not guess between them: the in-process lock
another of this caller's requests may hold, and the round trip to the session store that takes
the shared advisory lock.

**Diagnose.** From the message, not from `/readyz`: when the store is the cause, `/readyz` is the
probe that has just failed too — it answers `{"status":"not_ready","reason":"session_store_timeout"}`,
a reason and not an address, and its first response after the store wedges takes about 12s. So
dial the `{endpoint}` the message names — `psql "$DSN" -c 'select 1'`, or `nc -z host port` from
the same pod. It answers ⇒ the wait was real per-caller concurrency. It does not ⇒ store outage.
The same address is on the request's audit entry, in `error_records[]` where `source_id` is
`<broker>`, so a 503 nobody was watching can still be traced afterwards.

**Fix.** Retry — this is backpressure, not failure. If the store answers when you dial it, stop
issuing concurrent requests under one session, or raise `session_store.lock_timeout_s`. If it
does not, treat it as a store outage (below).

## The Postgres session store

All of these are `SessionStoreUnavailableError` or `SessionSchemaError`
(`nautilus/core/session_pg.py:75`, `:108`) — except the first, which is a
`ConfigError` raised before the store object exists.

### `session_store.backend=postgres needs the 'postgres' extra, whose driver asyncpg is not installed -- {install_extra_hint('postgres')}. Or set session_store.backend to sqlite (durable, single-node) or memory, neither of which needs a driver.`

**`ConfigError`**, `nautilus/core/session_pg.py:173-179`, from
`PostgresSessionStore.__init__`. `asyncpg` is an optional extra, and the published container
image installs none of the driver extras
([the table](../../how-to/deploying.md#extras-and-what-the-published-image-carries)), so a
ConfigMap that asks for this backend on that image lands here. In full:

```
ERROR: invalid config: session_store.backend=postgres needs the 'postgres' extra, whose driver asyncpg is not installed -- host: pip install 'nautilus-rkm[postgres]'; image: docker build --build-arg EXTRAS="--extra postgres" . (the published image installs --extra otel only, and has no shell or pip to add to it). Or set session_store.backend to sqlite (durable, single-node) or memory, neither of which needs a driver.
```

**Where it fires.** At construction, inside `Broker.from_config`, so `nautilus serve` prints it
as `ERROR: invalid config: …` and exits **2** before binding a port. It is checked here rather
than at first use because the import that needs it is deferred into `setup()`, which runs inside
the ASGI lifespan hook: unguarded, the operator got `ModuleNotFoundError: No module named
'asyncpg'` under a Starlette traceback, naming neither the extra nor a remedy.

**Why `on_failure` does not apply.** That policy degrades a store that is *unreachable*. A
driver that is not installed never becomes reachable, so `fallback_memory` would run the
exposure ledger in process memory for the life of the pod — the exact silent per-replica ledger
`session_store.backend: postgres` was chosen to avoid. Same reasoning as `SessionSchemaError`
below.

**Fix.** Rebuild the image with `--build-arg EXTRAS="--extra postgres"`, install the extra on a
host install, or set `session_store.backend` to `sqlite` (durable, single node) or `memory`
(single process, lost on restart), neither of which needs a driver.

### `PostgresSessionStore unavailable (dsn={self._sanitized_dsn()}): {exc}`

`nautilus/core/session_pg.py:314-317`. The pool could not be created. `{exc}` is the asyncpg
failure. `{self._sanitized_dsn()}` is **not** the DSN: it is the `scheme://host[:port]` that
`redact_connection` (`nautilus/config/models.py:797-827`) copies out by allowlist, so the
message names the host and nothing else — no password, and equally no database name, no path
and no query parameters. A DSN with no host to copy — the libpq keyword form
`host=db password=pw` — prints `<no host in session_store.dsn>` instead.

**Fix.** The host in the message is the whole of what the store will tell you: dial it from
the broker's own network namespace. Everything the message dropped — which database, and
whether `sslmode` was set — has to be read from `session_store.dsn` in `nautilus.yaml`, not
inferred from this line.

### `PostgresSessionStore unavailable (dsn={…}: {exc}) and sqlite fallback at {self._sqlite_path} failed: {sqlite_exc}`

`nautilus/core/session_pg.py:325-329`. Postgres was unreachable *and* the configured
`session_store.sqlite_path` fallback could not be opened either — usually a read-only or missing
directory. Fix the directory, or fix Postgres.

### `PostgresSessionStore.aget() called before setup() succeeded`

`nautilus/core/session_pg.py:378-380`. Also `PostgresSessionStore.aupdate() called before
setup() succeeded` (`:439`) and `SqliteSessionStore({self._path}) used before setup()
succeeded` (`nautilus/core/session_sqlite.py:156-159`).

**Means.** The store object exists but `setup()` never completed, so there is no pool and no
schema. Under `nautilus serve` this means startup failed earlier — read the log above it. When
embedding Nautilus, it means the store was constructed and used without awaiting `setup()`.

### `session-store pool exhausted: no connection became free within {self._acquire_timeout_s}s (pool max_size={self._pool_max_size}). Raise session_store.pool_max_size to at least your peak concurrency.`

`nautilus/core/session_pg.py:479-484`.

### `session-store lock pool exhausted: no connection became free within {self._acquire_timeout_s}s (lock pool max_size={self._lock_pool_max_size}). One is held per in-flight request, so raise session_store.lock_pool_max_size to at least your peak concurrency.`

`nautilus/core/session_pg.py:553-558`. The second pool is separate because a connection is held
for the whole lifetime of a request holding the advisory lock. Size it to peak in-flight
requests, not to average load — the first pool being adequate says nothing about this one.

## Schema version mismatches

The store stamps a schema version; a build that does not understand it refuses rather than
read-modify-writing rows whose shape it is guessing at.

### `session database carries schema version {…}; this build understands version {_SCHEMA_VERSION}. Finish or roll back the rollout — do not run both builds against one store.`

`nautilus/core/session_pg.py:288-292`, at boot.

### `session store at {…} now carries schema version {…}; this build understands version {_SCHEMA_VERSION}. Another Nautilus migrated the store while this one was running.`

`nautilus/core/session_pg.py:414-418`. Re-checked by `/readyz`, so the running pod drains itself
mid-rollout instead of writing rows it does not understand.

### `session database {self._path} carries schema version {found}; this build understands version {_SCHEMA_VERSION}. It was written by a different Nautilus — point session_store.sqlite_path at a fresh file, or run the matching build.`

`nautilus/core/session_sqlite.py:115-119`.

### `session database {self._path} now carries schema version {found}; this build understands version {_SCHEMA_VERSION}. Another Nautilus migrated the store while this one was running.`

`nautilus/core/session_sqlite.py:145-149`.

**Fix, all four.** Finish the rollout or roll it back so a single build owns the store. For
sqlite, a fresh `session_store.sqlite_path` is a valid answer; for Postgres it discards the
exposure ledger, so prefer completing the rollout.

Read the stamp without starting a broker:

```bash
nautilus session version --sqlite-path /tmp/nautilus-errors/sessions.db; echo "exit=$?"
```

## Session-store configuration

### `session_store.backend: redis has no implementation. It used to load and serve sessions from memory instead, which gives replicas a per-process view of cumulative exposure and no signal that this is happening. Use postgres for a store shared across replicas, or sqlite for a durable single-node one.`

`nautilus/config/models.py:609-616`, refused at startup.

### `session_store.backend=postgres requires 'dsn' or TEST_PG_DSN env var`

**`ConfigError`**, `nautilus/core/broker.py:1534-1538`. Set `session_store.dsn`, or export
`TEST_PG_DSN`.

```bash
python - <<'PY'
import pathlib, tempfile
from nautilus.config.loader import ConfigError, load_config
p = pathlib.Path(tempfile.mkdtemp()) / "redis.yaml"
p.write_text("sources: []\nsession_store:\n  backend: redis\n")
try:
    load_config(str(p))
except ConfigError as exc:
    print(exc)
PY
```

## `nautilus session version`

Source: `nautilus/cli/session.py`. Argument mistakes exit **2**; a store that could not be
read exits **1**.

| Message | Line | Meaning |
| --- | --- | --- |
| `ERROR: pass exactly one of --sqlite-path or --dsn` | `:56` | Both or neither were given. Exit 2. |
| `ERROR: no such file: {path}` | `:75` | The sqlite file does not exist — check `session_store.sqlite_path`. |
| `ERROR: asyncpg is not installed -- {install_extra_hint('postgres')}` | `:90` | The remedy clause names both routes ([index.md](index.md#reading-a-quoted-message)); on the container image only the `docker build --build-arg EXTRAS="--extra postgres"` half is runnable. Or read a SQLite store with `--sqlite-path`, which needs no driver. |
| `ERROR: could not connect: {exc}` | `:97` | `{exc}` is the asyncpg error; the DSN never reached a server. |
| `ERROR: could not read nautilus_schema_version: {exc}` | `:102` | Connected, but the stamp table is unreadable — wrong database, or a store this build never set up. |
| `ERROR: nautilus_schema_version holds no row` | `:107` | The table exists and is empty: `setup()` never finished against it. |
| `ERROR: unknown session subcommand {args.session_command!r}` | `:53` | Exit 2. |

```bash
nautilus session version 2>&1; echo "exit=$?"
```
