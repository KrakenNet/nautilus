# Sessions, the exposure ledger and the session store

One session accumulates what an agent has already seen. Reading and writing that ledger is
serialised per caller, and it lives in the session store — so most failures here are either
"this session is not yours" or "the store did not answer".

## Ownership

### `session_not_yours: session {state.session_id!r} belongs to another principal. A session id is not a credential — either use your own, or have its owner declare a handoff to agent_id={agent_id!r} in it first.`

**`SessionNotOwnedError`** (`nautilus/core/__init__.py:32`), raised at
`nautilus/core/broker.py:2357-2362`. **HTTP 403** via
`nautilus/transport/fastapi_app.py:632-638`.

**Interpolates.** `{state.session_id!r}` — the session named in the request.
`{agent_id!r}` — the caller that tried to use it.

**Means.** The session id exists and is owned by a different principal. Naming someone else's
session would fold their accumulated exposure into your request; the id alone proves nothing.

**Happens when.** A session id is reused across agents; a client caches one id globally; or a
handoff was performed downstream without being declared to the broker.

**Fix.** Use a session id of your own — omitting `session_id` lets the broker pick one — or have
the current owner declare the transfer before the receiving agent asks —
`await broker.declare_handoff(source_agent_id=…, receiving_agent_id=…, session_id=…,
data_classifications=[…])` (`nautilus/core/broker.py:1644`, keyword-only and async).

## Contention

### `Broker busy: waited {budget}s to take the exposure ledger on {what!r} and did not get it. Either another request from this caller still holds it — requests from one caller are served one at a time so cumulative exposure is counted once — or the session store is slow or unreachable. Check /readyz to tell the two apart. Retry, or raise session_store.lock_timeout_s.`

**`BrokerBusyError`** (`nautilus/core/__init__.py:46`), built by `_busy_message`
(`nautilus/core/broker.py:342-360`) and raised at `:2075` and `:2079`. **HTTP 503** with
`Retry-After: 1` (`nautilus/transport/fastapi_app.py:623-630`).

**Interpolates.** `{budget}` — `session_store.lock_timeout_s`. `{what!r}` — which ledger was
being taken (the session key or the principal key).

**Means.** The timeout expired while waiting for the exposure ledger. The wait covers two
different things and the message deliberately does not guess between them: the in-process lock
another of this caller's requests may hold, and the round trip to the session store that takes
the shared advisory lock.

**Diagnose.** Call `/readyz`. `{"status":"ok"}` points at real per-caller concurrency; a 503
points at the store.

**Fix.** Retry — this is backpressure, not failure. If it is chronic and `/readyz` is healthy,
stop issuing concurrent requests under one session, or raise `session_store.lock_timeout_s`. If
`/readyz` is unhealthy, treat it as a store outage (below).

## The Postgres session store

All of these are `SessionStoreUnavailableError` or `SessionSchemaError`
(`nautilus/core/session_pg.py:71`, `:104`).

### `PostgresSessionStore unavailable (dsn={self._sanitized_dsn()}): {exc}`

`nautilus/core/session_pg.py:260-263`. The pool could not be created. `{exc}` is the asyncpg
failure; the DSN is printed with its password stripped. Check reachability, credentials and
`sslmode`.

### `PostgresSessionStore unavailable (dsn={…}: {exc}) and sqlite fallback at {self._sqlite_path} failed: {sqlite_exc}`

`nautilus/core/session_pg.py:271-275`. Postgres was unreachable *and* the configured
`session_store.sqlite_path` fallback could not be opened either — usually a read-only or missing
directory. Fix the directory, or fix Postgres.

### `PostgresSessionStore.aget() called before setup() succeeded`

`nautilus/core/session_pg.py:311-314`. Also `PostgresSessionStore.aupdate() called before
setup() succeeded` (`:373`) and `SqliteSessionStore({self._path}) used before setup()
succeeded` (`nautilus/core/session_sqlite.py:156-159`).

**Means.** The store object exists but `setup()` never completed, so there is no pool and no
schema. Under `nautilus serve` this means startup failed earlier — read the log above it. When
embedding Nautilus, it means the store was constructed and used without awaiting `setup()`.

### `session-store pool exhausted: no connection became free within {self._acquire_timeout_s}s (pool max_size={self._pool_max_size}). Raise session_store.pool_max_size to at least your peak concurrency.`

`nautilus/core/session_pg.py:414-419`.

### `session-store lock pool exhausted: no connection became free within {self._acquire_timeout_s}s (lock pool max_size={self._lock_pool_max_size}). One is held per in-flight request, so raise session_store.lock_pool_max_size to at least your peak concurrency.`

`nautilus/core/session_pg.py:488-493`. The second pool is separate because a connection is held
for the whole lifetime of a request holding the advisory lock. Size it to peak in-flight
requests, not to average load — the first pool being adequate says nothing about this one.

## Schema version mismatches

The store stamps a schema version; a build that does not understand it refuses rather than
read-modify-writing rows whose shape it is guessing at.

### `session database carries schema version {…}; this build understands version {_SCHEMA_VERSION}. Finish or roll back the rollout — do not run both builds against one store.`

`nautilus/core/session_pg.py:234-238`, at boot.

### `session store at {…} now carries schema version {…}; this build understands version {_SCHEMA_VERSION}. Another Nautilus migrated the store while this one was running.`

`nautilus/core/session_pg.py:349-353`. Re-checked by `/readyz`, so the running pod drains itself
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

`nautilus/config/models.py:587-591`, refused at startup.

### `session_store.backend=postgres requires 'dsn' or TEST_PG_DSN env var`

**`ConfigError`**, `nautilus/core/broker.py:1021-1025`. Set `session_store.dsn`, or export
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
| `ERROR: pass exactly one of --sqlite-path or --dsn` | `:55` | Both or neither were given. Exit 2. |
| `ERROR: no such file: {path}` | `:74` | The sqlite file does not exist — check `session_store.sqlite_path`. |
| `ERROR: asyncpg is not installed` | `:88` | Install the extra: `pip install 'nautilus-rkm[postgres]'`. |
| `ERROR: could not connect: {exc}` | `:93` | `{exc}` is the asyncpg error; the DSN never reached a server. |
| `ERROR: could not read nautilus_schema_version: {exc}` | `:98` | Connected, but the stamp table is unreadable — wrong database, or a store this build never set up. |
| `ERROR: nautilus_schema_version holds no row` | `:103` | The table exists and is empty: `setup()` never finished against it. |
| `ERROR: unknown session subcommand {args.session_command!r}` | `:52` | Exit 2. |

```bash
nautilus session version 2>&1; echo "exit=$?"
```
