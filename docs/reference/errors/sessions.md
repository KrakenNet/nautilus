# Sessions, the exposure ledger and the session store

One session accumulates what an agent has already seen. Reading and writing that ledger is
serialised per caller, and it lives in the session store — so most failures here are either
"this session is not yours" or "the store did not answer".

## Ownership

### `session_not_yours: session {state.session_id!r} belongs to another principal. A session id is not a credential — either use your own, or have its owner declare a handoff to agent_id={agent_id!r} in it first.`

**`SessionNotOwnedError`** (`nautilus/core/__init__.py:32`), raised at
`nautilus/core/broker.py:2734-2739`. **HTTP 403** via
`nautilus/transport/fastapi_app.py:701-707`.

**Interpolates.** `{state.session_id!r}` — the session named in the request.
`{agent_id!r}` — the caller that tried to use it.

**Means.** The session id exists and is owned by a different principal. Naming someone else's
session would fold their accumulated exposure into your request; the id alone proves nothing.

**Happens when.** A session id is reused across agents; a client caches one id globally; or a
handoff was performed downstream without being declared to the broker.

**Fix.** Use a session id of your own — omitting `session_id` lets the broker pick one — or have
the current owner declare the transfer before the receiving agent asks —
`await broker.declare_handoff(source_agent_id=…, receiving_agent_id=…, session_id=…,
data_classifications=[…])` (`nautilus/core/broker.py:1950`, keyword-only and async).

## Contention

### `Broker busy: waited {budget}s to take the exposure ledger on {what!r} and did not get it. Either another request from this caller still holds it — requests from one caller are served one at a time so cumulative exposure is counted once — or the session store is slow or unreachable. This timeout does not tell the two apart: the session store is {endpoint}, so reach it from here to rule that one out. Retry, or raise session_store.lock_timeout_s.`

**`BrokerBusyError`** (`nautilus/core/__init__.py:46`), built by `_busy_message`
(`nautilus/core/broker.py:346-377`) and raised at `:2089` and `:2093`. **HTTP 503** with
`Retry-After: 1` (`nautilus/transport/fastapi_app.py:692-699`).

**Interpolates.** `{budget}` — `session_store.lock_timeout_s`. `{what!r}` — which ledger was
being taken (the session key or the principal key). `{endpoint}` — the session store as
`scheme://host[:port]`, rebuilt from `session_store.dsn` by `redact_connection`
(`nautilus/config/models.py:782-812`), so it never carries the DSN's password. With no dialable
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
(`nautilus/core/session_pg.py:72`, `:104`).

### `PostgresSessionStore unavailable (dsn={self._sanitized_dsn()}): {exc}`

`nautilus/core/session_pg.py:295-298`. The pool could not be created. `{exc}` is the asyncpg
failure; the DSN is printed with its password stripped. Check reachability, credentials and
`sslmode`.

### `PostgresSessionStore unavailable (dsn={…}: {exc}) and sqlite fallback at {self._sqlite_path} failed: {sqlite_exc}`

`nautilus/core/session_pg.py:306-310`. Postgres was unreachable *and* the configured
`session_store.sqlite_path` fallback could not be opened either — usually a read-only or missing
directory. Fix the directory, or fix Postgres.

### `PostgresSessionStore.aget() called before setup() succeeded`

`nautilus/core/session_pg.py:359-362`. Also `PostgresSessionStore.aupdate() called before
setup() succeeded` (`:373`) and `SqliteSessionStore({self._path}) used before setup()
succeeded` (`nautilus/core/session_sqlite.py:156-159`).

**Means.** The store object exists but `setup()` never completed, so there is no pool and no
schema. Under `nautilus serve` this means startup failed earlier — read the log above it. When
embedding Nautilus, it means the store was constructed and used without awaiting `setup()`.

### `session-store pool exhausted: no connection became free within {self._acquire_timeout_s}s (pool max_size={self._pool_max_size}). Raise session_store.pool_max_size to at least your peak concurrency.`

`nautilus/core/session_pg.py:462-467`.

### `session-store lock pool exhausted: no connection became free within {self._acquire_timeout_s}s (lock pool max_size={self._lock_pool_max_size}). One is held per in-flight request, so raise session_store.lock_pool_max_size to at least your peak concurrency.`

`nautilus/core/session_pg.py:536-541`. The second pool is separate because a connection is held
for the whole lifetime of a request holding the advisory lock. Size it to peak in-flight
requests, not to average load — the first pool being adequate says nothing about this one.

## Schema version mismatches

The store stamps a schema version; a build that does not understand it refuses rather than
read-modify-writing rows whose shape it is guessing at.

### `session database carries schema version {…}; this build understands version {_SCHEMA_VERSION}. Finish or roll back the rollout — do not run both builds against one store.`

`nautilus/core/session_pg.py:269-273`, at boot.

### `session store at {…} now carries schema version {…}; this build understands version {_SCHEMA_VERSION}. Another Nautilus migrated the store while this one was running.`

`nautilus/core/session_pg.py:397-401`. Re-checked by `/readyz`, so the running pod drains itself
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

`nautilus/config/models.py:594-598`, refused at startup.

### `session_store.backend=postgres requires 'dsn' or TEST_PG_DSN env var`

**`ConfigError`**, `nautilus/core/broker.py:1308-1312`. Set `session_store.dsn`, or export
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
