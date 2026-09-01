# CLI Reference

Complete reference for the `nautilus` command line: **13 top-level commands, 41
parsers in total, 102 arguments** (17 positional, 85 optional). Everything here
is read out of the argparse tree in `nautilus/cli/`; every default is the
literal `default=` the parser carries.

## Invoking

The distribution is `nautilus-rkm`; the import package is `nautilus`. Installing
it puts one console script on `PATH` (`[project.scripts]` in `pyproject.toml`,
`nautilus = "nautilus.cli:main"`):

```bash
nautilus --help
```

Two module forms are equivalent and need no console script — `nautilus/cli/__main__.py`
exists so the MCP stdio server can re-exec itself:

```bash
python -m nautilus --help
python -m nautilus.cli --help
```

Every parser in the tree accepts `-h` / `--help`, which prints usage and exits
`0`. There are no other global options: `nautilus.cli._build_parser` adds
`add_subparsers(dest="command", required=True, metavar="command")` directly to
the root parser and nothing else.

```bash
python -m nautilus --help
```

```text
usage: nautilus [-h] command ...

Nautilus reasoning-engine CLI. Stand a broker up (init, serve, health,
version, demo), govern its rules (rules, rkm, rule, events), and manage what
it trusts (adapters, key, session, attestation).

positional arguments:
  command
    version      Print the installed nautilus package version.
    session      Inspect a session store (schema version).
    health       Probe a nautilus /readyz endpoint over HTTP (exit 0 on 200).
    serve        Run the nautilus transport(s): REST, MCP, or both.
    demo         Run a governed agent-to-agent handoff decision. No config or
                 database needed.
    init         Write a runnable nautilus.yaml in the current directory.
    rkm          Review-queue and lineage management.
    rule         Rule lifecycle management.
    adapters     Adapter registry and schema operations.
    key          Key management (AC-18.c / AC-18.e / #25).
    rules        Rule management subcommands.
    events       Event type enumeration (DQ5).
    attestation  Chained attestation log tools (offline verify).

options:
  -h, --help     show this help message and exit
```

## Exit codes

The contract is stated in `nautilus/cli/_common.py` and in `nautilus.cli.main`:

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | User error — a file that is not there, a missing `--yes`, a missing `NAUTILUS_REVIEWER`, a rule that fails static validation, a proposal or rule that does not exist. |
| `2` | Validation / policy failure — a config that will not load, a score below threshold, a chain that does not verify, a required `--url` that was omitted, a non-200 from the broker. Also argparse's own code for a bad flag or a missing required argument. |
| `3` | **Not used.** Reserved and deliberately never returned (OQ5 LOCKED). |

`nautilus rules test` is the one command where `2` is a routine, expected
outcome: it means "the rule scored below `--threshold`".

## Output prefixes

`nautilus/cli/_common.py` defines four helpers and nothing else writes decorated
lines. There are no Unicode sigils and no colour.

| Helper | Emits | Stream |
|--------|-------|--------|
| `ok(msg)` | `OK: <msg>` | stdout |
| `warn(msg)` | `WARN: <msg>` | stderr |
| `err(msg)` | `ERROR: <msg>` | stderr |
| `fail(msg)` | `FAIL: <msg>` | stderr |

`--json`, where a subcommand has it, sends the machine-readable payload to
stdout and leaves `WARN:`/`ERROR:` lines on stderr, so `cmd --json 2>/dev/null`
is always parseable.

Every line in the **failure modes** tables below is catalogued in the
[error reference](errors/cli.md), which quotes the emitting source line.

## Environment variables

| Variable | Read by | Effect |
|----------|---------|--------|
| `NAUTILUS_REVIEWER` | `nautilus.cli._common.require_reviewer` | Operator identity recorded on every governance decision. Required by `rkm queue submit`, `rkm queue approve`, `rkm queue reject`, `rule retract`, `rule rollback`, `adapters schema-ack`, `key rotate`, `key revoke`. There is no `$USER` fallback — auto-detection would let a reviewer identity be spoofed by the shell (DQ4 LOCKED). Unset or blank ⇒ `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.` and exit `1`. |

## Command index

| Command | Subcommand | What it does |
|---------|------------|--------------|
| [`version`](#nautilus-version) | — | Print the installed package version. |
| [`session`](#nautilus-session) | `version` | Print the schema version a session store carries. |
| [`health`](#nautilus-health) | — | Probe a `/readyz` endpoint over HTTP. |
| [`serve`](#nautilus-serve) | — | Run the REST and/or MCP transport. |
| [`demo`](#nautilus-demo) | — | Run a governed handoff decision with no config or database. |
| [`init`](#nautilus-init) | — | Write a runnable `nautilus.yaml`. |
| [`rkm`](#nautilus-rkm) | `queue list` | List proposals in the review queue. |
| | `queue submit` | Validate a rule file and queue the proposal. |
| | `queue show` | Show one proposal in full. |
| | `queue approve` | Approve and promote a proposal on a running broker. |
| | `queue reject` | Reject a pending proposal. |
| | `queue diff` | Diff a proposal against its peer rule. |
| | `lineage` | Show the lineage DAG for a proposal ID or rule name. |
| [`rule`](#nautilus-rule) | `list` | List rules. |
| | `retract` | Retire a rule. Destructive. |
| | `lineage` | Show the lineage DAG for a rule. |
| | `history` | Show version history for a rule. |
| | `rollback` | Restore a prior version. Destructive. |
| [`adapters`](#nautilus-adapters) | `new` | Scaffold an adapter package from the bundled template. |
| | `list` | List registered adapters. |
| | `schema` | Print an adapter's `AdapterSchema`. |
| | `schema-fingerprint` | Print an adapter's current fingerprint hash. |
| | `schema-diff` | Show drift against the stored fingerprint. |
| | `schema-ack` | Acknowledge drift and update the stored fingerprint. |
| [`key`](#nautilus-key) | `list` | List a live broker's active signing keys. |
| | `rotate` | Mint a new primary signing key. |
| | `revoke` | Revoke a signing key immediately. |
| [`rules`](#nautilus-rules) | `validate` | Statically validate a rule YAML file. |
| | `test` | Run the full validator pipeline and score it. |
| | `history` | List rule lineage history by module. |
| [`events`](#nautilus-events) | `list` | List every known `event_type` value. |
| [`attestation`](#nautilus-attestation) | `verify` | Offline-verify a chained attestation log. |

A group invoked with no subcommand prints a hint naming the valid ones. The
codes differ by group and are listed under each command below.

---

## `nautilus version`

Print the version recorded in the installed distribution's metadata. Takes no
arguments.

```bash
nautilus version
```

```text
0.2.2
```

| Exit | When |
|------|------|
| `0` | Version printed to stdout. |
| `1` | `nautilus (version unknown — package metadata missing)` on stderr — `importlib.metadata` could not find the `nautilus-rkm` distribution. You are running from a source tree that was never installed; `pip install -e .` fixes it. |

---

## `nautilus session`

Read the schema stamp a session store carries on disk (or in Postgres) and
compare it against the number this build understands. The broker refuses a store
stamped for a version it does not know and `/readyz` re-checks it while running;
this command is how you find out which number is actually there without reading
Nautilus's source. There is one schema version — this is a diagnostic, not a
migration tool.

### `nautilus session version`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--sqlite-path` | `str` | `None` | Path to a sqlite session database. Read via `PRAGMA user_version`. |
| `--dsn` | `str` | `None` | Postgres DSN of a session store. Read via `SELECT version FROM nautilus_schema_version`. Requires `asyncpg`. |

Exactly one of the two is required.

<!-- not-executed: needs an existing sqlite session store; create one with SqliteSessionStore(...).setup() -->
```bash
nautilus session version --sqlite-path ./sessions.db
```

```text
store schema version: 1
this build understands: 1
```

| Exit | When |
|------|------|
| `0` | The store's version equals `nautilus.core.session_pg._SCHEMA_VERSION`. |
| `1` | The store could not be read, or it was read and the versions differ. |
| `2` | Neither or both of `--sqlite-path` / `--dsn` were given. |

**Failure modes**

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: pass exactly one of --sqlite-path or --dsn` | `2` | Pass one target, not zero and not both. |
| `ERROR: no such file: <path>` | `1` | The sqlite path does not exist. Check `session.sqlite_path` in your config. |
| `ERROR: asyncpg is not installed` | `1` | `pip install asyncpg`, or use `--sqlite-path`. |
| `ERROR: could not connect: <err>` | `1` | The DSN is wrong or the server is unreachable. |
| `ERROR: could not read nautilus_schema_version: <err>` | `1` | The table is missing — this DSN points at a database that is not a Nautilus session store, or one the broker has never initialised. |
| `ERROR: nautilus_schema_version holds no row` | `1` | The table exists but is empty. Let a broker start against it once, or point at a fresh store. |
| `They do not match, so this build refuses the store. Run the build that wrote it, or point the config at a fresh store.` | `1` | Printed after both numbers. A rollout is half-finished: finish it or roll it back. |

---

## `nautilus health`

Issue a single `GET` against a readiness URL with a 5-second timeout
(`nautilus.cli.health._HEALTH_TIMEOUT_S`). This is the liveness probe the
container images use.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--url` | `str` | `http://localhost:8000/readyz` | Readiness URL to probe. |

<!-- not-executed: needs a broker listening on 127.0.0.1:8000 -->
```bash
nautilus health --url http://127.0.0.1:8000/readyz
```

```text
OK 200 http://127.0.0.1:8000/readyz
```

| Exit | When |
|------|------|
| `0` | HTTP 200. |
| `1` | Any other status, an HTTP error, a timeout, or a socket error. |

**Failure modes**

| Message | Exit | What to do |
|---------|------|------------|
| `FAIL <status> <url>` | `1` | The endpoint answered but not with 200. A 503 from `/readyz` means the broker is up and not ready — check its logs for the config or session-store problem it is reporting. |
| `FAIL unreachable <url>: <urlopen error [Errno 111] Connection refused>` | `1` | Nothing is listening. Confirm the port from `nautilus serve --bind`, or from `api.host` / `api.port` in the config. |
| `FAIL unreachable <url>: timed out` | `1` | The process is listening but did not answer within 5 s. |

---

## `nautilus serve`

Load a config, construct a `Broker`, and run the transports. `--bind` wins over
`api.host` / `api.port` in the config; when neither is set the bind is
`127.0.0.1:8000` (`nautilus.cli.serve._DEFAULT_BIND`).

| Flag | Type | Default | Choices | Description |
|------|------|---------|---------|-------------|
| `--config` | `str` | `nautilus.yaml` | — | Path to the config file. Relative to the working directory. |
| `--transport` | `str` | `rest` | `rest`, `mcp`, `both` | Transport surface to expose. |
| `--mcp-mode` | `str` | `stdio` | `stdio`, `http` | MCP transport mode. Only consulted when `--transport` is `mcp` or `both`. |
| `--bind` | `str` | `None` | — | `HOST:PORT` for the REST (and MCP-over-http) listener. Overrides `api.host` / `api.port`. |
| `--air-gapped` | flag (`store_true`) | `False` | — | Force `analysis.mode='pattern'`, drop any `type: llm` source whose `connection` host is not loopback, and refuse an `analysis.provider` (NFR-1, #43). A `WARN:` line names each field it overrode. |
| `--log-format` | `str` | `text` | `text`, `json` | Application log format. `json` emits SIEM-ingestable structured lines on stdout. |

<!-- not-executed: starts a long-running server; run it in a directory with no nautilus.yaml -->
```bash
nautilus init && nautilus serve --config nautilus.yaml --bind 127.0.0.1:8000
```

Signal handling is uvicorn's: `Ctrl-C` raises `KeyboardInterrupt`, which
`_cmd_serve` swallows, closes the broker, and returns `0`.

| Exit | When |
|------|------|
| `0` | The server ran and shut down cleanly (including after `Ctrl-C`). |
| `2` | Anything that stops it before or during the bind: config missing, config invalid, malformed `--bind`, air-gap violation, broker construction failure, or a lifespan that failed to start. |

**Failure modes**

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: config path does not exist or is not a file: <path>` | `2` | The `--config` path is wrong. `nautilus init` writes a working one. |
| `ERROR: --bind must be HOST:PORT, got '<value>'` | `2` | You passed a bare host or a bare port. Use `127.0.0.1:8000`. |
| `ERROR: --bind port must be an integer, got '<value>'` | `2` | The part after the last `:` is not a number. |
| `ERROR: invalid config: <detail>` | `2` | The YAML parsed but failed model validation. The detail names the offending key; the config models reject unknown keys, so a typo shows up here as an extra-field error. |
| `ERROR: broker construction failed: <detail>` | `2` | Wiring failed after validation — most often a source whose driver is not installed. The message names the extra to install. |
| `WARN: --air-gapped overrides analysis.mode from '<mode>' to 'pattern' (NFR-1)` | — | Informational. Remove `analysis.mode` from the config, or drop `--air-gapped`. |
| `WARN: --air-gapped refuses analysis.provider (type='<type>'); dropping it (NFR-1)` | — | Informational. An air-gapped run has no LLM provider. |
| `WARN: --air-gapped drops LLM source id='<id>' — connection host is not loopback (NFR-1, #43)` | — | Informational. An LLM source is only air-gap compatible when the inference server is local. |
| `nautilus serve: error: argument --transport: invalid choice: '<value>' (choose from rest, mcp, both)` | `2` | argparse rejected the value before anything ran. |

---

## `nautilus demo`

Run two agent-to-agent handoff declarations and print what the broker decided
about each, then print the first real audit entry. Takes no arguments. It needs
no config, no adapter, no database and no network: a handoff declaration is a
reasoning-only path, so the whole run is in-process against three built-in
clearances (`chief`/secret, `analyst`/confidential, `intern`/unclassified) and
the built-in rule pack. The audit log is written to a temporary directory that
is deleted on the way out.

```bash
nautilus demo
```

```text
nautilus demo — one agent hands data to another, and the broker decides.

  analyst (confidential) hands confidential data to chief (secret)
    handoff ALLOWED

  chief (secret) hands secret data to intern (unclassified)
    handoff DENIED
    reason: receiving agent clearance does not dominate declared classification
    rule:   information-flow-violation

Both decisions were signed and appended to an audit log (2 entries).
Here is the first one:

{
  "timestamp": "2026-09-01T00:47:58.982614Z",
  "request_id": "04d9ca48-a5cb-4cbc-87f3-d21221be0ff4",
  "agent_id": "analyst",
  "session_id": "demo",
  "event_type": "handoff_declared",
  "handoff_decision": {
    "handoff_id": "04d9ca48-a5cb-4cbc-87f3-d21221be0ff4",
    "action": "allow",
    "denial_records": [],
    "rule_trace": []
  }
}

Every request the broker answers is recorded the same way.

Next: 'nautilus init' writes a nautilus.yaml you can serve, and
      'nautilus serve' runs it as a REST or MCP endpoint.
```

(The printed entry is the full `AuditEntry`; the null-valued fields are elided
above.)

| Exit | When |
|------|------|
| `0` | Always. The demo has no failure path of its own — the denial it prints is the expected result, not an error. |

---

## `nautilus init`

Write a `nautilus.yaml` that loads and answers. The config it writes declares its
rows inline (source `type: static`), so it runs with no database, no driver and
no adapter code. A fresh 32-hex-character API key is generated per invocation
with `secrets.token_hex(16)` — a constant here would ship one shared secret to
every user.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--dir` | `str` | `.` | Directory to write `nautilus.yaml` into. Parent directories are created. |

```bash
nautilus init --dir .
```

```text
OK: wrote nautilus.yaml
  next steps :
    nautilus serve --config nautilus.yaml   # REST on 127.0.0.1:8000
    nautilus demo                       # a governed handoff decision

  the generated api key is in nautilus.yaml:
    curl -H 'X-API-Key: 607a67633631dd1bc482a6639e8cf6a3' http://127.0.0.1:8000/v1/sources
```

| Exit | When |
|------|------|
| `0` | File written. |
| `1` | A `nautilus.yaml` already exists at the target. |

**Failure modes**

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: <path>/nautilus.yaml already exists — refusing to overwrite it` | `1` | Move or delete the existing file, or write elsewhere with `--dir`. The command never overwrites: the file holds a generated API key. |

---

## `nautilus rkm`

Review-queue and lineage management. See
[RKM: the Rule Lifecycle](../concepts/rkm-lifecycle.md).

`nautilus rkm` with no subcommand prints
`ERROR: rkm: no subcommand given (try: queue, lineage)` and exits `2`.
`nautilus rkm queue` with no operation prints
`ERROR: rkm queue: no op given (try: submit, list, show, approve, reject, diff)`
and exits `2`.

`approve` and `reject` are decisions, so each appends its record to the audit
log (`proposal_approved`, `proposal_rejected`, plus `rule_promoted` and
`proposal_promoted` when an approval promotes). `--config nautilus.yaml` sends
that record to the file's `audit.path`, resolved relative to the config's own
directory; without `--config` the default `./audit.jsonl` is used.

### `nautilus rkm queue list`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--status` | `str` | `None` | Filter by status (`pending`, `approved`, …). |
| `--min-confidence` | `float` | `0.0` | Minimum confidence score, 0.0–1.0. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

```bash
nautilus rkm queue list
```

```text
  prop_f544922c8c534eaab0ff456b53a9dd6e  status=pending  confidence=0.9
```

An empty queue prints `OK: no proposals`. Exit `0` either way.

### `nautilus rkm queue submit`

Runs the full validator pipeline over a rule file and queues the resulting
proposal. Requires `NAUTILUS_REVIEWER`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--file` | `str` | — | **Required.** Path to the rule YAML to propose. |
| `--config` | `str` | `None` | `nautilus.yaml` naming the audit log the sandbox stage replays. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

<!-- not-executed: needs a rule YAML at ./my-rules.yaml -->
```bash
NAUTILUS_REVIEWER=alice nautilus rkm queue submit --file my-rules.yaml
```

```text
OK: proposal prop_f544922c8c534eaab0ff456b53a9dd6e queued pending (confidence 0.90)
```

| Exit | When |
|------|------|
| `0` | Queued with status `pending`. |
| `1` | The rule file was not found, or the proposal was queued with status `rejected` — static validation failed, and each error is printed as a `WARN:` line. |

`WARN: could not read rkm settings from '<path>' (<err>); using defaults` means
`--config` could not be parsed; the submission still ran, on default sandbox
settings.

### `nautilus rkm queue show`

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `proposal_id` | `str` (positional) | — | **Required.** Proposal ID, `prop_<hex>`. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

<!-- not-executed: substitute a real proposal id from `nautilus rkm queue list` -->
```bash
nautilus rkm queue show prop_f544922c8c534eaab0ff456b53a9dd6e
```

```text
  proposal_id: prop_f544922c8c534eaab0ff456b53a9dd6e
  schema_version: 2
  status: pending
  proposer: pipeline
  proposed_at: 2026-09-01T00:48:39.973201+00:00
  target_module: curator
  artifact_type: rule
  artifact: {'yaml_path': 'my-rules.yaml', 'name': 'deny-confidential-to-support', 'module': 'nautilus-routing'}
  validation: {'static_ok': True, 'static_errors': [], 'sandbox': {...}, 'confidence': 0.9, ...}
  lineage: {'derived_from': None}
  decisions: []
  shadow_flags: []
```

Exit `0` on success, `1` with `ERROR: proposal <id> not found`.

### `nautilus rkm queue approve`

Approval is not bookkeeping: it promotes the rule into the CLIPS environment of
a **running** broker. `--url` is therefore effectively required — without it the
command refuses rather than marking a proposal promoted while loading the rule
nowhere. Requires `NAUTILUS_REVIEWER`, which is sent as `X-Nautilus-Reviewer`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `proposal_id` | `str` (positional) | — | **Required.** Proposal ID. |
| `--note` | `str` | `None` | Optional reviewer note. |
| `--url` | `str` | `None` | Base URL of the running broker, e.g. `http://localhost:8000`. Refuses to run without it. |
| `--api-key` | `str` | `None` | `X-API-Key` for the broker. |
| `--config` | `str` | `None` | `nautilus.yaml` whose `audit.path` receives the decision record (default `./audit.jsonl`). |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

<!-- not-executed: needs a running broker and a real proposal id -->
```bash
NAUTILUS_REVIEWER=alice nautilus rkm queue approve prop_f544922c8c534eaab0ff456b53a9dd6e \
  --url http://127.0.0.1:8000 --api-key "$NAUTILUS_API_KEY"
```

| Exit | When |
|------|------|
| `0` | Approved, or already approved (idempotent: JSON mode prints `{"status": "already_approved", ...}`). |
| `1` | `NAUTILUS_REVIEWER` unset, or the proposal does not exist on that broker. |
| `2` | `--url` omitted, the broker was unreachable, or it answered with a non-200 that was not 404. |

**Failure modes**

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: rkm queue approve: --url is required. Approving promotes the rule into the engine of a running broker, so there is nothing for the CLI to approve locally — point --url at the broker (e.g. --url http://localhost:8000).` | `2` | Start the broker and point at it. |
| `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.` | `1` | `export NAUTILUS_REVIEWER=<you>`. |
| `ERROR: rkm queue approve: cannot reach <endpoint>: <err>` | `2` | Wrong host/port, or the broker is down. `nautilus health` confirms. |
| `ERROR: proposal <id> not found` | `1` | The ID is not in that broker's queue. `nautilus rkm queue list` shows what is. |
| `ERROR: rkm queue approve: server returned <status>: <body>` | `2` | A 401 means the `--api-key` is wrong or missing; a 403 means that key is bound to a different agent. |

### `nautilus rkm queue reject`

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `proposal_id` | `str` (positional) | — | **Required.** Proposal ID. |
| `--reason` | `str` | — | **Required.** Rejection reason. |
| `--config` | `str` | `None` | `nautilus.yaml` whose `audit.path` receives the decision record (default `./audit.jsonl`). |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

<!-- not-executed: substitute a real pending proposal id -->
```bash
NAUTILUS_REVIEWER=alice nautilus rkm queue reject prop_f544922c8c534eaab0ff456b53a9dd6e \
  --reason "too broad"
```

```text
OK: proposal prop_f544922c8c534eaab0ff456b53a9dd6e rejected by alice: too broad
```

| Exit | When |
|------|------|
| `0` | Rejected. |
| `1` | `NAUTILUS_REVIEWER` unset, the proposal does not exist, or it was already decided. |

`ERROR: proposal <id> already decided: status=<status>` means someone got there
first — a rejection is not repeatable.

### `nautilus rkm queue diff`

Show the schema diff between a proposal and its peer rule. The peer is found by
the DQ6 heuristic: `lineage.derived_from` first, then the longest common prefix
of rule names, then `no peer`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `proposal_id` | `str` (positional) | — | **Required.** Proposal ID. |

<!-- not-executed: substitute a real proposal id -->
```bash
nautilus rkm queue diff prop_f544922c8c534eaab0ff456b53a9dd6e
```

```text
  proposal : prop_f544922c8c534eaab0ff456b53a9dd6e
  peer     : no peer
  artifact : {
  "yaml_path": "my-rules.yaml",
  "name": "deny-confidential-to-support",
  "module": "nautilus-routing"
}
```

Exit `0` on success, `1` with `ERROR: proposal <id> not found`.

### `nautilus rkm lineage`

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `str` (positional) | — | **Required.** Proposal ID **or** rule name. |
| `--depth` | `int` | `5` | Maximum ancestor depth to traverse. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

```bash
nautilus rkm lineage nonexistent
```

```text
WARN: no lineage records for 'nonexistent'
```

Exit `0` in both cases — an empty lineage is an answer, not an error. With
`--json` the empty case prints `[]`.

---

## `nautilus rule`

Rule lifecycle management, reading the lineage store under
`.nautilus/rkm/lineage`. `nautilus rule` with no subcommand prints
`ERROR: rule: no subcommand given (try: list, retract, lineage, history, rollback)`
and exits `2`.

### `nautilus rule list`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--status` | `str` | `None` | Filter by status. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

```bash
nautilus rule list
```

Prints one `  <name> v<version> [<status>]` line per rule; nothing at all when
the lineage store is empty. Exit `0`.

### `nautilus rule retract`

Retire a rule. **Destructive** — appends `rule_retracted` to the audit log.
Requires `NAUTILUS_REVIEWER`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Rule name. |
| `--reason` | `str` | — | **Required.** Retraction reason. |
| `--yes` | flag (`store_true`) | `False` | Confirm the destructive operation. Required. |
| `--cascade` | flag (`store_true`) | `False` | Retire all transitive descendants too (AC-35.10.d). |
| `--orphan-children` | flag (`store_true`) | `False` | Flag direct descendants as orphaned without retiring them (AC-35.10.d). Mutually exclusive with `--cascade`. |
| `--config` | `str` | `None` | `nautilus.yaml` whose `audit.path` receives the decision record (default `./audit.jsonl`). |

<!-- not-executed: substitute a rule name present in .nautilus/rkm/lineage -->
```bash
NAUTILUS_REVIEWER=alice nautilus rule retract deny-confidential-to-support \
  --reason "superseded by pack rule" --yes
```

```text
OK: rule 'deny-confidential-to-support' v3 retracted by alice
```

| Exit | When |
|------|------|
| `0` | Retracted. Affected descendants, if any, follow on a `WARN: affected descendants: ...` line. |
| `1` | `--yes` missing, `--reason` missing, both cascade flags given, `NAUTILUS_REVIEWER` unset, or the rule is not in the lineage store. |

**Failure modes**

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: --yes required for destructive op` | `1` | Add `--yes`. |
| `ERROR: --reason required for retract` | `1` | Add `--reason "..."` — the reason lands in the audit record. |
| `ERROR: --cascade and --orphan-children are mutually exclusive` | `1` | Pick one: retire the descendants, or mark them orphaned. |
| `ERROR: rule '<name>' not found in lineage` | `1` | `nautilus rule list` shows the names that exist. |

### `nautilus rule lineage`

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Rule name. |
| `--depth` | `int` | `5` | Maximum ancestor depth to traverse. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

<!-- not-executed: substitute a rule name present in .nautilus/rkm/lineage -->
```bash
nautilus rule lineage deny-confidential-to-support --depth 5
```

Exit `0`. An unknown name prints `WARN: no lineage records for '<name>'` and
still exits `0`; with `--json` it prints `{"proposer": null, "versions": []}`.

### `nautilus rule history`

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Rule name. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

```bash
nautilus rule history deny-confidential-to-support
```

```text
WARN: no history for 'deny-confidential-to-support'
```

Prints one `  v<n>  promoted=<iso8601>` line per version (with ` retired`
appended where applicable). Exit `0`, including for the empty case; `--json`
prints `[]`.

### `nautilus rule rollback`

Restore a prior version. **Destructive** — appends `rule_rolled_back` to the
audit log. Requires `NAUTILUS_REVIEWER`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Rule name. |
| `--to-version` | `int` | — | **Required.** Target version number to restore. |
| `--reason` | `str` | — | **Required.** Rollback reason. |
| `--yes` | flag (`store_true`) | `False` | Confirm the destructive operation. Required. |
| `--config` | `str` | `None` | `nautilus.yaml` whose `audit.path` receives the decision record (default `./audit.jsonl`). |

<!-- not-executed: substitute a rule name and a version that exist in the lineage store -->
```bash
NAUTILUS_REVIEWER=alice nautilus rule rollback deny-confidential-to-support \
  --to-version 2 --reason "v3 over-denied support queries" --yes
```

| Exit | When |
|------|------|
| `0` | Rolled back. |
| `1` | `--yes` missing, `NAUTILUS_REVIEWER` unset, or `ERROR: rule '<name>' v<n> not found in lineage` — use `nautilus rule history <name>` to see which versions exist. |

---

## `nautilus adapters`

Adapter registry, scaffolding, and schema-drift operations — see
[Developing Adapters](../how-to/developing-adapters.md).

`nautilus adapters` with no subcommand prints
`ERROR: adapters: no subcommand given (try: new, list, schema, schema-fingerprint, schema-diff, schema-ack)`
and exits `2`.

Where `--config` is optional it defaults to `./nautilus.yaml` when that file is
present; when it is not, the command reports
`ERROR: no config found: pass --config PATH, or run from a directory containing nautilus.yaml`
and exits `1`.

### `nautilus adapters new`

Scaffold an adapter package from the bundled copier template.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Distribution name, lowercase-dashed, e.g. `my-csv-adapter`. |
| `--dir` | `str` | `.` | Parent directory to create the package in. |

```bash
nautilus adapters new my-csv-adapter --dir .
```

```text
OK: scaffolded adapter package at my-csv-adapter
  source type : my-csv
  class       : my_csv_adapter.MyCsvAdapter
  next steps  :
    cd my-csv-adapter
    pip install -e ".[test]" && pytest -v
    nautilus adapters list   # confirm discovery once installed
```

| Exit | When |
|------|------|
| `0` | Package written. |
| `1` | Invalid name, non-empty destination, or `copier` not installed. |

**Failure modes**

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: invalid adapter name '<name>' (expected lowercase-dashed, e.g. my-csv-adapter)` | `1` | Underscores and capitals are rejected; the name becomes both a distribution name and a source type. |
| `ERROR: destination already exists and is not empty: <dest>` | `1` | Choose another name or `--dir`. |
| `ERROR: copier is required for 'adapters new' — install it with: pip install copier` | `1` | Run that command. |

### `nautilus adapters list`

Two modes. With `--url` it asks a running server, which knows about quarantine.
Without it, it reads a config file, which does not — a config file can only
report `configured`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--status` | `str` | `None` | Filter by status (`active`, `quarantined`). **Requires `--url`.** |
| `--config` | `str` | `None` | Path to `nautilus.yaml` (default `./nautilus.yaml` when present). |
| `--url` | `str` | `None` | Base URL of a running server. |
| `--api-key` | `str` | `None` | `X-API-Key` for `--url` mode. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

<!-- not-executed: needs the nautilus.yaml written by `nautilus init` in the working directory -->
```bash
nautilus adapters list --config nautilus.yaml
```

```text
  orders  type=static  status=configured
```

<!-- not-executed: needs a broker listening on 127.0.0.1:8000 -->
```bash
nautilus adapters list --url http://127.0.0.1:8000 --api-key "$NAUTILUS_API_KEY" --json
```

```text
[{"id": "orders", "type": "static", "status": "active"}]
```

| Exit | When |
|------|------|
| `0` | Listed. An empty registry prints `OK: no adapters registered`. |
| `1` | `--status` without `--url`, no config found, the config could not be loaded, or the server could not be reached. |

**Failure modes**

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: --status '<value>' needs --url: quarantine state lives in the serving process, so a config file cannot answer it. Reporting an empty list here would look like 'nothing is quarantined'.` | `1` | Add `--url`. |
| `ERROR: no config found: pass --config PATH, or run from a directory containing nautilus.yaml` | `1` | Pass `--config`, or `cd` to the config's directory. |
| `ERROR: could not load <path>: <err>` | `1` | The config is present but will not parse. |
| `ERROR: could not reach <url>: <err>` | `1` | The server is down or the URL is wrong. |

### `nautilus adapters schema`

Print the adapter's live `AdapterSchema` — tables, fields, capability flags and
the fetch timestamp.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Adapter name/id. |
| `--config` | `str` | `None` | Path to `nautilus.yaml` (default `./nautilus.yaml` when present). |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

<!-- not-executed: needs the nautilus.yaml written by `nautilus init`, whose sample source is `orders` -->
```bash
nautilus adapters schema orders --config nautilus.yaml
```

```text
  adapter_id: orders
  source_type: static
  tables: ({'name': 'orders', 'fields': ({'name': 'order_id', 'type': 'yaml', 'nullable': True, 'description': ''}, ...), 'indexes': (), 'primary_key': ()},)
  capability_flags: {}
  fetched_at: 2026-09-01T00:47:59.636841+00:00
```

Exit `0` on success; `1` with `ERROR: no schema available for adapter '<name>'`
when the id is not in the config's `sources` (JSON mode prints `null` first).

### `nautilus adapters schema-fingerprint`

Print the `sha256:`-prefixed digest of the adapter's current schema. This is the
value `schema-diff` compares against and `schema-ack` stores.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Adapter name/id. |
| `--config` | `str` | `None` | Path to `nautilus.yaml` (default `./nautilus.yaml` when present). |

<!-- not-executed: needs the nautilus.yaml written by `nautilus init`, whose sample source is `orders` -->
```bash
nautilus adapters schema-fingerprint orders --config nautilus.yaml
```

```text
sha256:c48627e080df819eaad265fab62fe513958afa03da7c7ee1465dbe74ea8ef49c
```

Exit `0`; `1` with `ERROR: no schema available for adapter '<name>'`.

### `nautilus adapters schema-diff`

Compare the live schema against the stored baseline.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Adapter name/id. |
| `--config` | `str` | — | **Required.** Path to `nautilus.yaml`. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

<!-- not-executed: needs the nautilus.yaml written by `nautilus init`, whose sample source is `orders` -->
```bash
nautilus adapters schema-diff orders --config nautilus.yaml
```

```text
WARN: no stored fingerprint for 'orders'; treating as new
  no baseline fingerprint for 'orders'
  current: sha256:c48627e080df819eaad265fab62fe513958afa03da7c7ee1465dbe74ea8ef49c
```

Exit is `0` in every case — including when drift is found, which prints
`  DRIFT DETECTED` after the stored and current digests. Branch on the `status`
field in `--json` mode (`no_baseline`, `clean`, or the drift payload) rather
than on the exit code. `WARN: no schema available for adapter '<name>'` also
exits `0`.

### `nautilus adapters schema-ack`

Acknowledge drift and update the stored fingerprint (AC-21.g). Emits
`schema_drift_severity_overridden` to the audit log. Requires
`NAUTILUS_REVIEWER`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Adapter name/id. |
| `--config` | `str` | — | **Required.** Path to `nautilus.yaml`. |
| `--reason` | `str` | — | **Required.** Reason for the acknowledgement. |
| `--yes` | flag (`store_true`) | `False` | Confirm the acknowledgement. Required. |

<!-- not-executed: needs the nautilus.yaml written by `nautilus init`, whose sample source is `orders` -->
```bash
NAUTILUS_REVIEWER=alice nautilus adapters schema-ack orders \
  --config nautilus.yaml --reason "upstream added a nullable column" --yes
```

```text
OK: schema-ack recorded for 'orders' by alice: upstream added a nullable column
```

| Exit | When |
|------|------|
| `0` | Recorded. |
| `1` | `ERROR: schema-ack requires --yes to confirm`, `NAUTILUS_REVIEWER` unset, or `ERROR: no schema available for adapter '<name>'; cannot ack`. |

---

## `nautilus key`

Session-token signing-key management — see
[key rotation in the operator guide](../how-to/operator-guide.md#6-rotate-signing-keys).

`--url` is effectively required on all three subcommands. The signing ring is
in-broker state: a broker holds it in memory whether or not
`session_tokens.key_ring_path` also persists it, so acting on the file would
leave the running broker signing with a key it no longer has and emit no audit
event. With `--url` the commands drive `GET /v1/keys/jwks.json`,
`POST /v1/keys/rotate` and `POST /v1/keys/{kid}/revoke`, and the server emits
`signing_key_rotated` / `signing_key_revoked`.

`nautilus key` with no subcommand prints
`ERROR: key: subcommand required (list, rotate, revoke).` and exits `1`.

All three share `--url`, `--api-key` and `--json`:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--url` | `str` | `None` | Base URL of the running broker whose signing ring to act on. Trailing slashes are stripped. |
| `--api-key` | `str` | `None` | `X-API-Key` for the broker. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

### `nautilus key list`

No additional arguments. Reads the public JWKS, so it needs no reviewer identity.

<!-- not-executed: needs a broker listening on 127.0.0.1:8000 -->
```bash
nautilus key list --url http://127.0.0.1:8000 --api-key "$NAUTILUS_API_KEY"
```

```text
  bb9b550c-48a6-4443-8381-c0e0bf2c3b5f  kty=OKP  use=sig
```

With `--json`, the raw JWKS `keys` array:

```text
[{"kty": "OKP", "crv": "Ed25519", "kid": "bb9b550c-48a6-4443-8381-c0e0bf2c3b5f", "x": "aMl3bY3v-5hKS6AMUHHXS1gcUeH-GjCoFCb09R5nthc", "use": "sig"}]
```

A broker with session tokens disabled prints
`no active keys (session tokens are disabled on this broker)` and exits `0`.

### `nautilus key rotate`

Mint a new primary key. In-flight session tokens keep verifying during the grace
window; agents are lazily re-signed on their next request (#25). Requires
`NAUTILUS_REVIEWER`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--yes` | flag (`store_true`) | `False` | Confirm the destructive operation. Required. |

Plus the shared `--url` / `--api-key` / `--json`.

<!-- not-executed: needs a broker with session_tokens.enabled: true -->
```bash
NAUTILUS_REVIEWER=alice nautilus key rotate --yes \
  --url http://127.0.0.1:8000 --api-key "$NAUTILUS_API_KEY"
```

```text
OK: rotated: new primary kid=9d2b1e7c-2f40-4a1e-9c3d-11ab7f0e5c62  reviewer=alice
```

### `nautilus key revoke`

Revoke a key immediately — no grace window. Requires `NAUTILUS_REVIEWER`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `kid` | `str` (positional) | — | **Required.** Key ID to revoke. |
| `--reason` | `str` | — | **Required.** Revocation reason. |
| `--yes` | flag (`store_true`) | `False` | Confirm the destructive operation. Required. |

Plus the shared `--url` / `--api-key` / `--json`.

<!-- not-executed: substitute a kid from `nautilus key list` -->
```bash
NAUTILUS_REVIEWER=alice nautilus key revoke bb9b550c-48a6-4443-8381-c0e0bf2c3b5f \
  --reason "laptop lost" --yes --url http://127.0.0.1:8000 --api-key "$NAUTILUS_API_KEY"
```

```text
OK: revoked: kid=bb9b550c-48a6-4443-8381-c0e0bf2c3b5f  reason='laptop lost'  reviewer=alice
```

### Exit codes and failure modes (all three)

| Exit | When |
|------|------|
| `0` | The broker answered 200. |
| `1` | `--yes` missing on `rotate`/`revoke`, or `NAUTILUS_REVIEWER` unset. |
| `2` | `--url` omitted, the broker was unreachable, or it answered non-200. |

The order matters: a missing `--url` is reported *before* a missing
`NAUTILUS_REVIEWER`, because a missing target is the more fundamental error.

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: rotate requires --yes to confirm.` | `1` | Add `--yes`. |
| `ERROR: revoke requires --yes to confirm.` | `1` | Add `--yes`. |
| `FAIL: key <cmd>: --url is required. Rotation and revocation are audited events the broker emits against the ring it is serving with, so there is nothing for the CLI to act on locally — point --url at the running broker (e.g. --url http://localhost:8000).` | `2` | Point `--url` at the broker. |
| `FAIL: key <cmd>: cannot reach <endpoint>: [Errno 111] Connection refused` | `2` | Nothing is listening there. Confirm with `nautilus health`. |
| `ERROR: key <cmd>: server returned 401: {"detail":"Invalid API key"}` | `2` | Wrong or missing `--api-key`. |
| `ERROR: key <cmd>: server returned 409: {"detail":"session tokens are disabled (session_tokens.enabled: false)"}` | `2` | There is no ring to rotate. Set `session_tokens.enabled: true` in the broker's config and restart it. |

---

## `nautilus rules`

Rule validation and testing — see
[Authoring Rules](../how-to/authoring-rules.md).

`nautilus rules` with no subcommand prints `ERROR: unknown rules subcommand` and
exits `2`.

### `nautilus rules validate`

Static validation, optionally followed by a sandbox replay.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `file` | `str` (positional) | — | **Required.** Path to the rule YAML file to validate. |
| `--sandbox` | flag (`store_true`) | `False` | Run a sandbox replay after static validation. |
| `--replay-n` | `int` | `1000` | Number of audit entries to replay in sandbox mode. |
| `--audit-log` | `str` | `None` | Audit log to replay in sandbox mode (default `./audit.jsonl`). |
| `--json` | flag (`store_true`) | `False` | Emit results as JSON. |

With `--sandbox`, one summary line per rule is printed before the final verdict:

<!-- not-executed: needs a rule YAML at ./my-rules.yaml and an ./audit.jsonl to replay -->
```bash
nautilus rules validate my-rules.yaml --sandbox --replay-n 1000
```

```text
rule 'deny-confidential-to-support': replayed=0 fired=0 relaxations=0
OK: my-rules.yaml
```

<!-- not-executed: paths are relative to a checkout of the nautilus source tree -->
```bash
nautilus rules validate nautilus/rules/rules/handoff.yaml
```

```text
OK: nautilus/rules/rules/handoff.yaml
```

<!-- not-executed: paths are relative to a checkout of the nautilus source tree -->
```bash
nautilus rules validate nautilus/rules/rules/handoff.yaml --json
```

```text
{
  "file": "nautilus/rules/rules/handoff.yaml",
  "ok": true,
  "errors": []
}
```

| Exit | When |
|------|------|
| `0` | Valid (and, with `--sandbox`, the replay completed). |
| `1` | File not found, static validation failed, or the audit log named for the replay does not exist. |

**Failure modes**

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: file not found: <path>` | `1` | Check the path. |
| `ERROR <file>:<line>: <message> Hint: <hint>` | `1` | One line per static error, on stderr. The `Hint:` suffix appears only when the validator has one. `--json` returns the same errors as `{"file", "line", "message"}` objects. |
| `ERROR: audit log not found: <path>` | `1` | `--sandbox` needs a log. Point `--audit-log` at the broker's `audit.path`, or drop `--sandbox`. |

### `nautilus rules test`

The full validator pipeline — static, shadow, sandbox, score — with a pass/fail
threshold. This is the gate to run in CI.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--file` | `str` | — | **Required.** Path to the rule YAML file to test. |
| `--replay-n` | `int` | `1000` | Number of audit entries to replay. |
| `--min-entries` | `int` | `100` | Entries required before the sandbox result is meaningful (matches `rkm.sandbox.min_entries`). |
| `--audit-log` | `str` | `None` | Audit-log JSONL to replay in the sandbox stage. Omitted ⇒ zero entries are replayed and the result carries `insufficient_history: true`. |
| `--config` | `str` | `None` | `nautilus.yaml` whose `rules.packs` / `rules.user_rules_dirs` the sandbox replays against (default `./nautilus.yaml` when present). |
| `--threshold` | `float` | `0.6` | Minimum confidence score to pass. |
| `--json` | flag (`store_true`) | `False` | Emit results as JSON. |

<!-- not-executed: needs a rule YAML at ./my-rules.yaml -->
```bash
nautilus rules test --file my-rules.yaml --threshold 0.6
```

```text
WARN: rule 'deny-confidential-to-support': insufficient audit history (replayed 0 entries)
rule 'deny-confidential-to-support': score=0.90 fired=0/0 relaxations=0 shadow_flags=0
OK: my-rules.yaml score=0.90 (threshold 0.60)
```

<!-- not-executed: needs a rule YAML at ./my-rules.yaml -->
```bash
nautilus rules test --file my-rules.yaml --json
```

```text
{"file": "my-rules.yaml", "threshold": 0.6, "score": 0.9, "passed": true, "rules": [{"name": "deny-confidential-to-support", "score": 0.9, "breakdown": {"base": 1.0, "regression_penalty": -0.0, "relaxation_penalty": -0.0, "shadow_penalty": -0.0, "fire_rate_penalty": -0.1, "cascade_penalty": 0.0, "drift_penalty": 0.0}, "shadow_flags": [], "sandbox": {"replayed_n_actual": 0, "fired": 0, "regressions": 0, "relaxations": 0, "cascade_max": 0, "insufficient_history": true, "skipped_no_input_facts": 0, "skipped_drifted": 0}}]}
```

| Exit | When |
|------|------|
| `0` | The lowest per-rule score is at or above `--threshold`. |
| `1` | File not found, audit log not found, static validation failed, or a rule would not compile. |
| `2` | **The rule is valid but scored below `--threshold`.** This is the CI-failure code. |

**Failure modes**

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: score <n> below threshold <t>: <file>` | `2` | Read the per-rule `breakdown` in `--json` mode: `fire_rate_penalty` means the rule almost never fires against the replayed history, `regression_penalty` means it changed decisions that were previously correct. |
| `ERROR: rule '<name>': proposed rule '<name>' does not compile: ... duplicate rule name '<module>::<name>'` | `1` | A rule of that name is already loaded from a shipped pack or a `user_rules_dirs` entry. Rename yours, or test it against a `--config` that does not load the colliding pack. |
| `WARN: rule '<name>': insufficient audit history (replayed 0 entries)` | — | The score is computed but weakly grounded. Pass `--audit-log` pointing at at least `--min-entries` entries. |
| `WARN: no rules found in <file>` | — | The `rules:` list is empty. |
| `ERROR: cannot read rules config from <path>: <err>` | — | `--config` would not load; the run continues against the built-in ruleset only. |

### `nautilus rules history`

List lineage history for every rule in a module. Reads
`.nautilus/rkm/lineage` (`nautilus.cli.rules._DEFAULT_LINEAGE_DIR`).

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--module M` | `str` | — | **Required.** Module name to filter by. |
| `--json` | flag (`store_true`) | `False` | Emit results as JSON. |

```bash
nautilus rules history --module nautilus-routing
```

```text
No lineage records found for module 'nautilus-routing'.
```

Otherwise one line per record:
`<rule_name> v<version>  proposer=<who>  chain=<derived-from chain>`, with
` retired` appended where applicable. Exit `0` in both cases.

---

## `nautilus events`

Enumerate the audit `event_type` vocabulary. This is the runtime source of truth
for the set, paired with the `Literal` in `nautilus/core/models.py` by a
drift-guard test, so a value printed here is a value the audit log can contain.

`nautilus events` with no subcommand prints
`ERROR: events: subcommand required (list).` and exits `1`.

### `nautilus events list`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | flag (`store_true`) | `False` | Emit a JSON array to stdout. |

```bash
nautilus events list
```

```text
request
handoff_declared
attestation_emitted
session_token_issued
session_token_verification_failed
signing_key_rotated
signing_key_revoked
proposal_emitted
proposal_validated
proposal_approved
proposal_rejected
proposal_promoted
meta_rule_fired
relationship_observed
rule_promoted
rule_retracted
rule_rolled_back
adapter_quarantined
adapter_unquarantined
schema_drift_detected
schema_drift_severity_overridden
```

Exit `0`. This command has no failure path — the list is a constant in the
process.

---

## `nautilus attestation`

Offline verification of chained attestation logs — see
[Verify a token](../how-to/verify-a-token.md).

`nautilus attestation` with no subcommand prints
`ERROR: attestation: subcommand required (verify).` and exits `1`.

### `nautilus attestation verify`

Check hash linkage and every line's EdDSA JWS in a log written by
`ChainedFileAttestationSink` (`attestation.sink.chained: true`). With
`--expected-head` or `--anchor-token` it also detects tail truncation against an
out-of-band anchor — the one attack a self-consistent chain cannot see, because
deleting the last N lines leaves a shorter chain that still verifies.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `log` | `str` (positional) | — | **Required.** Chained attestation JSONL log path. |
| `--pubkey` | `str` | `None` | Ed25519 public key PEM. Default: `<log>.pub.pem` beside the log. |
| `--expected-head` | `str` | `None` | Out-of-band mirrored line hash. Verification fails if that hash is absent from the log. |
| `--anchor-token` | `str` | `None` | Checkpoint JWS token; its checkpoint line must appear in the log. Checkpoints are written every `attestation.sink.checkpoint_interval` emissions. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

<!-- not-executed: needs a chained log produced by a broker with attestation.sink.chained: true -->
```bash
nautilus attestation verify ./attestation.jsonl
```

```text
OK: chain valid — 3 records, head ee1cc7552711b7f08dbc3ee0968a87beec6cb7a2c9e617dd6c529e91cc363076
```

<!-- not-executed: needs a chained log produced by a broker with attestation.sink.chained: true -->
```bash
nautilus attestation verify ./attestation.jsonl --json
```

```text
{"ok": true, "count": 3, "head_seq": 4, "head_sha256": "ee1cc7552711b7f08dbc3ee0968a87beec6cb7a2c9e617dd6c529e91cc363076", "error": null, "error_line": null, "anchor_ok": null, "log_id": "5717d61f88d34521af9c15be9d24c816"}
```

Pin the head you mirrored elsewhere; `(anchor ok)` is appended when it matches:

<!-- not-executed: substitute the head_sha256 you recorded out of band -->
```bash
nautilus attestation verify ./attestation.jsonl \
  --expected-head ee1cc7552711b7f08dbc3ee0968a87beec6cb7a2c9e617dd6c529e91cc363076
```

```text
OK: chain valid — 3 records, head ee1cc7552711b7f08dbc3ee0968a87beec6cb7a2c9e617dd6c529e91cc363076 (anchor ok)
```

| Exit | When |
|------|------|
| `0` | The chain verified (`result.ok`). Note this includes `--json` mode, which prints the payload and *then* returns the code. |
| `1` | The log file or the public key file was not found — a setup error, not a verification failure. |
| `2` | The chain did not verify: broken linkage, a bad signature, or a missing anchor. |

**Failure modes**

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: attestation verify: log not found: <path>` | `1` | Check the path against `attestation.sink.path`. |
| `ERROR: attestation verify: pubkey not found: <log>.pub.pem` | `1` | The public key is written beside the log by the sink. Copy it alongside, or pass `--pubkey`. |
| `ERROR: attestation verify: signature claims mismatch at line <n>: signed {...'record_sha256': 'a...'}, computed {...'record_sha256': 'b...'}` | `2` | Line `n` was edited after signing. The two digests are the signed and recomputed record hashes; the surrounding fields (`seq`, `prev_sha256`, `log_id`) tell you where in the chain. Treat the log as compromised from line `n` onward. |
| `ERROR: attestation verify: expected head '<hash>' not present in log — tail truncated?` | `2` | The chain is internally consistent but does not reach the head you mirrored. Lines were removed from the end. Compare `head_seq` in `--json` mode against the sequence you anchored. |

---

## Argparse-level errors

Errors argparse raises itself, before any command code runs, go to stderr and
exit `2`.

```bash
python -m nautilus bogus
```

```text
usage: nautilus [-h] command ...
nautilus: error: argument command: invalid choice: 'bogus' (choose from version, session, health, serve, demo, init, rkm, rule, adapters, key, rules, events, attestation)
```

Bare `nautilus`, and bare `nautilus session`, produce
`error: the following arguments are required: command` and
`error: the following arguments are required: subcommand` respectively — these
two levels declare `required=True` on their subparsers, so argparse rejects
them; the other groups handle a missing subcommand in their own dispatch and
emit the `ERROR:` hints documented above.
