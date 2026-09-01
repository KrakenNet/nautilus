# CLI Reference

Complete reference for the `nautilus` command line: **13 top-level commands, 41
parsers in total, 102 arguments** (17 positional, 85 optional). Everything here
is read out of the argparse tree in `nautilus/cli/`; every default is the
literal `default=` the parser carries, and every transcript below was produced
by running the command shown.

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
`add_subparsers(dest="command", required=True, metavar="command")` to the root
parser and nothing else.

```bash
nautilus --help
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

Three codes are defined and a fourth is reserved. There is no `EXIT_*` constant
to import: the contract is stated in the module docstring of
`nautilus/cli/_common.py`, and each command's dispatch function returns the
literal.

| Code | Meaning | Returned by |
|------|---------|-------------|
| `0` | Success. | Every command. |
| `1` | User error — a file that is not there, a missing `--yes`, a missing `NAUTILUS_REVIEWER`, a rule that fails static validation, a proposal or rule that does not exist. | Everything except the read-only listers and the two long-running commands. Never returned by `serve`, `demo`, `rkm queue list`, `rkm lineage`, `rule list`, `rule lineage`, `rule history`, `adapters schema-diff`, `key list`, `rules history` or `events list`. |
| `2` | Validation / policy failure — a config that will not load, a score below `--threshold`, a chain that does not verify, a required `--url` that was omitted, a non-200 from the broker. Also argparse's own code for a bad flag, a bad choice, or a missing required argument. | Command code: `serve`, `session version`, `rules test`, `rkm queue approve`, `attestation verify`, `key list`/`rotate`/`revoke`, and the missing-subcommand hints of `rkm`, `rkm queue`, `rule`, `adapters` and `rules`. Argparse: all 41 parsers. Nothing else returns `2` — `rules validate`, for instance, returns `2` only when argparse rejects a flag. |
| `3` | **Reserved. Never returned by any command** (OQ5 LOCKED). `grep -rn 'return 3\|exit(3)' nautilus/` matches nothing; a `3` from the process is your shell or a wrapper, not Nautilus. | Nothing. |

Each command's section below states the codes **that command** can return and
names the ones it never returns, so `$?` is decidable without reading this
table. Two cases are worth knowing before you script anything:

- `nautilus rules test` is the one command where `2` is a routine, expected
  outcome: it means "the rule is valid but scored below `--threshold`". That is
  the CI-failure code.
- `nautilus adapters schema-diff` returns `0` **even when it finds drift**.
  Branch on the `status` field of `--json`, never on `$?`.

## Output prefixes

`nautilus/cli/_common.py` defines four helpers and nothing else writes decorated
lines. All four are plain `print()` calls: no Unicode sigils, and no ANSI colour
on any stream, tty or not — output is byte-identical piped and interactive.

| Helper | Emits | Stream |
|--------|-------|--------|
| `ok(msg)` | `OK: <msg>` | stdout |
| `warn(msg)` | `WARN: <msg>` | stderr |
| `err(msg)` | `ERROR: <msg>` | stderr |
| `fail(msg)` | `FAIL: <msg>` | stderr |

Not every line carries a prefix — `nautilus health` prints bare `OK 200 <url>` /
`FAIL <status> <url>`, and the listing subcommands print plain indented rows.
The transcripts below show which is which.

`--json`, where a subcommand has it, sends the machine-readable payload to
stdout and leaves `WARN:`/`ERROR:` lines on stderr, so `cmd --json 2>/dev/null`
is always parseable.

Every line in the **failure modes** tables below is catalogued in the
[error reference](errors/cli.md), which quotes the emitting source line.

## Environment variables

| Variable | Read by | Effect |
|----------|---------|--------|
| `NAUTILUS_REVIEWER` | `nautilus.cli._common.require_reviewer` | Operator identity recorded on every governance decision. Required by exactly seven subcommands — `rkm queue approve`, `rkm queue reject`, `rule retract`, `rule rollback`, `adapters schema-ack`, `key rotate`, `key revoke` (the seven `require_reviewer()` call sites in `nautilus/cli/`). `rkm queue submit` does **not** require it: queueing a proposal is not a decision. There is no `$USER` fallback — auto-detection would let a reviewer identity be spoofed by the shell (DQ4 LOCKED). Unset or blank ⇒ `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.` and exit `1`. |

`NAUTILUS_REVIEWER` is the **only** environment variable the CLI reads —
`os.environ` appears once in `nautilus/cli/`, in `require_reviewer`. In
particular there is no `NO_COLOR` handling, because there is no colour to
suppress (see below), and `NAUTILUS_API_KEY` in the examples below is purely a
shell variable you set yourself; nothing in `nautilus/cli/` looks it up.

## State on disk

Commands that are not pointed at a broker read and write these paths, relative
to the working directory:

| Path | Written/read by | Source |
|------|-----------------|--------|
| `.nautilus/rkm/queue` | `rkm queue *` | `nautilus.cli.rkm._DEFAULT_QUEUE_DIR` |
| `.nautilus/rkm/lineage` | `rkm lineage`, `rule *`, `rules history` | `nautilus.cli.rkm._DEFAULT_LINEAGE_DIR`, `nautilus.cli.rule._DEFAULT_LINEAGE_DIR`, `nautilus.cli.rules._DEFAULT_LINEAGE_DIR` |
| `./audit.jsonl` | `rkm queue approve/reject`, `rule retract/rollback`, `adapters schema-ack`, `rules validate --sandbox` | `nautilus.config.models.AuditConfig.path` default, resolved by `nautilus.cli._common.audit_path_for` |
| `./nautilus.yaml` | `serve` (as `--config` default), `init` (output), every `--config`-optional command (as the implicit config when present) | `nautilus.cli.serve` / `nautilus.cli.init` |

A relative `audit.path` inside a config is resolved **against the config file's
directory**, not the process's working directory — same rule the broker uses
(`nautilus.core.Broker._resolve`). Without `--config`, the decision commands
write `./audit.jsonl` in the working directory.

## Reproducing the transcripts

Every block below is real terminal output. Three setups produce all of them;
each transcript that needs one names it. Nothing here needs Docker, a database
or a network.

**Setup A — a config and nothing else.**

```bash
mkdir -p /tmp/nautilus-demo && cd /tmp/nautilus-demo
nautilus init --dir .
export NAUTILUS_API_KEY=$(grep -oE '[0-9a-f]{32}' nautilus.yaml | head -1)
```

**Setup B — A, plus a running broker on `127.0.0.1:8765`.**

```bash
nautilus serve --config nautilus.yaml --bind 127.0.0.1:8765 &
until nautilus health --url http://127.0.0.1:8765/readyz; do sleep 1; done
```

**Setup C — A, plus session tokens and a chained attestation log, on `127.0.0.1:8766`.**
Replace the `attestation:` block of `nautilus.yaml` with the first stanza and
append the second, then serve:

```yaml
attestation:
  enabled: true
  sink:
    type: file
    path: ./attest.jsonl
    chained: true
    checkpoint_interval: 2
```

```yaml
session_tokens:
  enabled: true
  key_ring_path: ./keyring.json
```

```bash
nautilus serve --config nautilus.yaml --bind 127.0.0.1:8766 &
until nautilus health --url http://127.0.0.1:8766/readyz; do sleep 1; done
curl -s -o /dev/null -X POST http://127.0.0.1:8766/v1/request \
  -H "X-API-Key: $NAUTILUS_API_KEY" -H 'Content-Type: application/json' \
  -d '{"agent_id":"agent-alpha","intent":"list recent orders for support","context":{"session_id":"s1","purpose":"support"}}'
```

**Setup D — A, plus a writable rules directory, on `127.0.0.1:8767`.** Approving
a proposal needs somewhere durable to put the promoted rule. Append to
`nautilus.yaml` and serve:

```yaml
rules:
  user_rules_dirs: [./rules.d]
```

```bash
mkdir -p rules.d
nautilus serve --config nautilus.yaml --bind 127.0.0.1:8767 &
until nautilus health --url http://127.0.0.1:8767/readyz; do sleep 1; done
```

Several transcripts use `my-rules.yaml`, the rule from
[Authoring Rules](../how-to/authoring-rules.md):

```bash
cat > my-rules.yaml <<'EOF'
module: nautilus-routing
ruleset: my-org-rules
version: "1.0"
rules:
  - name: deny-finance-after-hours
    description: "Deny finance sources outside business hours."
    salience: 180
    when:
      - template: agent
        conditions:
          - slot: purpose
            bind: ?purpose
      - template: source
        conditions:
          - slot: id
            bind: ?sid
          - slot: classification
            expression: equals("confidential")
    then:
      action: deny
      reason: "finance data is unavailable after hours"
      assert:
        - template: denial_record
          slots:
            source_id: "?sid"
            reason: "finance data is unavailable after hours"
            rule_name: "deny-finance-after-hours"
EOF
```

API keys, proposal IDs, key IDs, hashes and timestamps differ on every run; the
shapes do not. Kill the background brokers with `kill %1` when you are done.

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

Each subcommand has its own section below with its arguments, a transcript, its
exit codes, and its failure strings.

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

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse,
for an unrecognised flag) and never returns `3`.

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

`session` is one of the two parsers that declare `required=True` on their
subparsers, so a missing subcommand is argparse's error, not the command's:

```bash
nautilus session
```

```text
usage: nautilus session [-h] subcommand ...
nautilus session: error: the following arguments are required: subcommand
```

### `nautilus session version`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--sqlite-path` | `str` | `None` | Path to a sqlite session database. Read via `PRAGMA user_version`. |
| `--dsn` | `str` | `None` | Postgres DSN of a session store. Read via `SELECT version FROM nautilus_schema_version`. Requires `asyncpg`. |

Exactly one of the two is required.

Create a store to point it at (Setup A directory):

```bash
python - <<'EOF'
import asyncio
from nautilus.core.session_sqlite import SqliteSessionStore
asyncio.run(SqliteSessionStore("./sessions.db").setup())
EOF
nautilus session version --sqlite-path ./sessions.db
```

```text
store schema version: 1
this build understands: 1
```

**Exit codes** — returns `0`, `1` or `2`. Never returns `3`.

| Exit | When |
|------|------|
| `0` | The store's version equals `nautilus.core.session_pg._SCHEMA_VERSION` (currently `1`). |
| `1` | The store could not be read, or it was read and the versions differ. |
| `2` | Neither or both of `--sqlite-path` / `--dsn` were given. |

**Failure modes**

```bash
nautilus session version
```

```text
ERROR: pass exactly one of --sqlite-path or --dsn
```

```bash
nautilus session version --sqlite-path ./nope.db
```

```text
ERROR: no such file: nope.db
```

```bash
nautilus session version --dsn postgresql://127.0.0.1:1/none
```

```text
ERROR: could not connect: [Errno 111] Connect call failed ('127.0.0.1', 1)
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: pass exactly one of --sqlite-path or --dsn` | `2` | Pass one target, not zero and not both. |
| `ERROR: no such file: <path>` | `1` | The sqlite path does not exist (the message prints the path normalised, without a leading `./`). Check `session.sqlite_path` in your config. |
| `ERROR: asyncpg is not installed` | `1` | `pip install asyncpg`, or use `--sqlite-path`. |
| `ERROR: could not connect: <err>` | `1` | The DSN is wrong or the server is unreachable. |
| `ERROR: could not read nautilus_schema_version: <err>` | `1` | The table is missing — this DSN points at a database that is not a Nautilus session store, or one the broker has never initialised. |
| `ERROR: nautilus_schema_version holds no row` | `1` | The table exists but is empty. Let a broker start against it once, or point at a fresh store. |
| `They do not match, so this build refuses the store. Run the build that wrote it, or point the config at a fresh store.` | `1` | Printed on stdout after both numbers. A rollout is half-finished: finish it or roll it back. |

---

## `nautilus health`

Issue a single `GET` against a readiness URL with a 5-second timeout
(`nautilus.cli.health._HEALTH_TIMEOUT_S = 5`). This is the liveness probe the
container images use.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--url` | `str` | `http://localhost:8000/readyz` (`nautilus.cli.health._DEFAULT_HEALTH_URL`) | Readiness URL to probe. |

Setup B:

```bash
nautilus health --url http://127.0.0.1:8765/readyz
```

```text
OK 200 http://127.0.0.1:8765/readyz
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse)
and never returns `3`. A `0` here means literally HTTP 200 and nothing else.

| Exit | When |
|------|------|
| `0` | HTTP 200. |
| `1` | Any other status, an HTTP error, a timeout, or a socket error. |

**Failure modes**

```bash
nautilus health --url http://127.0.0.1:9/readyz
```

```text
FAIL unreachable http://127.0.0.1:9/readyz: <urlopen error [Errno 111] Connection refused>
```

| Message | Exit | What to do |
|---------|------|------------|
| `FAIL unreachable <url>: <urlopen error [Errno 111] Connection refused>` | `1` | Nothing is listening. Confirm the port from `nautilus serve --bind`, or from `api.host` / `api.port` in the config. |
| `FAIL <status> <url>` | `1` | The endpoint answered but not with 200. A 503 from `/readyz` means the broker is up and not ready — check its logs for the config or session-store problem it is reporting. |
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

Setup A. This runs until interrupted; everything below `Started server process`
is uvicorn's:

```bash
nautilus serve --config nautilus.yaml --bind 127.0.0.1:8765
```

```text
INFO:nautilus.core.broker:discovered adapter entry-point 'influxdb' -> InfluxDBAdapter (from 'nautilus-rkm')
INFO:nautilus.core.broker:discovered adapter entry-point 's3' -> S3Adapter (from 'nautilus-rkm')
INFO:     Started server process [2636001]
INFO:     Waiting for application startup.
WARNING:nautilus.transport.fastapi_app:api.keys[0] is a bare string: bound to no agent_id, so it can ask as any agent and call every governance route. Use the {key, agent_id, capabilities} form to scope it.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8765 (Press CTRL+C to quit)
```

`Ctrl-C` (or `SIGTERM`) shuts it down cleanly and returns `0`:

```text
INFO:     Shutting down
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
INFO:     Finished server process [2636001]
```

**Exit codes** — returns `0` or `2`. Never returns `1` and never returns `3`.
Every startup failure is a `2`, including ones another CLI would call user
error: `serve` treats "I could not stand this up" as one class.

| Exit | When |
|------|------|
| `0` | The server ran and shut down cleanly (including after `Ctrl-C`, which `_cmd_serve` catches). |
| `2` | Anything that stops it before or during the bind: config missing, config invalid, malformed `--bind`, air-gap violation, broker construction failure, or a lifespan that failed to start. Also argparse's code for a bad `--transport` / `--mcp-mode` / `--log-format` choice. |

**Failure modes**

```bash
nautilus serve --config nope.yaml
```

```text
ERROR: config path does not exist or is not a file: nope.yaml
```

```bash
nautilus serve --config nautilus.yaml --bind 127001
```

```text
ERROR: --bind must be HOST:PORT, got '127001'
```

```bash
nautilus serve --config nautilus.yaml --bind 127.0.0.1:abc
```

```text
ERROR: --bind port must be an integer, got 'abc'
```

```bash
printf 'sources: []\nnot_a_key: 1\n' > bad.yaml
nautilus serve --config bad.yaml
```

```text
ERROR: invalid config: Config validation failed:
  not_a_key: Extra inputs are not permitted [type=extra_forbidden]
```

```bash
nautilus serve --transport bogus
```

```text
usage: nautilus serve [-h] [--config CONFIG] [--transport {rest,mcp,both}]
                      [--mcp-mode {stdio,http}] [--bind BIND] [--air-gapped]
                      [--log-format {text,json}]
nautilus serve: error: argument --transport: invalid choice: 'bogus' (choose from rest, mcp, both)
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: config path does not exist or is not a file: <path>` | `2` | The `--config` path is wrong. `nautilus init` writes a working one. |
| `ERROR: --bind must be HOST:PORT, got '<value>'` | `2` | You passed a bare host or a bare port. Use `127.0.0.1:8000`. |
| `ERROR: --bind port must be an integer, got '<value>'` | `2` | The part after the last `:` is not a number. |
| `ERROR: invalid config: Config validation failed:` + one indented `  <key>: <detail>` line per problem | `2` | The YAML parsed but failed model validation. The config models reject unknown keys, so a typo shows up here as `Extra inputs are not permitted`. |
| `ERROR: broker construction failed: <detail>` | `2` | Wiring failed after validation — most often a source whose driver is not installed. The message names the extra to install. |
| `nautilus serve: error: argument --transport: invalid choice: '<value>' (choose from rest, mcp, both)` | `2` | argparse rejected the value before anything ran. `--mcp-mode` and `--log-format` produce the same shape. |
| `WARNING:nautilus.transport.fastapi_app:api.keys[0] is a bare string: bound to no agent_id, so it can ask as any agent and call every governance route. Use the {key, agent_id, capabilities} form to scope it.` | — | Startup warning, not a failure. `nautilus init` writes a bare key so the first run works; before exposing the port, replace it with the `{key, agent_id, capabilities}` form. |
| `WARN: --air-gapped overrides analysis.mode from '<mode>' to 'pattern' (NFR-1)` | — | Informational. Remove `analysis.mode` from the config, or drop `--air-gapped`. |
| `WARN: --air-gapped refuses analysis.provider (type='<type>'); dropping it (NFR-1)` | — | Informational. An air-gapped run has no LLM provider. |
| `WARN: --air-gapped drops LLM source id='<id>' — connection host is not loopback (NFR-1, #43)` | — | Informational. An LLM source is only air-gap compatible when the inference server is local. |

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
  "timestamp": "2026-09-01T01:49:43.334694Z",
  "request_id": "aa58bdc0-7e54-48e1-b0f5-7b3cac9a5f89",
  "agent_id": "analyst",
  "principal_id": null,
  "session_id": "demo",
  "raw_intent": "",
  "intent_analysis": null,
  "facts_asserted_summary": {
    "data_handoff": 1
  },
  "routing_decisions": [],
  "scope_constraints": [],
  "denial_records": [],
  "error_records": [],
  "rule_trace": [],
  "ruleset_hash": null,
  "sources_queried": [],
  "sources_denied": [],
  "sources_skipped": [],
  "sources_errored": [],
  "truncated_sources": null,
  "attestation_token": null,
  "duration_ms": 0,
  "llm_provider": null,
  "llm_model": null,
  "llm_version": null,
  "raw_response_hash": null,
  "source_response_hashes": null,
  "prompt_version": null,
  "fallback_used": null,
  "scope_hash_version": null,
  "session_id_source": null,
  "session_store_mode": null,
  "input_facts": null,
  "event_type": "handoff_declared",
  "adapter_id": null,
  "handoff_id": "aa58bdc0-7e54-48e1-b0f5-7b3cac9a5f89",
  "handoff_decision": {
    "handoff_id": "aa58bdc0-7e54-48e1-b0f5-7b3cac9a5f89",
    "action": "allow",
    "denial_records": [],
    "rule_trace": []
  },
  "trace_id": null,
  "schema_version": null,
  "event_fields": null
}

Every request the broker answers is recorded the same way.

Next: 'nautilus init' writes a nautilus.yaml you can serve, and
      'nautilus serve' runs it as a REST or MCP endpoint.
```

That is the full `AuditEntry` shape, nulls included — the same record
`GET /v1/audit` returns and the same one `rules validate --sandbox` replays.

**Exit codes** — returns `0`. Never returns `1`, `2` (except from argparse) or
`3`.

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
    curl -H 'X-API-Key: deadbeefdeadbeefdeadbeefdeadbeef' http://127.0.0.1:8000/v1/sources
```

The file it wrote, verbatim (the key differs on every run):

```yaml
# Written by 'nautilus init'. See https://github.com/KrakenNet/nautilus
# (docs/getting-started.md).
#
# This config serves the rows below with no database attached. Point a real
# source at your data by replacing the 'static' block with, say:
#
#   - id: main-db
#     type: postgres
#     classification: confidential
#     data_types: [users, orders]
#     connection: ${DATABASE_URL}
#     table: public.orders

sources:
  - id: orders
    type: static
    description: Sample order rows, served from this file.
    classification: unclassified
    data_types: [orders]
    allowed_purposes: [support]
    rows:
      - {order_id: 1001, user_id: 42, total: 19.99}
      - {order_id: 1002, user_id: 43, total: 7.50}

# Declared agents are how clearance and purpose stop being whatever the caller
# claims. Undeclared, the broker takes the caller's word for both and warns.
agents:
  agent-alpha:
    id: agent-alpha
    clearance: confidential
    allowed_purposes: [support]

attestation:
  enabled: true

audit:
  path: ./audit.jsonl

# Every route that reads data needs a key. An empty list fails closed, which is
# the right default and a poor first run: without this block 'nautilus serve'
# starts clean and answers 401 to /v1/sources and /v1/request. Replace this
# generated key before anyone else can reach the port.
api:
  keys:
    - deadbeefdeadbeefdeadbeefdeadbeef
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse)
and never returns `3`.

| Exit | When |
|------|------|
| `0` | File written. |
| `1` | A `nautilus.yaml` already exists at the target. |

**Failure modes**

```bash
nautilus init --dir .
```

```text
ERROR: nautilus.yaml already exists — refusing to overwrite it
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: <dir>/nautilus.yaml already exists — refusing to overwrite it` (with `--dir .` the path prints as bare `nautilus.yaml`) | `1` | Move or delete the existing file, or write elsewhere with `--dir`. The command never overwrites: the file holds a generated API key. |

---

## `nautilus rkm`

Review-queue and lineage management. See
[RKM: the Rule Lifecycle](../concepts/rkm-lifecycle.md). The queue lives in
`.nautilus/rkm/queue` under the working directory.

```bash
nautilus rkm
```

```text
ERROR: rkm: no subcommand given (try: queue, lineage)
```

```bash
nautilus rkm queue
```

```text
ERROR: rkm queue: no op given (try: submit, list, show, approve, reject, diff)
```

Both exit `2`.

`approve` and `reject` are decisions, so each appends its record to the audit
log (`proposal_approved`, `proposal_rejected`, plus `rule_promoted` and
`proposal_promoted` when an approval promotes). `--config nautilus.yaml` sends
that record to the file's `audit.path`, resolved relative to the config's own
directory; without `--config` the default `./audit.jsonl` is used.

### `nautilus rkm queue list`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--status` | `str` | `None` | Filter by status (`pending`, `rejected`, `approved`, `promoted`). |
| `--min-confidence` | `float` | `0.0` | Minimum confidence score, 0.0–1.0. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

```bash
nautilus rkm queue list
```

```text
  prop_66a1dd99794f42059f7101be51671119  status=pending  confidence=0.9
  prop_a5720da395cf46819de640a393e6baa9  status=rejected  confidence=0.9
  prop_ba936dca5d7b40149b7855befbcf34f0  status=pending  confidence=0.9
  prop_daf5e4ab73814c1cbeec62a7b85ddb0e  status=pending  confidence=0.9
```

```bash
nautilus rkm queue list --status pending
```

```text
  prop_ba936dca5d7b40149b7855befbcf34f0  status=pending  confidence=0.9
  prop_daf5e4ab73814c1cbeec62a7b85ddb0e  status=pending  confidence=0.9
```

`--json` prints the full proposal objects, not the summary line — the same shape
`queue show --json` prints, in an array. An empty queue prints `OK: no proposals`
(and `[]` with `--json`).

**Exit codes** — returns `0`. Never returns `1`, `2` (except from argparse) or
`3`: an empty result is an answer, not an error.

### `nautilus rkm queue submit`

Runs the full validator pipeline over a rule file and queues the resulting
proposal. Does **not** require `NAUTILUS_REVIEWER` — queueing is not a decision.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--file` | `str` | — | **Required.** Path to the rule YAML to propose. |
| `--config` | `str` | `None` | `nautilus.yaml` naming the audit log the sandbox stage replays. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

```bash
nautilus rkm queue submit --file my-rules.yaml --config nautilus.yaml
```

```text
OK: proposal prop_66a1dd99794f42059f7101be51671119 queued pending (confidence 0.90)
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse)
and never returns `3`.

| Exit | When |
|------|------|
| `0` | Queued with status `pending`. |
| `1` | The rule file was not found, or the proposal was queued with status `rejected` — the queue keeps the rejected proposal as a record; each validation error is printed as a `WARN:` line first. |

**Failure modes**

```bash
nautilus rkm queue submit --file /dev/null
```

```text
ERROR: rule file not found: /dev/null
```

A file that does not compile is queued and then rejected — note the `OK:` line
on stdout *and* exit `1`:

```bash
nautilus rkm queue submit --file broken.yaml
```

```text
WARN: Rule file does not compile: [fathom.compiler] parse rules failed: invalid ruleset in broken.yaml — 2 validation errors for RulesetDefinition
rules.0.name
  Value error, RuleDefinition.name name 'bad rule' is not a valid CLIPS identifier (must match [A-Za-z_][A-Za-z0-9_-]*) [type=value_error, input_value='bad rule', input_type=str]
    For further information visit https://errors.pydantic.dev/2.13/v/value_error
rules.0.then.action
  Input should be 'allow', 'deny', 'escalate', 'scope' or 'route' [type=enum, input_value='nope', input_type=str]
    For further information visit https://errors.pydantic.dev/2.13/v/enum
OK: proposal prop_a5720da395cf46819de640a393e6baa9 queued rejected (confidence 0.90)
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: rule file not found: <path>` | `1` | Check `--file`. The path is printed exactly as you passed it. |
| `WARN: Rule file does not compile: ...` then `OK: proposal <id> queued rejected (confidence <c>)` | `1` | Static validation failed. Fix the rule and resubmit; the rejected proposal stays in the queue as the record that you tried. |
| `WARN: Rule file does not compile: ... duplicate rule name '<module>::<name>'` | `1` | A rule of that name is already promoted or shipped in a pack. Rename yours, or retract the existing one first. |
| `WARN: could not read rkm settings from '<path>' (<err>); using defaults` | — | `--config` could not be parsed; the submission still ran, on default sandbox settings. |

### `nautilus rkm queue show`

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `proposal_id` | `str` (positional) | — | **Required.** Proposal ID, `prop_<hex>`. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

```bash
nautilus rkm queue show prop_66a1dd99794f42059f7101be51671119
```

```text
  proposal_id: prop_66a1dd99794f42059f7101be51671119
  schema_version: 2
  status: pending
  proposer: pipeline
  proposed_at: 2026-09-01T01:50:04.970757+00:00
  target_module: curator
  artifact_type: rule
  artifact: {'yaml_path': 'my-rules.yaml', 'name': 'deny-finance-after-hours', 'module': 'nautilus-routing'}
  validation: {'static_ok': True, 'static_errors': [], 'sandbox': {'replayed_n': 1000, 'replayed_n_actual': 0, 'regressions': 0, 'relaxations': 0, 'fired': 0, 'cascade_max': 0, 'insufficient_history': True, 'skipped_no_input_facts': 3, 'skipped_drifted': 0, 'top_triggers': [], 'error': None}, 'confidence': 0.9, 'confidence_breakdown': {'base': 1.0, 'regression_penalty': -0.0, 'relaxation_penalty': -0.0, 'shadow_penalty': -0.0, 'fire_rate_penalty': -0.1, 'cascade_penalty': 0.0, 'drift_penalty': 0.0, 'total': 0.9}}
  lineage: {'derived_from': None}
  decisions: []
  shadow_flags: []
```

```bash
nautilus rkm queue show prop_66a1dd99794f42059f7101be51671119 --json
```

```text
{"proposal_id": "prop_66a1dd99794f42059f7101be51671119", "schema_version": 2, "status": "pending", "proposer": "pipeline", "proposed_at": "2026-09-01T01:50:04.970757+00:00", "target_module": "curator", "artifact_type": "rule", "artifact": {"yaml_path": "my-rules.yaml", "name": "deny-finance-after-hours", "module": "nautilus-routing"}, "validation": {"static_ok": true, "static_errors": [], "sandbox": {"replayed_n": 1000, "replayed_n_actual": 0, "regressions": 0, "relaxations": 0, "fired": 0, "cascade_max": 0, "insufficient_history": true, "skipped_no_input_facts": 3, "skipped_drifted": 0, "top_triggers": [], "error": null}, "confidence": 0.9, "confidence_breakdown": {"base": 1.0, "regression_penalty": -0.0, "relaxation_penalty": -0.0, "shadow_penalty": -0.0, "fire_rate_penalty": -0.1, "cascade_penalty": 0.0, "drift_penalty": 0.0, "total": 0.9}}, "lineage": {"derived_from": null}, "decisions": [], "shadow_flags": []}
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse)
and never returns `3`.

**Failure modes**

```bash
nautilus rkm queue show prop_deadbeef
```

```text
ERROR: proposal prop_deadbeef not found
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: proposal <id> not found` | `1` | The ID is not in `.nautilus/rkm/queue`. `nautilus rkm queue list` shows what is. |

### `nautilus rkm queue approve`

Approval is not bookkeeping: it promotes the rule into the CLIPS environment of
a **running** broker. `--url` is therefore effectively required — without it the
command refuses rather than marking a proposal promoted while loading the rule
nowhere. Requires `NAUTILUS_REVIEWER`, which is sent as `X-Nautilus-Reviewer`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `proposal_id` | `str` (positional) | — | **Required.** Proposal ID. |
| `--note` | `str` | `None` | Optional reviewer note. Recorded on the decision. |
| `--url` | `str` | `None` | Base URL of the running broker, e.g. `http://localhost:8000`. Refuses to run without it. |
| `--api-key` | `str` | `None` | `X-API-Key` for the broker. |
| `--config` | `str` | `None` | `nautilus.yaml` whose `audit.path` receives the decision record (default `./audit.jsonl`). |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

Setup D (the broker needs `rules.user_rules_dirs`, or promotion fails — see the
failure table):

```bash
NAUTILUS_REVIEWER=alice nautilus rkm queue approve prop_2a1492909ca94498afcdd8aa9a4b314c \
  --url http://127.0.0.1:8767 --api-key "$NAUTILUS_API_KEY" \
  --config nautilus.yaml --note 'reviewed with the data owner'
```

```text
OK: proposal prop_2a1492909ca94498afcdd8aa9a4b314c approved by alice (promoted=True)
```

Approving twice is idempotent, not an error:

```bash
NAUTILUS_REVIEWER=alice nautilus rkm queue approve prop_2a1492909ca94498afcdd8aa9a4b314c \
  --url http://127.0.0.1:8767 --api-key "$NAUTILUS_API_KEY" --json
```

```text
{"status": "already_approved", "proposal_id": "prop_2a1492909ca94498afcdd8aa9a4b314c"}
```

**Exit codes** — returns `0`, `1` or `2`. Never returns `3`.

| Exit | When |
|------|------|
| `0` | Approved and promoted, or already approved. |
| `1` | `NAUTILUS_REVIEWER` unset (checked *first*, before `--url`), or the proposal does not exist on that broker. |
| `2` | `--url` omitted, the broker was unreachable, or it answered with a non-200 that was not 404 — including the 422 that means "approved, but the rule could not be promoted". |

**Failure modes**

```bash
NAUTILUS_REVIEWER=alice nautilus rkm queue approve prop_a5720da395cf46819de640a393e6baa9
```

```text
ERROR: rkm queue approve: --url is required. Approving promotes the rule into the engine of a running broker, so there is nothing for the CLI to approve locally — point --url at the broker (e.g. --url http://localhost:8000).
```

```bash
NAUTILUS_REVIEWER=alice nautilus rkm queue approve prop_a5720da395cf46819de640a393e6baa9 \
  --url http://127.0.0.1:9 --api-key k
```

```text
ERROR: rkm queue approve: cannot reach http://127.0.0.1:9/v1/rkm/queue/prop_a5720da395cf46819de640a393e6baa9/approve: [Errno 111] Connection refused
```

Against a broker with no `rules.user_rules_dirs` (Setup C), the proposal is
approved but the rule cannot be made durable:

```text
ERROR: rkm queue approve: server returned 422: {"detail":{"error":"promotion_failed","message":"FathomRouter.reload_rule failed for proposal 'prop_4d7a427788264351bf82e401ae3a2dbb': cannot promote rule 'prop_4d7a427788264351bf82e401ae3a2dbb': no rules.user_rules_dirs is configured, so the rule would live only in this process and be gone at the next restart while the proposal reads 'promoted'. Configure a writable rules directory and retry the approval.","current_status":"approved","recovery":"fix the rule and re-approve to retry the promotion, or reject the proposal"}}
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: rkm queue approve: --url is required. Approving promotes the rule into the engine of a running broker, so there is nothing for the CLI to approve locally — point --url at the broker (e.g. --url http://localhost:8000).` | `2` | Start the broker and point at it. |
| `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.` | `1` | `export NAUTILUS_REVIEWER=<you>`. Checked before `--url`, so fix this first. |
| `ERROR: rkm queue approve: cannot reach <endpoint>: [Errno 111] Connection refused` | `2` | Wrong host/port, or the broker is down. `nautilus health` confirms. |
| `ERROR: proposal <id> not found` | `1` | The ID is not in that broker's queue. `nautilus rkm queue list` shows what is. |
| `ERROR: rkm queue approve: server returned 401: {"detail":"Invalid API key"}` | `2` | Wrong or missing `--api-key`. A 403 means that key is bound to a different agent. |
| `ERROR: rkm queue approve: server returned 422: {"detail":{"error":"promotion_failed",...,"recovery":"fix the rule and re-approve to retry the promotion, or reject the proposal"}}` | `2` | Set `rules.user_rules_dirs` to a writable directory in the broker's config, restart it, and re-approve — the `current_status` field tells you the approval itself stuck. |

### `nautilus rkm queue reject`

Requires `NAUTILUS_REVIEWER`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `proposal_id` | `str` (positional) | — | **Required.** Proposal ID. |
| `--reason` | `str` | — | **Required.** Rejection reason. Recorded on the decision. |
| `--config` | `str` | `None` | `nautilus.yaml` whose `audit.path` receives the decision record (default `./audit.jsonl`). |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

```bash
NAUTILUS_REVIEWER=alice nautilus rkm queue reject prop_66a1dd99794f42059f7101be51671119 \
  --reason 'too broad'
```

```text
OK: proposal prop_66a1dd99794f42059f7101be51671119 rejected by alice: too broad
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse,
which is what a missing `--reason` produces) and never returns `3`.

| Exit | When |
|------|------|
| `0` | Rejected. |
| `1` | `NAUTILUS_REVIEWER` unset, the proposal does not exist, or it was already decided. |

**Failure modes**

```bash
nautilus rkm queue reject prop_a5720da395cf46819de640a393e6baa9 --reason x
```

```text
ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.
```

```bash
NAUTILUS_REVIEWER=alice nautilus rkm queue reject prop_66a1dd99794f42059f7101be51671119 \
  --reason 'too broad'
```

```text
ERROR: proposal prop_66a1dd99794f42059f7101be51671119 already decided: status=rejected
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.` | `1` | `export NAUTILUS_REVIEWER=<you>`. |
| `ERROR: proposal <id> not found` | `1` | Check the ID with `nautilus rkm queue list`. |
| `ERROR: proposal <id> already decided: status=<status>` | `1` | Someone got there first — a decision is not repeatable. `rkm queue show <id>` names the decider. |
| `nautilus rkm queue reject: error: the following arguments are required: --reason` | `2` | argparse; `--reason` is `required=True`. |

### `nautilus rkm queue diff`

Show the schema diff between a proposal and its peer rule. The peer is found by
the DQ6 heuristic: `lineage.derived_from` first, then the longest common prefix
of rule names, then `no peer`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `proposal_id` | `str` (positional) | — | **Required.** Proposal ID. |

No `--json` on this one.

```bash
nautilus rkm queue diff prop_66a1dd99794f42059f7101be51671119
```

```text
  proposal : prop_66a1dd99794f42059f7101be51671119
  peer     : no peer
  artifact : {
  "yaml_path": "my-rules.yaml",
  "name": "deny-finance-after-hours",
  "module": "nautilus-routing"
}
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse)
and never returns `3`.

**Failure modes**

```bash
nautilus rkm queue diff prop_deadbeef
```

```text
ERROR: proposal prop_deadbeef not found
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: proposal <id> not found` | `1` | Check the ID with `nautilus rkm queue list`. |

### `nautilus rkm lineage`

Reads the same lineage store as `nautilus rule lineage`, but accepts a proposal
ID as well as a rule name.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `str` (positional) | — | **Required.** Proposal ID **or** rule name. |
| `--depth` | `int` | `5` | Maximum ancestor depth to traverse. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

Setup D, after the approval above:

```bash
nautilus rkm lineage deny-finance-after-hours
```

```text
  deny-finance-after-hours v1  approver=alice  promoted=2026-09-01T01:53:30.122910+00:00
```

An unknown id is not an error:

```bash
nautilus rkm lineage nonexistent --json
```

```text
WARN: no lineage records for 'nonexistent'
[]
```

(The `WARN:` line is on stderr, the `[]` on stdout.)

**Exit codes** — returns `0`. Never returns `1`, `2` (except from argparse) or
`3`: an empty lineage is an answer.

---

## `nautilus rule`

Rule lifecycle management, reading the lineage store under
`.nautilus/rkm/lineage` (`nautilus.cli.rule._DEFAULT_LINEAGE_DIR`).

```bash
nautilus rule
```

```text
ERROR: rule: no subcommand given (try: list, retract, lineage, history, rollback)
```

Exit `2`.

### `nautilus rule list`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--status` | `str` | `None` | Filter by status (`active`, `retired`). |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

`--status` accepts `active` (`retired_at is None`) and `retired`; any other
value filters nothing out.

Setup D, immediately after one approval — one promoted version:

```bash
nautilus rule list
```

```text
  deny-finance-after-hours v1 [active]
```

```bash
nautilus rule list --json
```

```text
[{"name": "deny-finance-after-hours", "version": 1, "retired": false}]
```

And after a rollback (which adds v2) and a retraction of v2:

```bash
nautilus rule list
```

```text
  deny-finance-after-hours v1 [active]
  deny-finance-after-hours v2 [retired]
```

An empty lineage store prints nothing at all on stdout (and `[]` with `--json`).

**Exit codes** — returns `0`. Never returns `1`, `2` (except from argparse) or
`3`.

### `nautilus rule retract`

Retire a rule. **Destructive** — appends `rule_retracted` to the audit log with
`{"rule_name", "version", "reason", "reviewer", "affected_descendants"}`.
Requires `NAUTILUS_REVIEWER`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Rule name. |
| `--reason` | `str` | — | **Required.** Retraction reason. |
| `--yes` | flag (`store_true`) | `False` | Confirm the destructive operation. Required. |
| `--cascade` | flag (`store_true`) | `False` | Retire all transitive descendants too (AC-35.10.d). |
| `--orphan-children` | flag (`store_true`) | `False` | Flag direct descendants as orphaned without retiring them (AC-35.10.d). Mutually exclusive with `--cascade`. |
| `--config` | `str` | `None` | `nautilus.yaml` whose `audit.path` receives the decision record (default `./audit.jsonl`). |

```bash
NAUTILUS_REVIEWER=alice nautilus rule retract deny-finance-after-hours \
  --reason 'superseded by pack rule' --yes --config nautilus.yaml
```

```text
OK: rule 'deny-finance-after-hours' v2 retracted by alice
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse,
which is what a missing `--reason` produces) and never returns `3`.

| Exit | When |
|------|------|
| `0` | Retracted. Affected descendants, if any, follow on a `WARN: affected descendants: ...` line. |
| `1` | `--yes` missing, both cascade flags given, `NAUTILUS_REVIEWER` unset, or the rule is not in the lineage store. |

**Failure modes**

```bash
NAUTILUS_REVIEWER=alice nautilus rule retract deny-finance-after-hours --reason x
```

```text
ERROR: --yes required for destructive op
```

```bash
NAUTILUS_REVIEWER=alice nautilus rule retract deny-finance-after-hours \
  --reason x --yes --cascade --orphan-children
```

```text
ERROR: --cascade and --orphan-children are mutually exclusive
```

```bash
NAUTILUS_REVIEWER=alice nautilus rule retract deny-finance-after-hours --reason x --yes
```

```text
ERROR: rule 'deny-finance-after-hours' not found in lineage
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: --yes required for destructive op` | `1` | Add `--yes`. |
| `ERROR: --cascade and --orphan-children are mutually exclusive` | `1` | Pick one: retire the descendants, or mark them orphaned. |
| `ERROR: rule '<name>' not found in lineage` | `1` | `nautilus rule list` shows the names that exist. Nothing is promoted until a proposal is approved. |
| `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.` | `1` | `export NAUTILUS_REVIEWER=<you>`. |
| `nautilus rule retract: error: the following arguments are required: --reason` | `2` | argparse; `--reason` is `required=True`. |

### `nautilus rule lineage`

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Rule name. |
| `--depth` | `int` | `5` | Maximum ancestor depth to traverse. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

```bash
nautilus rule lineage deny-finance-after-hours --depth 5
```

```text
  deny-finance-after-hours v1  approver=alice  promoted=2026-09-01T01:53:30.122910+00:00
```

```bash
nautilus rule lineage deny-finance-after-hours --json
```

```text
{"proposer": "pipeline", "versions": [{"rule_name": "deny-finance-after-hours", "version": 1, "proposer": "pipeline", "observation_ids": {}, "sandbox_results": {}, "approver": "alice", "derived_from": [], "promoted_at": "2026-09-01T01:53:30.122910+00:00", "retired_at": null, "retire_reason": null, "retire_reviewer": null, "module": "nautilus-routing", "reviewer": "alice"}]}
```

An unknown name prints `WARN: no lineage records for '<name>'` on stderr and
still exits `0`; with `--json` it prints `{"proposer": null, "versions": []}`.

**Exit codes** — returns `0`. Never returns `1`, `2` (except from argparse) or
`3`.

### `nautilus rule history`

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Rule name. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

```bash
nautilus rule history deny-finance-after-hours
```

```text
  v1  promoted=2026-09-01T01:53:30.122910+00:00
  v2  promoted=2026-09-01T01:53:39.383026+00:00 [retired]
```

One `  v<n>  promoted=<iso8601>` line per version, with ` [retired]` appended
where applicable. An unknown name:

```bash
nautilus rule history deny-finance-after-hours
```

```text
WARN: no history for 'deny-finance-after-hours'
```

**Exit codes** — returns `0`, including for the empty case. Never returns `1`,
`2` (except from argparse) or `3`. `--json` prints `[]` when empty.

### `nautilus rule rollback`

Restore a prior version. **Destructive** — appends `rule_rolled_back` to the
audit log with `{"rule_name", "restored_version", "new_version", "reason",
"reviewer"}`. The restore is forward-only: rolling back to v1 creates a **new**
version, it does not delete v2. Requires `NAUTILUS_REVIEWER`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Rule name. |
| `--to-version` | `int` | — | **Required.** Target version number to restore. |
| `--reason` | `str` | — | **Required.** Rollback reason. |
| `--yes` | flag (`store_true`) | `False` | Confirm the destructive operation. Required. |
| `--config` | `str` | `None` | `nautilus.yaml` whose `audit.path` receives the decision record (default `./audit.jsonl`). |

```bash
NAUTILUS_REVIEWER=alice nautilus rule rollback deny-finance-after-hours \
  --to-version 1 --reason 'v2 salience broke ordering' --yes --config nautilus.yaml
```

```text
OK: rule 'deny-finance-after-hours' rolled back to v1 as v2 by alice: v2 salience broke ordering
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse,
which is what a missing or non-integer `--to-version` produces) and never
returns `3`.

| Exit | When |
|------|------|
| `0` | Rolled back; the restored content is written as the next version number. |
| `1` | `--yes` missing, `NAUTILUS_REVIEWER` unset, or that name/version pair is not in the lineage store. |

**Failure modes**

```bash
NAUTILUS_REVIEWER=alice nautilus rule rollback deny-finance-after-hours \
  --to-version 2 --reason x --yes
```

```text
ERROR: rule 'deny-finance-after-hours' v2 not found in lineage
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: rule '<name>' v<n> not found in lineage` | `1` | `nautilus rule history <name>` lists the versions that exist. |
| `ERROR: --yes required for destructive op` | `1` | Add `--yes`. |
| `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.` | `1` | `export NAUTILUS_REVIEWER=<you>`. |
| `nautilus rule rollback: error: argument --to-version: invalid int value: 'x'` | `2` | argparse; `--to-version` is `type=int`. |

---

## `nautilus adapters`

Adapter registry, scaffolding, and schema-drift operations — see
[Developing Adapters](../how-to/developing-adapters.md).

```bash
nautilus adapters
```

```text
ERROR: adapters: no subcommand given (try: new, list, schema, schema-fingerprint, schema-diff, schema-ack)
```

Exit `2`.

Where `--config` is optional it defaults to `./nautilus.yaml` when that file is
present; when it is not:

```bash
cd /tmp && nautilus adapters list
```

```text
ERROR: no config found: pass --config PATH, or run from a directory containing nautilus.yaml
```

Exit `1`.

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

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse)
and never returns `3`.

| Exit | When |
|------|------|
| `0` | Package written. |
| `1` | Invalid name, non-empty destination, or `copier` not installed. |

**Failure modes**

```bash
nautilus adapters new My_Bad_Name
```

```text
ERROR: invalid adapter name 'My_Bad_Name' (expected lowercase-dashed, e.g. my-csv-adapter)
```

```bash
nautilus adapters new my-csv-adapter --dir .
```

```text
ERROR: destination already exists and is not empty: my-csv-adapter
```

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

Setup A — config mode:

```bash
nautilus adapters list --config nautilus.yaml
```

```text
  orders  type=static  status=configured
```

```bash
nautilus adapters list --config nautilus.yaml --json
```

```text
[{"id": "orders", "type": "static", "status": "configured"}]
```

Setup B — server mode. Note the status changes from `configured` to `active`,
because now something is actually serving it:

```bash
nautilus adapters list --url http://127.0.0.1:8765 --api-key "$NAUTILUS_API_KEY"
```

```text
  orders  type=static  status=active
```

```bash
nautilus adapters list --url http://127.0.0.1:8765 --api-key "$NAUTILUS_API_KEY" --json
```

```text
[{"id": "orders", "type": "static", "status": "active"}]
```

```bash
nautilus adapters list --url http://127.0.0.1:8765 --api-key "$NAUTILUS_API_KEY" --status active
```

```text
  orders  type=static  status=active
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse)
and never returns `3`. Note the asymmetry with `key` and `rkm queue approve`: a
bad broker answer here is a `1`, not a `2`.

| Exit | When |
|------|------|
| `0` | Listed. An empty registry prints `OK: no adapters registered`. |
| `1` | `--status` without `--url`, no config found, the config could not be loaded, or the server could not be reached — including when it answers 401. |

**Failure modes**

```bash
nautilus adapters list --status active
```

```text
ERROR: --status 'active' needs --url: quarantine state lives in the serving process, so a config file cannot answer it. Reporting an empty list here would look like 'nothing is quarantined'.
```

```bash
nautilus adapters list --url http://127.0.0.1:8765 --api-key wrongkey
```

```text
ERROR: could not reach http://127.0.0.1:8765: Client error '401 Unauthorized' for url 'http://127.0.0.1:8765/v1/adapters'
For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: --status '<value>' needs --url: quarantine state lives in the serving process, so a config file cannot answer it. Reporting an empty list here would look like 'nothing is quarantined'.` | `1` | Add `--url`. |
| `ERROR: no config found: pass --config PATH, or run from a directory containing nautilus.yaml` | `1` | Pass `--config`, or `cd` to the config's directory. |
| `ERROR: could not load <path>: <err>` | `1` | The config is present but will not parse. |
| `ERROR: could not reach <url>: Client error '401 Unauthorized' for url '<url>/v1/adapters'` | `1` | The key is wrong. This is an auth failure wearing the transport error's message — the URL is fine. |
| `ERROR: could not reach <url>: <err>` | `1` | The server is down or the URL is wrong. |

### `nautilus adapters schema`

Print the adapter's live `AdapterSchema` — tables, fields, capability flags and
the fetch timestamp.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Adapter name/id. |
| `--config` | `str` | `None` | Path to `nautilus.yaml` (default `./nautilus.yaml` when present). |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

Setup A (`orders` is the sample source `nautilus init` writes):

```bash
nautilus adapters schema orders --config nautilus.yaml
```

```text
  adapter_id: orders
  source_type: static
  tables: ({'name': 'orders', 'fields': ({'name': 'order_id', 'type': 'yaml', 'nullable': True, 'description': ''}, {'name': 'user_id', 'type': 'yaml', 'nullable': True, 'description': ''}, {'name': 'total', 'type': 'yaml', 'nullable': True, 'description': ''}), 'indexes': (), 'primary_key': ()},)
  capability_flags: {}
  fetched_at: 2026-09-01T01:49:57.649963+00:00
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse)
and never returns `3`.

**Failure modes**

```bash
nautilus adapters schema nope --config nautilus.yaml
```

```text
ERROR: no schema available for adapter 'nope'
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: no schema available for adapter '<name>'` | `1` | The id is not in the config's `sources`, or its adapter could not introspect. `nautilus adapters list` shows the ids. In `--json` mode a `null` is printed on stdout first. |

### `nautilus adapters schema-fingerprint`

Print the `sha256:`-prefixed digest of the adapter's current schema. This is the
value `schema-diff` compares against and `schema-ack` stores.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Adapter name/id. |
| `--config` | `str` | `None` | Path to `nautilus.yaml` (default `./nautilus.yaml` when present). |

No `--json` on this one — the output is already one token.

```bash
nautilus adapters schema-fingerprint orders --config nautilus.yaml
```

```text
sha256:c48627e080df819eaad265fab62fe513958afa03da7c7ee1465dbe74ea8ef49c
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse)
and never returns `3`.

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: no schema available for adapter '<name>'` | `1` | Same as `adapters schema` — check the id. |

### `nautilus adapters schema-diff`

Compare the live schema against the stored baseline.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `name` | `str` (positional) | — | **Required.** Adapter name/id. |
| `--config` | `str` | — | **Required.** Path to `nautilus.yaml`. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

No baseline yet:

```bash
nautilus adapters schema-diff orders --config nautilus.yaml
```

```text
WARN: no stored fingerprint for 'orders'; treating as new
  no baseline fingerprint for 'orders'
  current: sha256:c48627e080df819eaad265fab62fe513958afa03da7c7ee1465dbe74ea8ef49c
```

After `schema-ack` has stored one:

```bash
nautilus adapters schema-diff orders --config nautilus.yaml
```

```text
OK: no drift for 'orders' (fingerprint matches)
```

```bash
nautilus adapters schema-diff orders --config nautilus.yaml --json
```

```text
{"status": "clean", "fingerprint": "sha256:c48627e080df819eaad265fab62fe513958afa03da7c7ee1465dbe74ea8ef49c"}
```

And with drift — add a `region: emea` field to the first row of the `orders`
source in `nautilus.yaml` to reproduce it:

```bash
nautilus adapters schema-diff orders --config nautilus.yaml
```

```text
  adapter : orders
  stored  : sha256:c48627e080df819eaad265fab62fe513958afa03da7c7ee1465dbe74ea8ef49c
  current : sha256:35f1f95945544ca08508c5ae9be964f55f043e5f513d64ed594adfd2c5bd611c
  DRIFT DETECTED
```

```bash
nautilus adapters schema-diff orders --config nautilus.yaml --json
```

```text
{"status": "drift", "stored": "sha256:c48627e080df819eaad265fab62fe513958afa03da7c7ee1465dbe74ea8ef49c", "current": "sha256:35f1f95945544ca08508c5ae9be964f55f043e5f513d64ed594adfd2c5bd611c"}
```

**Exit codes** — returns `0` **in every case**, including when it finds drift.
Never returns `1`, `2` (except from argparse, which is what a missing `--config`
produces) or `3`. Branch on the `status` field in `--json` mode — it is exactly
one of `no_baseline`, `clean` or `drift` — never on `$?`.

| Message | Exit | What to do |
|---------|------|------------|
| `WARN: no stored fingerprint for 'orders'; treating as new` | `0` | First run for this adapter. `schema-ack` stores the baseline. |
| `  DRIFT DETECTED` (after the stored and current digests) | `0` | The upstream schema changed. Review the diff, then `schema-ack` with a reason to accept it. |
| `WARN: no schema available for adapter '<name>'` | `0` | The id is not in the config's `sources` — a `WARN`, not an `ERROR`, because a missing adapter is not drift. |
| `nautilus adapters schema-diff: error: the following arguments are required: --config` | `2` | argparse; `--config` is `required=True` here even though it is optional on `schema` and `schema-fingerprint`. |

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

```bash
NAUTILUS_REVIEWER=alice nautilus adapters schema-ack orders \
  --config nautilus.yaml --reason 'upstream added a nullable column' --yes
```

```text
OK: schema-ack recorded for 'orders' by alice: upstream added a nullable column
```

**Exit codes** — returns `0` or `1`. Never returns `2` (except from argparse,
which is what a missing `--config` or `--reason` produces) and never returns `3`.

**Failure modes**

```bash
nautilus adapters schema-ack orders --config nautilus.yaml \
  --reason 'upstream added a nullable column'
```

```text
ERROR: schema-ack requires --yes to confirm
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: schema-ack requires --yes to confirm` | `1` | Add `--yes`. |
| `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.` | `1` | `export NAUTILUS_REVIEWER=<you>`; the identity is written into the audit event. |
| `ERROR: no schema available for adapter '<name>'; cannot ack` | `1` | Check the id with `nautilus adapters list`. |

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

```bash
nautilus key
```

```text
ERROR: key: no subcommand given (try: list, rotate, revoke)
```

Exit `1` — the only group whose missing-subcommand hint is a `1` rather than a
`2`. (`events` and `attestation` do the same; `rkm`, `rule`, `adapters` and
`rules` return `2`.)

All three subcommands share `--url`, `--api-key` and `--json`
(`nautilus.cli.key._add_target_args`):

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--url` | `str` | `None` | Base URL of the running broker whose signing ring to act on. Trailing slashes are stripped. |
| `--api-key` | `str` | `None` | `X-API-Key` for the broker. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

### `nautilus key list`

No additional arguments. Reads the **public** JWKS, so it needs no reviewer
identity — and, on a default config, no valid API key either: `--api-key` is
sent but the route does not require it.

Setup C:

```bash
nautilus key list --url http://127.0.0.1:8766 --api-key "$NAUTILUS_API_KEY"
```

```text
  cff81580-382a-44ee-ac13-542e36ffb360  kty=OKP  use=sig
```

```bash
nautilus key list --url http://127.0.0.1:8766 --api-key "$NAUTILUS_API_KEY" --json
```

```text
[{"kty": "OKP", "crv": "Ed25519", "kid": "cff81580-382a-44ee-ac13-542e36ffb360", "x": "IcwltX1JXDbgI-X6bukvQV2Il3gD56dTDS878PV_0Lk", "use": "sig"}]
```

A broker with session tokens disabled still answers, with an empty ring:
`no active keys (session tokens are disabled on this broker)`, exit `0`.

### `nautilus key rotate`

Mint a new primary key. In-flight session tokens keep verifying during the grace
window; agents are lazily re-signed on their next request (#25). Requires
`NAUTILUS_REVIEWER`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--yes` | flag (`store_true`) | `False` | Confirm the destructive operation. Required. |

Plus the shared `--url` / `--api-key` / `--json`.

Setup C:

```bash
NAUTILUS_REVIEWER=alice nautilus key rotate --yes \
  --url http://127.0.0.1:8766 --api-key "$NAUTILUS_API_KEY"
```

```text
OK: rotated: new primary kid=4dae7a63-5a86-4216-9eeb-fcf7e220c338  reviewer=alice
```

```bash
NAUTILUS_REVIEWER=alice nautilus key rotate --yes \
  --url http://127.0.0.1:8766 --api-key "$NAUTILUS_API_KEY" --json
```

```text
{"new_primary_kid": "492a94e4-b2ee-40b7-acd2-957cc855494b", "reviewer": "alice"}
```

### `nautilus key revoke`

Revoke a key immediately — no grace window. Requires `NAUTILUS_REVIEWER`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `kid` | `str` (positional) | — | **Required.** Key ID to revoke. Must be a UUID. |
| `--reason` | `str` | — | **Required.** Revocation reason. |
| `--yes` | flag (`store_true`) | `False` | Confirm the destructive operation. Required. |

Plus the shared `--url` / `--api-key` / `--json`.

Setup C:

```bash
NAUTILUS_REVIEWER=alice nautilus key revoke cff81580-382a-44ee-ac13-542e36ffb360 \
  --reason 'laptop lost' --yes --url http://127.0.0.1:8766 --api-key "$NAUTILUS_API_KEY"
```

```text
OK: revoked: kid=cff81580-382a-44ee-ac13-542e36ffb360  reason='laptop lost'  reviewer=alice
```

### Exit codes and failure modes (all three)

**Exit codes** — `list`, `rotate` and `revoke` return `0`, `1` or `2`. None of
them returns `3`.

| Exit | When |
|------|------|
| `0` | The broker answered 200 (`list` also returns `0` for an empty ring). |
| `1` | `--yes` missing on `rotate`/`revoke`, or `NAUTILUS_REVIEWER` unset. Also the `key` group's own missing-subcommand error. |
| `2` | `--url` omitted, the broker was unreachable, or it answered non-200. |

The order matters, and it is the opposite of `rkm queue approve`: here a missing
`--yes` is reported first, then `--url`, then `NAUTILUS_REVIEWER`.

```bash
nautilus key rotate
```

```text
ERROR: rotate requires --yes to confirm.
```

```bash
nautilus key revoke somekid --reason x
```

```text
ERROR: revoke requires --yes to confirm.
```

```bash
nautilus key list
```

```text
FAIL: key list: --url is required. Rotation and revocation are audited events the broker emits against the ring it is serving with, so there is nothing for the CLI to act on locally — point --url at the running broker (e.g. --url http://localhost:8000).
```

Rotating against a broker with `session_tokens.enabled: false` (Setup B):

```bash
NAUTILUS_REVIEWER=alice nautilus key rotate --yes \
  --url http://127.0.0.1:8765 --api-key "$NAUTILUS_API_KEY"
```

```text
ERROR: key rotate: server returned 409: {"detail":"session tokens are disabled (session_tokens.enabled: false)"}
```

Revoking something that is not a UUID (Setup C):

```bash
NAUTILUS_REVIEWER=alice nautilus key revoke nosuchkid --reason x --yes \
  --url http://127.0.0.1:8766 --api-key "$NAUTILUS_API_KEY"
```

```text
ERROR: key revoke: server returned 400: {"detail":"kid must be a UUID"}
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: key: no subcommand given (try: list, rotate, revoke)` | 2 | Name one of the three. |
| `ERROR: rotate requires --yes to confirm.` | `1` | Add `--yes`. |
| `ERROR: revoke requires --yes to confirm.` | `1` | Add `--yes`. |
| `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.` | `1` | `export NAUTILUS_REVIEWER=<you>`. Not required by `key list`. |
| `FAIL: key <cmd>: --url is required. Rotation and revocation are audited events the broker emits against the ring it is serving with, so there is nothing for the CLI to act on locally — point --url at the running broker (e.g. --url http://localhost:8000).` | `2` | Point `--url` at the broker. |
| `FAIL: key <cmd>: cannot reach <endpoint>: [Errno 111] Connection refused` | `2` | Nothing is listening there. Confirm with `nautilus health`. |
| `ERROR: key <cmd>: server returned 400: {"detail":"kid must be a UUID"}` | `2` | Copy the `kid` from `nautilus key list`, not from a log line. |
| `ERROR: key <cmd>: server returned 401: {"detail":"Invalid API key"}` | `2` | Wrong or missing `--api-key`. |
| `ERROR: key <cmd>: server returned 409: {"detail":"session tokens are disabled (session_tokens.enabled: false)"}` | `2` | There is no ring to rotate. Set `session_tokens.enabled: true` in the broker's config and restart it. |

---

## `nautilus rules`

Rule validation and testing — see
[Authoring Rules](../how-to/authoring-rules.md).

```bash
nautilus rules
```

```text
ERROR: rules: no subcommand given (try: validate, test, history)
```

Exit `2`.

### `nautilus rules validate`

Static validation, optionally followed by a sandbox replay.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `file` | `str` (positional) | — | **Required.** Path to the rule YAML file to validate. |
| `--sandbox` | flag (`store_true`) | `False` | Run a sandbox replay after static validation. |
| `--replay-n` | `int` | `1000` | Number of audit entries to replay in sandbox mode. |
| `--audit-log` | `str` | `None` | Audit log to replay in sandbox mode (default `./audit.jsonl`). |
| `--json` | flag (`store_true`) | `False` | Emit results as JSON. |

```bash
nautilus rules validate my-rules.yaml
```

```text
OK: my-rules.yaml
```

```bash
nautilus rules validate my-rules.yaml --json
```

```text
{
  "file": "my-rules.yaml",
  "ok": true,
  "errors": []
}
```

With `--sandbox`, one summary line per rule is printed before the verdict. This
needs an audit log with entries in it — Setup C's broker wrote 14:

```bash
nautilus rules validate my-rules.yaml --sandbox --replay-n 1000
```

```text
rule 'deny-finance-after-hours': replayed=3 fired=0 relaxations=0
OK: my-rules.yaml
```

(`replayed=3` of 14 lines: only entries carrying engine input facts can be
replayed.)

**Exit codes** — the command returns `0` or `1`; argparse can return `2`. Never
returns `3`.

| Exit | When |
|------|------|
| `0` | Valid (and, with `--sandbox`, the replay completed). |
| `1` | File not found, static validation failed, or the audit log named for the replay does not exist. |
| `2` | argparse only — e.g. a non-integer `--replay-n`. |

**Failure modes**

```bash
nautilus rules validate nope.yaml
```

```text
ERROR: file not found: nope.yaml
```

```bash
nautilus rules validate broken.yaml
```

```text
ERROR broken.yaml:1: Rule file does not compile: [fathom.compiler] parse rules failed: invalid ruleset in broken.yaml — 2 validation errors for RulesetDefinition
rules.0.name
  Value error, RuleDefinition.name name 'bad rule' is not a valid CLIPS identifier (must match [A-Za-z_][A-Za-z0-9_-]*) [type=value_error, input_value='bad rule', input_type=str]
    For further information visit https://errors.pydantic.dev/2.13/v/value_error
rules.0.then.action
  Input should be 'allow', 'deny', 'escalate', 'scope' or 'route' [type=enum, input_value='nope', input_type=str]
    For further information visit https://errors.pydantic.dev/2.13/v/enum Hint: Each 'when' condition takes slot + one of expression/bind/test. 'operator:'/'value:' are not condition keys.
```

```bash
nautilus rules validate my-rules.yaml --sandbox
```

```text
ERROR: audit log not found: audit.jsonl
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: file not found: <path>` | `1` | Check the path. |
| `ERROR <file>:<line>: <message>` (with ` Hint: <hint>` appended when the validator has one) | `1` | One entry per static error, on stderr. `--json` returns the same errors as `{"file", "line", "message"}` objects. |
| `ERROR: audit log not found: <path>` | `1` | `--sandbox` needs a log. Point `--audit-log` at the broker's `audit.path`, or drop `--sandbox`. The default is `./audit.jsonl` relative to the working directory. |

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

With no audit log to replay:

```bash
nautilus rules test --file my-rules.yaml --threshold 0.6
```

```text
WARN: rule 'deny-finance-after-hours': insufficient audit history (replayed 0 entries)
rule 'deny-finance-after-hours': score=0.90 fired=0/0 relaxations=0 shadow_flags=0
OK: my-rules.yaml score=0.90 (threshold 0.60)
```

With one (Setup C's log). The second `WARN:` accounts for the entries that were
skipped rather than silently dropping them:

```bash
nautilus rules test --file my-rules.yaml --audit-log ./audit.jsonl \
  --min-entries 100 --config nautilus.yaml
```

```text
WARN: rule 'deny-finance-after-hours': insufficient audit history (replayed 3 entries)
WARN: rule 'deny-finance-after-hours': 11 audit entries carry no engine input and were not replayed
rule 'deny-finance-after-hours': score=0.90 fired=0/3 relaxations=0 shadow_flags=0
OK: my-rules.yaml score=0.90 (threshold 0.60)
```

```bash
nautilus rules test --file my-rules.yaml --audit-log ./audit.jsonl --config nautilus.yaml --json
```

```text
{"file": "my-rules.yaml", "threshold": 0.6, "score": 0.9, "passed": true, "rules": [{"name": "deny-finance-after-hours", "score": 0.9, "breakdown": {"base": 1.0, "regression_penalty": -0.0, "relaxation_penalty": -0.0, "shadow_penalty": -0.0, "fire_rate_penalty": -0.1, "cascade_penalty": 0.0, "drift_penalty": 0.0}, "shadow_flags": [], "sandbox": {"replayed_n_actual": 3, "fired": 0, "regressions": 0, "relaxations": 0, "cascade_max": 0, "insufficient_history": true, "skipped_no_input_facts": 11, "skipped_drifted": 0}}]}
```

**Exit codes** — returns `0`, `1` or `2`. Never returns `3`. This is the one
command where `2` is an ordinary outcome rather than an operator mistake.

| Exit | When |
|------|------|
| `0` | The lowest per-rule score is at or above `--threshold`. |
| `1` | File not found, audit log not found, static validation failed, or a rule would not compile. |
| `2` | **The rule is valid but scored below `--threshold`.** This is the CI-failure code. |

**Failure modes**

```bash
nautilus rules test --file my-rules.yaml --threshold 0.99
```

```text
WARN: rule 'deny-finance-after-hours': insufficient audit history (replayed 0 entries)
rule 'deny-finance-after-hours': score=0.90 fired=0/0 relaxations=0 shadow_flags=0
ERROR: score 0.90 below threshold 0.99: my-rules.yaml
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: score <n> below threshold <t>: <file>` | `2` | Read the per-rule `breakdown` in `--json` mode: `fire_rate_penalty` means the rule almost never fires against the replayed history, `regression_penalty` means it changed decisions that were previously correct. |
| `ERROR: rule '<name>': proposed rule '<name>' does not compile: ... duplicate rule name '<module>::<name>'` | `1` | A rule of that name is already loaded from a shipped pack or a `user_rules_dirs` entry. Rename yours, or test it against a `--config` that does not load the colliding pack. |
| `WARN: rule '<name>': insufficient audit history (replayed <n> entries)` | — | The score is computed but weakly grounded. Pass `--audit-log` pointing at at least `--min-entries` entries. |
| `WARN: rule '<name>': <n> audit entries carry no engine input and were not replayed` | — | Governance events (approvals, retractions) hold no request facts. Only `request` and `handoff_declared` entries are replayable. |
| `WARN: no rules found in <file>` | — | The `rules:` list is empty. |
| `ERROR: cannot read rules config from <path>: <err>` | — | `--config` would not load; the run continues against the built-in ruleset only. |

### `nautilus rules history`

List lineage history for every rule in a module. Reads
`.nautilus/rkm/lineage` (`nautilus.cli.rules._DEFAULT_LINEAGE_DIR`).

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--module M` | `str` | — | **Required.** Module name to filter by (the `module:` key of the rule file). |
| `--json` | flag (`store_true`) | `False` | Emit results as JSON. |

Setup D, after an approval:

```bash
nautilus rules history --module nautilus-routing
```

```text
deny-finance-after-hours v1  proposer=pipeline  chain=(root)
```

`chain=` shows the `derived_from` chain; a rule with no ancestor prints
`(root)`, and ` [retired]` is appended to a retired version. Before anything is
promoted:

```bash
nautilus rules history --module nautilus-routing
```

```text
No lineage records found for module 'nautilus-routing'.
```

**Exit codes** — returns `0` in both cases. Never returns `1`, `3`, or `2`
except from argparse (a missing `--module`, which is `required=True`).

---

## `nautilus events`

Enumerate the audit `event_type` vocabulary. This is the runtime source of truth
for the set, paired with the `Literal` in `nautilus/core/models.py` by a
drift-guard test, so a value printed here is a value the audit log can contain.

```bash
nautilus events
```

```text
ERROR: events: no subcommand given (try: list)
```

Exit `1`.

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

```bash
nautilus events list --json
```

```text
["request", "handoff_declared", "attestation_emitted", "session_token_issued", "session_token_verification_failed", "signing_key_rotated", "signing_key_revoked", "proposal_emitted", "proposal_validated", "proposal_approved", "proposal_rejected", "proposal_promoted", "meta_rule_fired", "relationship_observed", "rule_promoted", "rule_retracted", "rule_rolled_back", "adapter_quarantined", "adapter_unquarantined", "schema_drift_detected", "schema_drift_severity_overridden"]
```

**Exit codes** — returns `0`. Never returns `1`, `2` (except from argparse) or
`3`: the list is a constant in the process, so there is no failure path.

---

## `nautilus attestation`

Offline verification of chained attestation logs — see
[Verify a token](../how-to/verify-a-token.md).

```bash
nautilus attestation
```

```text
ERROR: attestation: no subcommand given (try: verify)
```

Exit `1`.

### `nautilus attestation verify`

Check hash linkage and every line's EdDSA JWS in a log written by
`ChainedFileAttestationSink` (`attestation.sink.chained: true`). With
`--expected-head` or `--anchor-token` it also detects tail truncation against an
out-of-band anchor — the one attack a self-consistent chain cannot see, because
deleting the last N lines leaves a shorter chain that still verifies.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `log` | `str` (positional) | — | **Required.** Chained attestation JSONL log path. |
| `--pubkey` | `str` | `None` | Ed25519 public key PEM. Default: `<log>.pub.pem` beside the log, which is where the sink writes it. |
| `--expected-head` | `str` | `None` | Out-of-band mirrored line hash. Verification fails if that hash is absent from the log. |
| `--anchor-token` | `str` | `None` | Checkpoint JWS token; its checkpoint line must appear in the log. Checkpoints are written every `attestation.sink.checkpoint_interval` emissions. |
| `--json` | flag (`store_true`) | `False` | Emit JSON to stdout. |

Setup C, after the broker has been stopped (the sink holds an exclusive lock
while it runs):

```bash
nautilus attestation verify ./attest.jsonl
```

```text
OK: chain valid — 3 records, head 00d6f54408364b0632d2d7bedc2dc8e405aae3a676274e6550ea53930d57593e
```

```bash
nautilus attestation verify ./attest.jsonl --json
```

```text
{"ok": true, "count": 3, "head_seq": 4, "head_sha256": "00d6f54408364b0632d2d7bedc2dc8e405aae3a676274e6550ea53930d57593e", "error": null, "error_line": null, "anchor_ok": null, "log_id": "5efc6f69a2584cb28f0dcd5519549ca2"}
```

Pin the head you mirrored elsewhere; `(anchor ok)` is appended when it matches:

```bash
nautilus attestation verify ./attest.jsonl \
  --expected-head 00d6f54408364b0632d2d7bedc2dc8e405aae3a676274e6550ea53930d57593e
```

```text
OK: chain valid — 3 records, head 00d6f54408364b0632d2d7bedc2dc8e405aae3a676274e6550ea53930d57593e (anchor ok)
```

**Exit codes** — returns `0`, `1` or `2`. Never returns `3`. The split is
deliberate: `1` means *you* pointed it at the wrong file, `2` means the log
itself did not verify.

| Exit | When |
|------|------|
| `0` | The chain verified (`result.ok`). Includes `--json` mode, which prints the payload and *then* returns the code. |
| `1` | The log file or the public key file was not found — a setup error, not a verification failure. |
| `2` | The chain did not verify: broken linkage, a bad signature, or a missing anchor. |

**Failure modes**

```bash
nautilus attestation verify ./nope.jsonl
```

```text
ERROR: attestation verify: log not found: nope.jsonl
```

```bash
nautilus attestation verify ./attest.jsonl --pubkey ./nope.pem
```

```text
ERROR: attestation verify: pubkey not found: nope.pem
```

Edit any line of the log and the chain breaks at the line *after* it, because
each line commits to the hash of the whole previous line:

```bash
nautilus attestation verify ./attest-tampered.jsonl
```

```text
ERROR: attestation verify: broken chain at line 3: prev_sha256 'a6fc90aa7aa1788d3430045671cada67a27b881f874cd879cf25bfe7038623d6' does not match previous line hash 'aee538a0202ce346533bebf016b171a2013822f2888154bce143fb1715cfe83b'
```

```bash
nautilus attestation verify ./attest.jsonl \
  --expected-head 0000000000000000000000000000000000000000000000000000000000000000
```

```text
ERROR: attestation verify: expected head '0000000000000000000000000000000000000000000000000000000000000000' not present in log — tail truncated?
```

| Message | Exit | What to do |
|---------|------|------------|
| `ERROR: attestation verify: log not found: <path>` | `1` | Check the path against `attestation.sink.path`. The message normalises the path (no leading `./`). |
| `ERROR: attestation verify: pubkey not found: <log>.pub.pem` | `1` | The public key is written beside the log by the sink. Copy it alongside, or pass `--pubkey`. |
| `ERROR: attestation verify: broken chain at line <n>: prev_sha256 '<a>' does not match previous line hash '<b>'` | `2` | Line `n-1` was edited, or a line was inserted or removed. Treat the log as compromised from `n-1` onward; the lines before it still verify. |
| `ERROR: attestation verify: signature claims mismatch at line <n>: signed {...}, computed {...}` | `2` | The line's own JWS no longer covers its content — the record was edited without re-signing. The two dicts are the signed and recomputed claims (`seq`, `prev_sha256`, `record_sha256`, `log_id`, `v`); compare them to see which field moved. |
| `ERROR: attestation verify: expected head '<hash>' not present in log — tail truncated?` | `2` | The chain is internally consistent but does not reach the head you mirrored. Lines were removed from the end. Compare `head_seq` in `--json` mode against the sequence you anchored. |
| `ERROR: attestation verify: anchor checkpoint line not present in log — tail truncated?` | `2` | Same as above, for `--anchor-token`: the checkpoint the token names is not in the log. |

---

## Argparse-level errors

Errors argparse raises itself, before any command code runs, go to stderr and
exit `2`. This is true of every one of the 41 parsers.

```bash
nautilus bogus
```

```text
usage: nautilus [-h] command ...
nautilus: error: argument command: invalid choice: 'bogus' (choose from version, session, health, serve, demo, init, rkm, rule, adapters, key, rules, events, attestation)
```

```bash
nautilus
```

```text
usage: nautilus [-h] command ...
nautilus: error: the following arguments are required: command
```

```bash
nautilus rkm queue approve --url http://127.0.0.1:8767
```

```text
usage: nautilus rkm queue approve [-h] [--note NOTE] [--json] [--url URL]
                                  [--api-key API_KEY] [--config CONFIG]
                                  proposal_id
nautilus rkm queue approve: error: the following arguments are required: proposal_id
```

The root parser and `session` are the only two that declare `required=True` on
their subparsers, so those two produce argparse's `the following arguments are
required` for a missing subcommand. The other groups (`rkm`, `rkm queue`,
`rule`, `adapters`, `key`, `rules`, `events`, `attestation`) handle a missing
subcommand in their own dispatch and emit the `ERROR:` hints documented in each
section — `1` for `key`, `events` and `attestation`, `2` for the rest.
