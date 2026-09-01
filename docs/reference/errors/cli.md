# Command line

## Conventions

Diagnostics go to **stderr** with a fixed prefix (`nautilus/cli/_common.py:88-101`):
`ERROR: `, `WARN: `, `FAIL: `. There are no Unicode sigils and no colour. `OK: ` marks
success.

Exit codes (`nautilus/cli/_common.py:5-7`): **0** success, **1** user error, **2**
validation/policy failure. Code **3** is deliberately never used.

Anything wrapped in `{…}` interpolates; `{exc}` is a lower-level error passed through unchanged.

## Any governance subcommand

### `ERROR: NAUTILUS_REVIEWER env var required for this command. Set it to your operator identity.`

`require_reviewer`, `nautilus/cli/_common.py:28-35`. Exit **1**.

**Means.** A command that records a governance decision has no operator identity to record. The
value comes from the environment only — there is no `$USER` auto-detection, because a reviewer
identity that the tool guesses is not evidence of anything.

**Fix.** `export NAUTILUS_REVIEWER="your.name@example.com"`.

```bash
env -u NAUTILUS_REVIEWER python - <<'PY'
from nautilus.cli._common import require_reviewer
try:
    require_reviewer()
except SystemExit as exc:
    print("exit code:", exc.code)
PY
```

## `nautilus serve`

`nautilus/cli/__init__.py:209-280` and `nautilus/cli/serve.py`. All of these exit **2**.

| Message | Line |
| --- | --- |
| `ERROR: config path does not exist or is not a file: {config_path}` | `__init__.py:210` |
| `ERROR: invalid config: {exc}` | `__init__.py:238` |
| `ERROR: broker construction failed: {exc}` | `__init__.py:241` |
| `ERROR: {exc}` (bind parsing, air-gapped load, serve failure) | `__init__.py:218,227,275` |

The wrapped `{exc}` texts:

### `--bind must be HOST:PORT, got {bind!r}`

**`ValueError`**, `nautilus/cli/serve.py:20-26`, printed as `ERROR: --bind must be HOST:PORT,
got 'badbind'`. Raised when the value has no `:` or an empty half.

### `--bind port must be an integer, got {port_s!r}`

`nautilus/cli/serve.py:27-29`.

### `Unable to read config '{config_path}': {exc}`

**`RuntimeError`**, `nautilus/cli/serve.py:123-125`, from the `--air-gapped` pre-pass that reads
the YAML before the broker does.

### `application startup failed; the server never accepted a connection. The cause is logged above.`

**`RuntimeError`**, `nautilus/cli/serve.py:162-166`. uvicorn returns from `serve()` rather than
raising when a lifespan fails, so without this the process exited **0** after never serving a
request. The real cause — a `ConfigError`, an unreachable session store — is in the log lines
directly above.

```bash
nautilus serve --config /nonexistent/nautilus.yaml; echo "exit=$?"
```

### `--air-gapped` warnings

`--air-gapped` strips anything that would leave the host. Each removal is announced on stderr
(`nautilus/cli/serve.py:60-105`); none is fatal.

| Message |
| --- |
| `WARN: --air-gapped drops LLM source id={…!r} — connection host is not loopback (NFR-1, #43)` |
| `WARN: --air-gapped overrides analysis.mode from {current_mode!r} to 'pattern' (NFR-1)` |
| `WARN: --air-gapped refuses analysis.provider (type={provider_type!r}); dropping it (NFR-1)` |

If a source you rely on is silently missing under `--air-gapped`, this is why.

## `nautilus health`

`nautilus/cli/health.py:15-28`. Exit **0** only on HTTP 200.

| Message | Line | Meaning |
| --- | --- | --- |
| `FAIL {status} {url}` | `:21` | The endpoint answered with a non-200 status. For `/readyz` the body carries the `reason` — see [transport.md](transport.md). |
| `FAIL {exc.code} {url}` | `:24` | An `HTTPError`: the code is `{exc.code}`. |
| `FAIL unreachable {url}: {exc}` | `:27` | The connection never completed. `{exc}` is the `URLError` — connection refused, DNS failure, timeout. |

```bash
nautilus health --url http://127.0.0.1:1/readyz; echo "exit=$?"
```

## `nautilus rules`

`nautilus/cli/rules.py`. Three subcommands: `validate` (static check), `test` (static check plus
a sandbox replay and a score) and `history`.

For the per-rule compiler diagnostics — `ERROR {file}:{line}: {message}` and
`ERROR: rule {name!r}: {exc}` — see [rules.md](rules.md).

### `ERROR: file not found: {file_path}`

`nautilus/cli/rules.py:149` (`validate`) and `:265` (`test`). Exit **1**. `{file_path}` is the
positional `file` argument of `validate`, or the `--file` value of `test`, with `str()`.

```bash
nautilus rules validate /nope.yaml; echo "exit=$?"
nautilus rules test --file /nope.yaml; echo "exit=$?"
```

### `ERROR: audit log not found: {audit_path}`

`nautilus/cli/rules.py:188` (`validate --sandbox`) and `:271` (`test --audit-log`). Exit **1**.
`{audit_path}` is the `--audit-log` value, defaulting to `./audit.jsonl` relative to the working
directory — not to the rule file.

**Means.** The sandbox stage replays real past requests against the candidate rule to find
regressions. Without a log there is nothing to replay.

**Fix.** Point `--audit-log` at the broker's `audit.path`, or drop `--sandbox` to run the static
check alone. `test` checks the log before it compiles the rule, so this fires even on a rule file
that would not compile; `validate --sandbox` compiles first.

```bash
cd /tmp/nautilus-errors && nautilus rules test --file rule.yaml --audit-log /nope.jsonl; echo "exit=$?"
```

### `ERROR: cannot read rules config from {path}: {exc}`

`nautilus/cli/rules.py:421`. Exit **1**, raised as `SystemExit(1)` rather than returned.
`{path}` is the `--config` value; `{exc}` is the loader failure — look it up in
[config.md](config.md). The CLI needs `rules.packs` and `rules.user_rules_dirs` from that config
to know which rules the candidate is being compiled alongside.

<!-- not-executed: reached only after the rule file compiles -->
```bash
: > /tmp/n-bad.yaml
nautilus rules test --file rule-packs/cve-rem-cmdb-substrate/rules/library-allow.yaml \
  --config /tmp/n-bad.yaml --audit-log /tmp/nautilus-errors/audit.jsonl; echo "exit=$?"
```

### `ERROR: score {min_total} below threshold {threshold}: {file_path}`

`nautilus/cli/rules.py:400`. Exit **2** — a policy failure, not a usage error. Both numbers are
formatted to two decimals (`{min_total:.2f}`, `{threshold:.2f}`), so the rendered line reads
`ERROR: score 0.42 below threshold 0.70: my_rule.yaml`. `{min_total}` is the **lowest** score
across every rule in the file, so one weak rule fails the file. `{threshold}` is `--threshold`.

**Means.** The rule compiles and replays without regression, but scores below the bar — coverage,
specificity and replay evidence all feed the score. On success the same command prints
`OK: {file_path} score={min_total:.2f} (threshold {threshold:.2f})` and exits **0**.

**Fix.** Tighten the rule, or replay against more history (`--replay-n`, `--min-entries`) so the
evidence term is not starved.

<!-- not-executed: reached only after the rule file compiles and replays -->
```bash
nautilus rules test --file rule-packs/cve-rem-cmdb-substrate/rules/library-allow.yaml \
  --audit-log /tmp/nautilus-errors/audit.jsonl --threshold 1.0; echo "exit=$?"
```

### `WARN: rule '{name}': shadow finding {relation} (existing rule '{existing_rule}')`

`nautilus/cli/rules.py:372-375`. **Exit 0**. `{name}` is the candidate rule; `{relation}` is how
it overlaps an installed rule (for example `subsumes`, `subsumed_by`, `conflicts`);
`{existing_rule}` is that installed rule's name. The candidate is not wrong, but one of the two is
redundant or contradictory once both are in force.

### `WARN: rule '{name}': insufficient audit history (replayed {replayed_n_actual} entries)`

`nautilus/cli/rules.py:377-380`. **Exit 0**. `{replayed_n_actual}` is how many audit entries
actually replayed, against the `--min-entries` floor. The score is still printed, but its
regression evidence is thin — a rule that denies nothing in ten replays has not been tested.

**Fix.** Replay against more history: raise `--replay-n`, or point `--audit-log` at a longer log.

### `WARN: rule '{name}': {skipped_drifted} audit entries could not be replayed -- the current rules no longer reproduce what they recorded`

`nautilus/cli/rules.py:381-385`. **Exit 0**. Note the ASCII double hyphen `--`, not an em dash.
`{skipped_drifted}` is the count of entries dropped from the replay.

**Means.** Those entries were recorded under a rule set that no longer exists, so replaying them
would compare the candidate against a decision the engine can no longer make. They are skipped
rather than counted as regressions.

### `WARN: rule '{name}': {skipped_no_input_facts} audit entries carry no engine input and were not replayed`

`nautilus/cli/rules.py:386-390`. **Exit 0**. `{skipped_no_input_facts}` is the count of entries
with no recorded engine input — entries written before input capture, or by a path that does not
record it. There is nothing to feed the candidate rule.

### `WARN: no rules found in {file_path}`

`nautilus/cli/rules.py:297`. **Exit 0**. The file parsed but declared no rules — usually a YAML
list that is empty, or keys at the wrong nesting depth. Nothing was scored.

### `WARN: could not read audit path from {config_path!r} ({exc}); using {path}`

`nautilus/cli/_common.py:79`, shared by every governance subcommand that resolves an audit sink.
**Exit 0** — the decision is still recorded, but in the default `./audit.jsonl` rather than the
path your config names. `{config_path}` is `repr()`-quoted, `{exc}` is the loader failure,
`{path}` is the fallback actually used.

**Means.** A governance record went somewhere you were not expecting. If a later
`nautilus rule lineage` cannot find the decision, this warning is why.

## `nautilus session version`

See [sessions.md](sessions.md).

## A missing subcommand

Every command group answers a bare invocation with its own sentence naming the subcommands it
accepts. The exit code is **not** uniform, and the split is worth knowing if you script these:
`rkm`, `rule`, `rules` and `adapters` exit **2**; `key`, `attestation` and `events` exit **1**.

### `ERROR: rkm: no subcommand given (try: queue, lineage)`

`nautilus/cli/rkm.py:151`. Exit **2**. No interpolation.

```bash
nautilus rkm; echo "exit=$?"
```

### `ERROR: rkm queue: no op given (try: submit, list, show, approve, reject, diff)`

`nautilus/cli/rkm.py:177`. Exit **2**. No interpolation. `queue` is a group of its own, so
`nautilus rkm queue` is as incomplete as `nautilus rkm`.

```bash
nautilus rkm queue; echo "exit=$?"
```

### `ERROR: rule: no subcommand given (try: list, retract, lineage, history, rollback)`

`nautilus/cli/rule.py:125`. Exit **2**. No interpolation.

```bash
nautilus rule; echo "exit=$?"
```

### `ERROR: rules: no subcommand given (try: validate, test, history)`

`nautilus/cli/rules.py:126`. Exit **2**. No interpolation. Reached when
`args.rules_subcommand` is neither `validate`, `test` nor `history` — in practice, when you typed
`nautilus rules` and stopped. A *misspelled* subcommand never gets this far: argparse rejects the
choice itself and prints its own usage line.

```bash
nautilus rules; echo "exit=$?"
```

### `ERROR: adapters: no subcommand given (try: new, list, schema, schema-fingerprint, schema-diff, schema-ack)`

`nautilus/cli/adapters.py:121-124`. Exit **2**. No interpolation.

```bash
nautilus adapters; echo "exit=$?"
```

### `ERROR: key: no subcommand given (try: list, rotate, revoke)`

`nautilus/cli/key.py:73`. Exit **2**. No interpolation.

```bash
nautilus key; echo "exit=$?"
```

### `ERROR: attestation: no subcommand given (try: verify)`

`nautilus/cli/attestation.py:60`. Exit **2**. No interpolation. `verify` is the only subcommand;
signing happens inside the broker, never in the CLI.

```bash
nautilus attestation; echo "exit=$?"
```

### `ERROR: events: no subcommand given (try: list)`

`nautilus/cli/events.py:66`. Exit **2**. No interpolation.

```bash
nautilus events; echo "exit=$?"
```

## `nautilus init`

`nautilus/cli/init.py:80-95`. Writes `nautilus.yaml` with a freshly generated API key into
`--dir` (default `.`).

### `ERROR: {target} already exists — refusing to overwrite it`

`nautilus/cli/init.py:83`. Exit **1**. `{target}` is `Path(--dir) / "nautilus.yaml"`, printed
with `str()` — the path as you spelled it, not resolved: `--dir /tmp/n-init` prints
`/tmp/n-init/nautilus.yaml`.

**Means.** `init` never merges and never backs up. The existing file may hold a key that real
agents authenticate with, so overwriting it is a credential rotation nobody asked for.

**Fix.** Write elsewhere (`nautilus init --dir ./fresh`), or move the existing file aside first.

```bash
mkdir -p /tmp/n-init && : > /tmp/n-init/nautilus.yaml
nautilus init --dir /tmp/n-init; echo "exit=$?"
```

## `nautilus key`

`nautilus/cli/key.py`. All three subcommands talk to a **running broker** over HTTP; none of them
touches a config file. The `keys` capability is required on the key you pass to `--api-key`.

### `FAIL: key {command}: --url is required. Rotation and revocation are audited events the broker emits against the ring it is serving with, so there is nothing for the CLI to act on locally — point --url at the running broker (e.g. --url http://localhost:8000).`

`nautilus/cli/key.py:82-87` (`_require_url`). Exit **2**, and it is a `FAIL: ` line, not
`ERROR: `, because the missing piece is a network endpoint. `{command}` is the literal
subcommand name: `list`, `rotate` or `revoke`.

**Means.** The signing ring lives in the broker process. A CLI that edited a file on disk would
mint keys the running broker never learns about.

**Fix.** Pass `--url` and a `keys`-capable `--api-key`.

```bash
nautilus key rotate --yes; echo "exit=$?"
nautilus key rotate --yes --url "$NAUTILUS" --api-key govern-key; echo "exit=$?"
```

### `ERROR: rotate requires --yes to confirm.`

`nautilus/cli/key.py:154`. Exit **1**. No interpolation. Checked **before** `--url` and before
`NAUTILUS_REVIEWER`, so this is the first thing a bare `nautilus key rotate` says.

**Means.** Rotation changes which key signs new session tokens. Old tokens keep verifying — only
revocation is retroactive — but the change is a governance event either way.

```bash
nautilus key rotate; echo "exit=$?"
```

### `ERROR: revoke requires --yes to confirm.`

`nautilus/cli/key.py:179`. Exit **1**. No interpolation.

**Means.** Revocation *is* retroactive: every session token already minted under that `kid` stops
verifying with reason code `unknown_kid` (see
[session-tokens.md](session-tokens.md#key-kidr-has-been-revoked)).

```bash
nautilus key revoke 00000000-0000-4000-8000-000000000000 --reason leaked; echo "exit=$?"
```

### `FAIL: key {command}: cannot reach {endpoint}: {exc}`

`nautilus/cli/key.py:127`. Exit **2**. `{command}` is `list`, `rotate` or `revoke`; `{endpoint}`
is the full URL the CLI built (`{--url}/v1/keys`, `/v1/keys/rotate`, `/v1/keys/{kid}/revoke`);
`{exc}` is the `httpx.HTTPError` — connection refused, DNS failure, TLS error, timeout.

```bash
nautilus key list --url http://127.0.0.1:1; echo "exit=$?"
```

### `ERROR: key {command}: server returned {status_code}: {text}`

`nautilus/cli/key.py:130`. Exit **2**. The broker answered, and answered something other than
200. `{status_code}` is the HTTP status; `{text}` is the raw response body, normally
`{"detail": "..."}` — look that sentence up in [auth.md](auth.md) (401/403) or
[attestation.md](attestation.md) (400/404/409). The commonest cause is a key without the `keys`
capability.

```bash
nautilus key list --url "$NAUTILUS" --api-key query-key; echo "exit=$?"
```

## `nautilus rule`

`nautilus/cli/rule.py`. Local lineage operations against the audit log — no broker needed.
`retract` and `rollback` are destructive and require `--yes` and `NAUTILUS_REVIEWER`.

### `ERROR: --yes required for destructive op`

`nautilus/cli/rule.py:160` (retract) and `:270` (rollback). Exit **1**. No interpolation. The same
sentence for both, and it is checked first, before `--reason` and before the reviewer identity.

```bash
nautilus rule retract some_rule --reason "superseded"; echo "exit=$?"
nautilus rule rollback some_rule --to-version 1 --reason "bad deploy"; echo "exit=$?"
```

### `ERROR: --reason required for retract`

`nautilus/cli/rule.py:163`. Exit **1**. No interpolation. `--reason` is `required=True` in
argparse, so omitting the flag entirely gets argparse's own message and exit 2; this sentence is
what a *blank* reason gets — the value is `.strip()`ed before the check.

```bash
nautilus rule retract some_rule --reason '   ' --yes; echo "exit=$?"
```

### `ERROR: --cascade and --orphan-children are mutually exclusive`

`nautilus/cli/rule.py:166`. Exit **1**. No interpolation.

**Means.** A retracted rule may have descendants in the lineage DAG. `--cascade` retracts them
too; `--orphan-children` leaves them in force with a dangling parent. Asking for both is not a
policy.

**Fix.** Pick one. Passing neither is legal and means "retire only the named rule".

```bash
nautilus rule retract some_rule --reason r --yes --cascade --orphan-children; echo "exit=$?"
```

### `ERROR: rule {name!r} not found in lineage`

`nautilus/cli/rule.py:183`. Exit **1**. `{name}` is the positional rule name, `repr()`-quoted:
`rule 'no_such_rule' not found in lineage`. The lineage store is the audit log resolved by
`audit_path_for()` — `--config`'s `audit.path`, else `./audit.jsonl` in the working directory.
A rule that exists in a YAML file but was never promoted has no lineage record.

```bash
cd /tmp/nautilus-errors && nautilus rule retract no_such_rule --reason r --yes; echo "exit=$?"
```

### `ERROR: rule {name!r} v{to_version} not found in lineage`

`nautilus/cli/rule.py:287`. Exit **1**. `{name}` is `repr()`-quoted, `{to_version}` is the
integer from `--to-version` with no `v` prefix of its own — the `v` in the message is literal:
`rule 'my_rule' v7 not found in lineage`. Use `nautilus rule history my_rule` to see which
versions exist.

```bash
cd /tmp/nautilus-errors && nautilus rule rollback my_rule --to-version 999 --reason r --yes; echo "exit=$?"
```

### `WARN: affected descendants: {names}`

`nautilus/cli/rule.py:197`. **Exit 0** — `retract --cascade` succeeded. `{names}` is the affected
rule names joined with `", "`. Every rule listed was retracted too; this is the record of what
else stopped being enforced.

### `WARN: no lineage records for {name!r}` / `WARN: no history for {name!r}`

`nautilus/cli/rule.py:206` and `:245`. **Exit 0** — these are warnings, not failures.
`nautilus rule lineage` and `nautilus rule history` answer with an empty result rather than an
error, so a script checking only the exit code will not notice.

```bash
cd /tmp/nautilus-errors && nautilus rule history never_promoted; echo "exit=$?"
```

## `nautilus rkm`

`nautilus/cli/rkm.py`. The review queue. `submit`, `list`, `show`, `reject` and `diff` work
against the local audit log; `approve` is the only one that requires a running broker.

### `ERROR: rule file not found: {rule_path}`

`nautilus/cli/rkm.py:194`. Exit **1**. `{rule_path}` is the `--file` value with `str()`, not
resolved. This is `submit` reading the rule YAML it is about to propose.

```bash
nautilus rkm queue submit --file /nope.yaml; echo "exit=$?"
```

### `ERROR: rkm queue approve: --url is required. Approving promotes the rule into the engine of a running broker, so there is nothing for the CLI to approve locally — point --url at the broker (e.g. --url http://localhost:8000).`

`nautilus/cli/rkm.py:316-320`. Exit **2**. No interpolation. `NAUTILUS_REVIEWER` is checked
*first*, so an unset reviewer identity masks this message until you set it.

**Fix.** Point `--url` at the broker whose engine should start enforcing the rule, and pass a
`govern`-capable `--api-key`.

```bash
NAUTILUS_REVIEWER=you@example.com nautilus rkm queue approve prop_deadbeef; echo "exit=$?"
```

### `ERROR: rkm queue approve: cannot reach {endpoint}: {exc}`

`nautilus/cli/rkm.py:336`. Exit **2**. `{endpoint}` is
`{--url}/v1/rkm/queue/{proposal_id}/approve`; `{exc}` is the `httpx.HTTPError`. Nothing was
decided — the proposal is still pending, so retrying is safe.

```bash
NAUTILUS_REVIEWER=you@example.com nautilus rkm queue approve prop_deadbeef --url http://127.0.0.1:1; echo "exit=$?"
```

### `ERROR: proposal {proposal_id} not found`

`nautilus/cli/rkm.py:289`, `:347`, `:370`, `:387`, `:411`. Exit **1**. `{proposal_id}` is the
positional argument with `str()` — **not** `repr()`-quoted, unlike the HTTP route's
`proposal not found: {proposal_id!r}` in [rules.md](rules.md#proposal-not-found-proposal_idr).
`:347` is the local rendering of the broker's own 404 during `approve`; the rest are local
lookups in the audit log.

**Fix.** `nautilus rkm queue list` prints the IDs that exist. IDs have the form `prop_<hex>`.

```bash
cd /tmp/nautilus-errors && nautilus rkm queue show prop_notreal; echo "exit=$?"
```

### `ERROR: proposal {proposal_id} already decided: status={current_status}`

`nautilus/cli/rkm.py:384`, from `AlreadyDecidedError`. Exit **1**. `{proposal_id}` is the
positional argument; `{current_status}` is the proposal's status — `approved`, `rejected` or
`superseded`. Decisions are terminal: there is no un-reject.

Note the asymmetry with `approve`, which treats an already-decided proposal as success: a 409 from
the broker prints `OK: proposal {id} already decided` and exits **0** (`nautilus/cli/rkm.py:339-345`),
so re-running an approval is idempotent while re-running a rejection is an error.

```bash
cd /tmp/nautilus-errors && nautilus rkm queue reject prop_notreal --reason r; echo "exit=$?"
```

### `ERROR: rkm queue approve: server returned {status_code}: {text}`

`nautilus/cli/rkm.py:350`. Exit **2**. Any broker response that is not 200, 404 or 409.
`{status_code}` is the HTTP status; `{text}` is the raw body. The one you are most likely to see
is **422** with a JSON object carrying `error`, `message`, `current_status` and `recovery` — a
promotion that could not be made real. Its `recovery` field tells you what to change; the causes
are listed in [rules.md](rules.md#promotion).

```bash
NAUTILUS_REVIEWER=you@example.com nautilus rkm queue approve prop_deadbeef \
  --url "$NAUTILUS" --api-key govern-key; echo "exit=$?"
```

### `WARN: could not read rkm settings from {config_path!r} ({exc}); using defaults`

`nautilus/cli/rkm.py:242`. **Exit 0** — the submission still happens, with default RKM settings.
`{config_path}` is `repr()`-quoted; `{exc}` is the loader error. If a proposal behaved as though
your `rkm:` block were absent, this line is why.

### `WARN: no lineage records for {id!r}`

`nautilus/cli/rkm.py:470`. **Exit 0**. `{id}` is the positional argument of
`nautilus rkm lineage`, which accepts either a proposal ID or a rule name.

## `nautilus adapters`

`nautilus/cli/adapters.py`. Two modes: `--config` reads a `nautilus.yaml` and constructs adapters
locally; `--url` asks a running broker. They answer different questions and are not
interchangeable.

### `ERROR: invalid adapter name {name!r} (expected lowercase-dashed, e.g. my-csv-adapter)`

`nautilus/cli/adapters.py:226`. Exit **1**. `{name}` is the positional argument, `repr()`-quoted.
The name becomes a Python distribution name and a package directory, so uppercase, underscores
and leading digits are refused.

```bash
nautilus adapters new My_Adapter; echo "exit=$?"
```

### `ERROR: destination already exists and is not empty: {dest}`

`nautilus/cli/adapters.py:231`. Exit **1**. `{dest}` is `Path(--dir) / name` with `str()`.
An *empty* directory of that name is fine — scaffolding proceeds into it.

```bash
mkdir -p /tmp/n-ad/my-csv-adapter && : > /tmp/n-ad/my-csv-adapter/x
nautilus adapters new my-csv-adapter --dir /tmp/n-ad; echo "exit=$?"
```

### `ERROR: copier is required for 'adapters new' — install it with: pip install copier`

`nautilus/cli/adapters.py:237`. Exit **1**. No interpolation. `copier` renders the bundled
template and is not a runtime dependency of Nautilus, so it is absent from a normal install.

```bash
pip install copier && nautilus adapters new my-csv-adapter --dir /tmp/n-ad
```

### `ERROR: no config found: pass --config PATH, or run from a directory containing nautilus.yaml`

`nautilus/cli/adapters.py:278-281` and `:457`. Exit **1**. No interpolation. The implicit lookup
is `./nautilus.yaml` in the process's working directory — not the config the broker is serving
with, and not `$NAUTILUS_CONFIG`.

```bash
cd /tmp && nautilus adapters list; echo "exit=$?"
cd /tmp/nautilus-errors && nautilus adapters list; echo "exit=$?"
```

### `ERROR: --status {status_filter!r} needs --url: quarantine state lives in the serving process, so a config file cannot answer it. Reporting an empty list here would look like 'nothing is quarantined'.`

`nautilus/cli/adapters.py:270-274`. Exit **1**. `{status_filter}` is the `--status` value,
`repr()`-quoted.

**Means.** Quarantine is decided at runtime by the broker as adapters fail. A config file
describes what *could* be constructed, not what is currently healthy, so answering from it would
be a confident lie.

**Fix.** `nautilus adapters list --status quarantined --url "$NAUTILUS" --api-key query-key`.

```bash
nautilus adapters list --status quarantined --config /tmp/nautilus-errors/nautilus.yaml; echo "exit=$?"
```

### `ERROR: could not load {config_path}: {exc}`

`nautilus/cli/adapters.py:317`. Exit **1**. `{config_path}` is the resolved config path;
`{exc}` is the `ConfigError` or `OSError` from the loader — look that sentence up in
[config.md](config.md).

```bash
: > /tmp/n-bad.yaml && nautilus adapters list --config /tmp/n-bad.yaml; echo "exit=$?"
```

### `ERROR: could not reach {url}: {exc}`

`nautilus/cli/adapters.py:337`. Exit **1**. `{url}` is the `--url` value; `{exc}` is the
`httpx.HTTPError`.

```bash
nautilus adapters list --url http://127.0.0.1:1; echo "exit=$?"
```

### `ERROR: no schema available for adapter {name!r}`

`nautilus/cli/adapters.py:346` (`adapters schema`) and `:364`
(`adapters schema-fingerprint`). Exit **1**. `{name}` is `repr()`-quoted. With `--json`, `null`
is still printed on stdout before the non-zero exit, so a JSON consumer gets valid JSON either
way.

**Means.** The adapter does not implement `get_schema()`, or it returned nothing. The HTTP
equivalent is `501 Adapter '{name}' does not support schema introspection`
(see [transport.md](transport.md#adapter-name-does-not-support-schema-introspection)).

The scratch broker cannot reproduce this: its `notes` source is a static adapter, which *does*
implement `get_schema()` and exits **0** with the schema. Use that as the positive control, then
try the adapter that failed.

```bash
cd /tmp/nautilus-errors && nautilus adapters schema notes --config nautilus.yaml; echo "exit=$?"
cd /tmp/nautilus-errors && nautilus adapters schema no_such_source --config nautilus.yaml; echo "exit=$?"
```

### `ERROR: no schema available for adapter {name!r}; cannot ack`

`nautilus/cli/adapters.py:428`. Exit **1**. The same condition reached from `schema-ack`: there
is no current fingerprint to record an acknowledgement against. Checked **after** `--yes` and
after `NAUTILUS_REVIEWER`.

<!-- not-executed: needs an adapter without get_schema(); the scratch broker's static source has one -->
```bash
cd /tmp/nautilus-errors && NAUTILUS_REVIEWER=you@example.com \
  nautilus adapters schema-ack no_such_source --config nautilus.yaml --reason "drift ok" --yes; echo "exit=$?"
```

### `ERROR: schema-ack requires --yes to confirm`

`nautilus/cli/adapters.py:420`. Exit **1**. No interpolation. Acknowledging drift writes a new
fingerprint, which silences `schema-diff` for that adapter until the schema changes again.

```bash
nautilus adapters schema-ack notes --config /tmp/nautilus-errors/nautilus.yaml --reason r; echo "exit=$?"
```

### `WARN: could not read schema for {name!r}: {exc}`

`nautilus/cli/adapters.py:179`. **Exit 0**. `adapters list` reports every adapter it can and warns
about the ones whose schema it could not read, rather than failing the whole listing.

### `WARN: no stored fingerprint for {name!r}; treating as new`

`nautilus/cli/adapters.py:383`. **Exit 0**, from `schema-diff`. There is nothing to compare
against yet — the first `schema-diff` for an adapter always says this. Run `schema-ack` to store
the baseline.

## `nautilus attestation verify`

`nautilus/cli/attestation.py`. Offline verification of a chained attestation log: hash chain plus
JWS signatures, with no broker running.

### `ERROR: attestation verify: log not found: {log_path}`

`nautilus/cli/attestation.py:76`. Exit **1**. `{log_path}` is the positional `log` argument with
`str()`.

```bash
nautilus attestation verify /nope.jsonl; echo "exit=$?"
```

### `ERROR: attestation verify: pubkey not found: {pubkey_path}`

`nautilus/cli/attestation.py:79`. Exit **1**. `{pubkey_path}` is `--pubkey` if you passed it, and
otherwise the default `<log>.pub.pem` beside the log — so verifying `audit.jsonl` with no
`--pubkey` reports `audit.jsonl.pub.pem`, a file you may never have been told to create.

**Fix.** Pass `--pubkey` explicitly, or place the broker's Ed25519 public key PEM beside the log
under that name.

```bash
cd /tmp/nautilus-errors && : > chain.jsonl && nautilus attestation verify chain.jsonl; echo "exit=$?"
```

### `ERROR: attestation verify: {result.error}`

`nautilus/cli/attestation.py:95`. Exit **2** — verification ran and failed, which is a policy
failure, not a usage error. `{result.error}` is the first failure the verifier found: a broken
hash link, a signature that does not verify, an `--expected-head` that is absent from the log
(tail truncation), or an `--anchor-token` whose checkpoint line is missing.

**Means.** The log has been altered, truncated, or was signed by a different key. Exit **0** means
every line chained and every signature verified.

```bash
cd /tmp/nautilus-errors && printf '{"a":1}\n' > chain.jsonl \
  && nautilus attestation verify chain.jsonl --pubkey /nope.pem; echo "exit=$?"
```

## Argument parsing

An unknown subcommand or flag is handled by `argparse`, not by Nautilus, and exits **2**:

```text
usage: nautilus session [-h] subcommand ...
nautilus session: error: argument subcommand: invalid choice: 'schema' (choose from version)
```

`nautilus <command> --help` lists the valid subcommands for each group.

```bash
nautilus --help | head -25
```
