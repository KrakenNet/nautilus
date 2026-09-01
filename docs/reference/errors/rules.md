# Rules, RKM and the policy engine

Failures from authoring a rule, from moving a proposal through the review queue, and from the
engine that evaluates the result.

## Authoring a rule

### `ERROR {serr.file}:{serr.line}: {serr.message}{hint_suffix}`

`nautilus/cli/rules.py:171-177` (and `:281-287` on the `rule` path). Printed once per static
error to **stderr**; `nautilus rules validate` exits **1**. `{hint_suffix}` is
`" Hint: {serr.hint}"` when the compiler supplied one, and empty otherwise. Rendered example:

```text
ERROR /tmp/bad_rule.yaml:1: Rule file does not compile: [fathom.compiler] parse rules failed:
YAML file must contain a top-level 'module' key Hint: Each 'when' condition takes slot + one
of expression/bind/test. 'operator:'/'value:' are not condition keys.
```

The text after `[fathom.compiler]` comes from the rule compiler, so it changes with the rule.
The file and line locate it. With `--json`, the same errors are emitted as
`{"file": …, "ok": false, "errors": [{"file": …, "line": …, "message": …}]}`.

### `ERROR: file not found: {file_path}`

`nautilus/cli/rules.py:148-150`. Exit **1**. The path passed to `nautilus rules validate` does
not exist.

```bash
printf 'rules:\n  - name: r\n' > /tmp/nautilus-bad-rule.yaml
nautilus rules validate /tmp/nautilus-bad-rule.yaml; echo "exit=$?"
nautilus rules validate /nonexistent/rule.yaml; echo "exit=$?"
```

### Fact-file errors

`nautilus/rules/facts.py`, all `ValueError`, all prefixed with `{path}:{line}:`:

| Message | Line |
| --- | --- |
| `{yaml_file}:1: YAML parse error: {exc}` | `facts.py:46` |
| `{path}:{approx_line}: invalid relationship_type={rel_type!r}; must be one of [{valid}]` | `facts.py:62-65` |
| `{path}:{approx_line}: {float_slot} must be a float, got {value!r}` | `facts.py:74-77` |
| `{path}:{approx_line}: {float_slot}={fval} out of range [0.0, 1.0]` | `facts.py:80` |

## The sandbox validator

Every proposal is replayed against recorded traffic before it can be promoted.

### `proposed rule {rule_name!r} does not compile: {exc}`

**`SandboxRuleError`** (`nautilus/rkm/validator/sandbox.py:49`), raised at `:227`. `{exc}` is the
compiler error. Same fix as `nautilus rules validate`.

### `Regression detected: rule {rule_name!r} denies access the current rules grant, in {regression_count} of {replayed} replayed request(s). First: {first_regression}`

**`SandboxRegressionError`** (`nautilus/rkm/validator/sandbox.py:37`), raised at `:328-333`.

**Means.** The proposed rule was replayed against real recorded requests and took away access
that today's rules give. `{replayed}` is how many requests were replayed — if it is small, the
audit log is thin and the result is weak evidence either way. `{first_regression}` identifies the
first request that changed.

**Fix.** Narrow the rule's `when` conditions, or accept the tightening deliberately — that is a
policy decision, so it goes through review with the regression named in the proposal record.

## The review queue

### `proposal not found: {proposal_id!r}`

**HTTP 404.** `nautilus/transport/fastapi_app.py:1284`; also `KeyError` from
`nautilus/rkm/review.py:122,241`. The queue file has no such proposal. `GET /v1/rkm/queue` lists
what is there. `nautilus/rkm/queue.py:230` uses the unquoted form,
`proposal not found: {proposal_id}`.

### `{"error": "already_decided", "current_status": …}`

**HTTP 409**, a JSON object rather than a string. `nautilus/transport/fastapi_app.py:1336-1341`
and `:1382-1387`, from `AlreadyDecidedError` (`nautilus/rkm/review.py:39`). `current_status` is
the status the proposal already holds — `approved`, `rejected` or `retracted`. Decisions are not
idempotent replays: a second one is refused, not silently ignored.

### `cannot transition {proposal_id} from {current!r} to {to!r}`

**`InvalidTransition`** (`nautilus/rkm/queue.py:56`), raised at `:234`. Maps to HTTP 409. The
state machine has no edge between those two states.

### `lock contention timeout on proposal queue`

**`ProposalQueueLocked`** (`nautilus/rkm/queue.py:52`), raised at `:103` and `:114` after a
5-second `lockf` backoff. Maps to HTTP 503. Another process holds the queue file lock — a
concurrent `nautilus rkm` command, or a stale lock from a killed process. Retry; if it persists,
find the process holding the lock on the queue file.

### Governance request-body validation

**HTTP 400** unless noted, from `nautilus/transport/fastapi_app.py`:

| Message | Line | Route |
| --- | --- | --- |
| `body must carry 'rule_yaml': the contents of the rule file` | `:1210` | `POST /v1/rkm/queue` — send the rule file's text, not a path |
| `reason is required for rejection` | `:1365` | `POST /v1/rkm/queue/{id}/reject` |
| `reason is required for retraction` | `:1481` | `POST /v1/rules/{name}/retract` |
| `to_version is required for rollback` | `:1574` | `POST /v1/rules/{name}/rollback` |
| `yes=true required for destructive operation` (**412**) | `:1475,1568` | retract and rollback |

`X-Nautilus-Reviewer header required` is in [auth.md](auth.md).

```bash
curl -s -X POST http://127.0.0.1:8000/v1/rkm/queue \
  -H 'X-API-Key: govern-key' -H 'Content-Type: application/json' -d '{}'
curl -s -X POST http://127.0.0.1:8000/v1/rules/some_rule/retract \
  -H 'X-API-Key: govern-key' -H 'Content-Type: application/json' -d '{}'
```

## Promotion

`PromotionFailedError` (`nautilus/rkm/review.py:51`) and `PolicyEngineError`
(`nautilus/core/__init__.py:14`) — an approval that could not be made real.

**HTTP 422** from `POST /v1/rkm/queue/{proposal_id}/approve`
(`nautilus/transport/fastapi_app.py`), as a JSON object carrying `error`,
`message`, `current_status` and `recovery`. It was an uncaught `500` until the
route learned to catch it, which meant the commonest cause — no
`rules.user_rules_dirs` on a default install — reached the reviewer as nothing
at all. The proposal is left in `approved`: re-approving retries the promotion,
rejecting is the other way out.

### `cannot promote rule {rule_name!r}: no rules.user_rules_dirs is configured, so the rule would live only in this process and be gone at the next restart while the proposal reads 'promoted'. Configure a writable rules directory and retry the approval.`

`nautilus/core/fathom_router.py:803-810`. Set `rules.user_rules_dirs` to a writable directory
and approve again.

### `cannot promote rule {rule_name!r}: writing {target} failed: {exc}`

`nautilus/core/fathom_router.py:817-820`. The directory is configured but the write failed —
`{exc}` names the OS error. Read-only mount and missing directory are the usual causes.

### `proposal {proposal.proposal_id!r} carries no rule YAML: artifact has neither 'yaml' nor 'yaml_path' (keys: {sorted(artifact)})`

`nautilus/rkm/review.py:418-421`. The proposal record is incomplete; `{sorted(artifact)}` shows
what it does carry. Re-propose the rule.

### `proposal {proposal.proposal_id!r} references unreadable rule file {path!r}: {exc}`

`nautilus/rkm/review.py:415-418`. The proposal stored a `yaml_path` and the file has since moved
or become unreadable. Re-propose with the YAML inline.

### `FathomRouter.reload_rule failed for proposal {proposal_id!r}: {exc}`

`nautilus/rkm/review.py:157-160`. The rule was written but the engine refused to load it.
`{exc}` carries the compiler or engine error.

### `cannot retract rule {rule_name!r}: it is still in force after a rebuild, so it comes from a loaded rule pack. Remove the pack from rules.packs instead.`

`nautilus/core/fathom_router.py:856-860`. Pack-supplied rules are not retractable one at a time;
edit `rules.packs`.

## Lookups

| Message | Where | Status |
| --- | --- | --- |
| `rule not found: {rule_name!r}` | `fastapi_app.py:1436,1502` | 404 |
| `rule {rule_name!r} version {to_version} not found` | `fastapi_app.py:1593` | 404 |
| `rule {rule_name!r} v{to_version} not found in lineage` | `rkm/review.py:351` | `KeyError` |
| `lineage record not found: {rule_name} v{version}` | `rkm/lineage.py:249` | `KeyError` |

`GET /v1/rules` lists live rules; `GET /v1/rules/{rule_name}/lineage` lists the versions a
rollback may target.

### `invalid rule name {rule_name!r}: expected a bare rule name, optionally prefixed 'module::'`

**`LineageNameError`** (`nautilus/rkm/lineage.py:21`), raised at `:34-38`. Rule names are
`name` or `module::name`. A path, a file name with `.yaml`, or extra `::` separators are
rejected, because the name becomes part of a lineage file name.

### `LineageCycleError`

`nautilus/rkm/lineage.py:43`, raised at `:186` with the offending `path` as its only argument —
so the message is the list of rule versions forming the cycle. A rule's `supersedes` chain
loops back on itself. Break the loop by correcting the `supersedes` of the newest record.

## The engine

### `rule pack {pack_name!r} is claimed by more than one installed distribution ({', '.join(claimants)}). Which policy runs would be decided by distribution name order. Uninstall one, or rename the pack in the distribution you do not want.`

**`PolicyEngineError`**, `nautilus/core/fathom_router.py:135-141`. Two installed packages both
register the same entry-point pack name. Nautilus refuses to pick.

### `Fathom engine construction failed: {exc}`

`nautilus/core/fathom_router.py:196` and `:229`. The rule set did not compile into an engine at
startup or after a reload. `{exc}` is the compiler error — validate the rule files with
`nautilus rules validate`.

### `FathomRouter.route() failed for agent_id={agent_id!r}: {exc}` / `FathomRouter.replay() failed: {exc}` / `FathomRouter.reload_rule() failed for rule_name={rule_name!r}: {exc}`

`nautilus/core/fathom_router.py:481`, `:525`, `:831`. Evaluation raised. `{exc}` is the
underlying failure; a rule referencing a slot that does not exist is the common one.

### `ConsistencyError`

`nautilus/core/__init__.py:63`, raised by `FathomRouter` at `:625-671` with a **code** and a
message. Each means the evaluation produced a fact set that contradicts itself — a routing
decision Nautilus will not act on.

| Code | Message | Meaning |
| --- | --- | --- |
| `routing_unknown_source` | `routing_decision references undeclared source(s) {sorted(unknown_routed)!r}` | A rule routed to a source id that is not in `sources:`. Usually a typo in the rule. |
| `scope_without_routing` | `scope_constraint without a routing_decision for source(s) {sorted(unscoped)!r}` | A rule constrained a source it never routed to; the constraint would never be applied. |
| `denial_unknown_source` | `denial_record references undeclared source {denial.source_id!r}` | A denial names a source that does not exist. |
| `denial_missing_linkage` | `denial_record for source {denial.source_id!r} is missing reason/rule_name linkage (reason={denial.reason!r}, rule_name={denial.rule_name!r})` | A denial without a reason or an owning rule is unexplainable in the audit record. |
| `agent_fact_integrity` | `expected exactly 1 agent fact after evaluation, found {len(agent_facts)}` | Rules asserted or retracted the agent fact. |
| `agent_fact_integrity` | `agent fact slot {slot!r} mutated during evaluation: asserted {asserted!r}, found {actual!r}` | A rule rewrote the caller's identity mid-evaluation. |
| `session_exposure_count` | `expected {expected_exposure_count} session_exposure fact(s) after evaluation, found {len(exposure_facts)} (unexpected retraction cascade or injection)` | The exposure ledger was changed by rule evaluation. |

**Fix, all seven.** These name a rule bug, not an operational one. Find the rule that asserts the
offending fact and correct it; `nautilus rules validate --sandbox` replays it before it ships.

### `unknown agent id={agent_id!r}`

Not an exception — a denial `reason` on the response
(`nautilus/core/fathom_router.py:363`). The request named an agent with no entry under `agents:`.

### `rule {rule_name!r} targets routing-owned template {template!r}`

**`CuratorIsolationViolation`** (`nautilus/rkm/curator/isolation.py:32`), raised at `:85-88`
with a `file:line` `location`. A curator meta-rule tried to write a template the routing module
owns. Meta-rules may propose changes to rules; they may not assert routing facts directly.
