# Authoring Rules

How to write, validate, test, and ship Fathom routing rules for Nautilus.

## Rule file anatomy

Rules are YAML, evaluated by the CLIPS-backed Fathom engine. A file
declares a module, a ruleset, and a list of rules:

```yaml
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
```

- **`when`** — a list of fact patterns. Each entry matches a template
  (`agent`, `source`, `intent`, `session_exposure`, ...) with slot
  conditions. A condition takes a `slot:` plus exactly one of
  `expression:`, `bind:`, or `test:` — those four keys are the whole
  vocabulary, and any other key is rejected by the compiler.
  `bind: ?var` captures a slot value; `test:` entries embed raw CLIPS
  predicates.
- **`then`** — `action: allow | deny | scope | route | escalate` plus
  facts to `assert`. The `action` is what emits the `__fathom_decision`
  fact that puts the rule in the rule trace.
- **`salience`** — higher fires first. See
  [Salience](#salience-what-the-shipped-rules-use) below.

The shipped templates live in `nautilus/rules/templates/`, the default
rules in `nautilus/rules/rules/`, and module declarations in
`nautilus/rules/modules/` — read them as worked examples.

## Condition expressions

`expression:` takes an operator call. The full vocabulary:

| Operator | Example | Matches |
|---|---|---|
| `equals` | `equals("secret")` | slot equal to the literal |
| `not_equals` | `not_equals("public")` | slot not equal to the literal |
| `greater_than` / `less_than` | `greater_than(5)` | numeric comparison |
| `in` / `not_in` | `in("cui", "secret")` | slot is (not) one of a list |
| `contains` | `contains("phi")` | substring of the slot |
| `matches` | `matches("^cve-")` | regex against the slot |

Classification-hierarchy operators, which compare against a registered
hierarchy rather than a literal: `dominates`, `meets_or_exceeds`,
`below`, `within_scope`, `in_compartment`, `has_compartments`.

Temporal / aggregate operators, which look across the session's recorded
history: `changed_within`, `count_exceeds`, `distinct_count`, `last_n`,
`rate_exceeds`, `schema_frequency_exceeds`, `sequence_detected`.

`eq` is **not** an operator — it is the single most common authoring
mistake, and the compiler rejects it with `unsupported condition
operator 'eq'`.

An expression may also reference another pattern's alias:
`expression: equals($src.id)` joins this slot to the `source` pattern
declared with `alias: $src`.

## Salience: what the shipped rules use

Place your rules relative to what actually ships:

| Salience | Rule | File |
|---|---|---|
| 250 | `information-flow-violation` | `rules/handoff.yaml` |
| 250 | `purpose-expired-deny` | `rules/temporal.yaml` |
| 200 | `deny-purpose-mismatch` | `rules/denial.yaml` |
| 150 | `default-classification-deny` | `rules/classification.yaml` |
| 120 | `session-exposure-escalation-deny` | `rules/escalation.yaml` |
| 100 | `match-sources-by-data-type` | `rules/routing.yaml` |

Denial records are unioned into a set, so a denial at lower salience
still denies — salience decides trace order and which rule gets the
attribution, not whether a denial takes effect. A rule that asserts a
`scope_constraint` must fire *after* routing, because the constraint has
to reference a source that has a routing decision; match the
`routing_decision` fact in the rule's `when` rather than relying on
salience alone.

Salience orders the agenda **within a CLIPS module**. A rule in its own
module does not interleave with `nautilus-routing` at all — the engine
runs one module's agenda to exhaustion before moving on.

## The `session` template

`session` carries the per-session counters a cumulative-exposure rule
matches on. Its slots are not obvious from the shipped rules, so:

| Slot | Type | Meaning |
|---|---|---|
| `id` | string | Session id (required) |
| `pii_sources_accessed` | integer | Count of PII-classified sources served this session |
| `data_types_seen` | multislot | Data types served so far |
| `sources_visited` | multislot | Source ids served so far |
| `pii_sources_accessed_list` | multislot | Source ids of the PII sources served |
| `purpose_start_ts` | float | Epoch seconds when the declared purpose began |
| `purpose_ttl_seconds` | float | Seconds before the purpose expires |

Multislots are encoded as one space-separated string at the router
layer, so `equals` compares the *whole* string. Match them with the
registered `contains-all` external, which takes set-containment
semantics over both arguments:

```yaml
      - template: session
        conditions:
          - slot: data_types_seen
            bind: ?seen
          - test: '(python-function contains-all "phi" ?seen)'
```

Registered externals are reachable only through `python-function`;
calling `(contains-all ...)` directly fails the CLIPS build. The shipped
escalation rule (`rules/escalation.yaml`) is the worked example.

`pii_sources_accessed` is asserted but no shipped rule reads it — a
source-count threshold needs a rule you write. The shipped cumulative
denial keys on `data_types_seen`.

## The denial-record invariant

The router runs post-evaluation consistency checks (fail-closed: a
violation raises `PolicyEngineError` rather than mis-routing). Two of
them constrain rules you write:

1. **Every `denial_record` must reference a declared source** — its
   `source_id` slot must match a source id from the registry. Bind it
   from the matched `source` fact (`source_id: "?sid"`); never hardcode.
2. **Every `denial_record` must carry a non-empty `reason` and
   `rule_name`.**

A rule that asserts an unlinked or anonymous denial record will fail the
whole request with a `ConsistencyError` — by design, since an
unattributable denial cannot be audited.

Scope constraints are checked too: a `scope_constraint` must reference a
source that has a routing decision, and its operator must be in the
`scope_constraint` template allowlist (`=`, `!=`, `IN`, `NOT IN`, `<`, `>`,
`<=`, `>=`, `LIKE`, `BETWEEN`, `IS NULL`).

Checks default on; `rules.consistency_checks: false` opts out for
performance-sensitive deployments.

## Wiring rules into the broker

```yaml
rules:
  user_rules_dirs:
    - /etc/nautilus/rules.d     # every *.yaml in these dirs is loaded
```

Pre-built packs (NIST, HIPAA) load by name — see
[Rule Packs](../reference/rule-packs.md).

## Validate → test → ship

### 1. Static validation

```bash
nautilus rules validate my-rules.yaml
nautilus rules validate my-rules.yaml --sandbox --replay-n 1000
```

Catches structural errors: unknown templates, malformed conditions,
missing required slots. `--sandbox` additionally replays recent audit
entries against the rule. Exit 1 on any error.

### 2. Full test run

```bash
nautilus rules test --file my-rules.yaml \
  --audit-log /var/lib/nautilus/audit.jsonl \
  --threshold 0.6 --json
```

Runs the full validator pipeline per rule:

- **static** — same checks as `validate`; errors exit 1.
- **shadow** — detects rules in the file that can never fire because a
  broader rule with higher salience always wins. Shadowed rules WARN and
  lower the confidence score.
- **sandbox replay** — replays the audit log; a rule that would *flip*
  a previously-allowed request to denied (or vice versa) is a regression
  and exits 1.
- **score** — a confidence breakdown per rule; if the minimum score in
  the file is below `--threshold` (default 0.6), exit 2.

Exit codes: `0` pass, `1` validation/regression failure, `2` below
threshold. Without `--audit-log` the sandbox stage has no history and
WARNs `insufficient_history` instead of replaying — always test against
a recent production audit log before shipping.

### 3. Lineage

```bash
nautilus rules history --module nautilus-routing --json
```

Lists the rule lineage for a module: which rules were promoted, when,
and from which proposal.

## Debugging a misfiring rule

1. Run the request and pull its audit entry
   (`GET /v1/audit/{request_id}`) — `rule_trace` lists every decision
   fact with the emitting rule name and salience.
2. If a source is denied unexpectedly, check salience interplay: a
   higher-salience deny always beats your allow.
3. If the request fails with `ConsistencyError`, the message carries the
   failing check name and offending ids — usually a denial record
   missing its `source_id` binding.

## RKM: rules proposed by the system

Beyond hand-written rules, the Rule Knowledge Management subsystem takes
proposed rules, runs them through the same validator pipeline, and queues
them for human review (`GET /v1/rkm/queue`, approve/reject endpoints). See
[RKM lifecycle](../concepts/rkm-lifecycle.md).

The curator meta-rules that would *generate* those proposals from observed
traffic ship disabled: they need negation conditions (`not:`) that
fathom-rules 0.11 does not have, so `pattern-tracker.yaml` loads with an
empty rule list. Proposals today come from the pipeline you invoke, not
from the system watching itself.
