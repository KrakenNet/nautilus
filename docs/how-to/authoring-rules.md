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
            operator: eq
            value: confidential
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
  conditions. `bind: ?var` captures a slot value; `test:` entries embed
  raw CLIPS predicates (e.g. the `fathom-dominates` hierarchy check).
- **`then`** — `action: allow | deny | scope` plus facts to `assert`.
  `action: deny` is required for the rule to emit a `__fathom_decision`
  fact and appear in the rule trace.
- **`salience`** — higher fires first. The shipped defaults use
  purpose-mismatch denial at 200, classification denial at 150, routing
  at 100; place your rules relative to those.

The shipped templates live in `nautilus/rules/templates/`, the default
rules in `nautilus/rules/rules/`, and module declarations in
`nautilus/rules/modules/` — read them as worked examples.

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
adapter allowlist (`=`, `eq`, `!=`, `IN`, `NOT IN`, `LIKE`, `IS NULL`).

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

Beyond hand-written rules, the Rule Knowledge Management subsystem
proposes new rules from observed traffic, runs them through the same
validator pipeline, and queues them for human review
(`GET /v1/rkm/queue`, approve/reject endpoints). See
[RKM lifecycle](../concepts/rkm-lifecycle.md).
