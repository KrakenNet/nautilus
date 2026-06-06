# Write a Routing Rule

Add a custom scope rule that narrows what an agent sees, end to end.
For the full DSL, see [Authoring Rules](authoring-rules.md).

## 1. Write the rule file

`/etc/nautilus/rules.d/severity-scope.yaml`:

```yaml
module: nautilus-routing
ruleset: my-org-scoping
version: "1.0"
rules:
  - name: scope-interns-to-low-severity
    description: "Interns only see low-severity vulnerability rows."
    salience: 120          # above routing (100), below default denials (150/200)
    when:
      - template: agent
        conditions:
          - slot: clearance
            operator: eq
            value: unclassified
      - template: source
        conditions:
          - slot: id
            bind: ?sid
          - slot: classification
            operator: eq
            value: unclassified
    then:
      action: scope
      assert:
        - template: scope_constraint
          slots:
            source_id: "?sid"
            field: severity
            operator: "="
            value: low
```

The `scope_constraint` reaches the adapter as a WHERE-clause fragment
(`severity = 'low'`). Operators must come from the adapter allowlist
(`=`, `eq`, `!=`, `IN`, `NOT IN`, `LIKE`, `IS NULL`) and the constraint
must target a source that is actually routed — the router's consistency
checks fail the request otherwise.

## 2. Validate and test

```bash
nautilus rules validate /etc/nautilus/rules.d/severity-scope.yaml
nautilus rules test --file /etc/nautilus/rules.d/severity-scope.yaml \
  --audit-log /var/lib/nautilus/audit.jsonl
```

`rules test` will flag the rule if it is shadowed by a higher-salience
rule with the same conditions, and replay your audit history to prove it
doesn't flip past allow/deny outcomes (exit 1 on regression, exit 2
below the confidence threshold).

## 3. Load it

```yaml
rules:
  user_rules_dirs:
    - /etc/nautilus/rules.d
```

Restart, send a request as an `unclassified` agent, and check the audit
entry's `rule_trace` for `scope-interns-to-low-severity` plus the scoped
rows in the response.
