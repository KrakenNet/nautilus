# RKM: the Rule Lifecycle

The Reflexive Knowledge Module (RKM) is how the rule base evolves
safely: every rule change — human-authored or system-proposed — passes
the same validator pipeline, lands in a reviewable queue, and leaves a
lineage trail.

## The pipeline

```
proposal ──► static ──► shadow ──► sandbox ──► score ──► review queue ──► promote
```

1. **Static** — structural validation: templates exist, conditions are
   well-formed, required slots present. Hard fail.
2. **Shadow** — can this rule ever fire, given the existing rule base?
   A broader rule with higher salience that always wins marks the
   proposal as shadowed.
3. **Sandbox** — replay recent audit history against the candidate rule
   in an isolated engine. A proposal that would *flip* a past
   allow/deny outcome is a regression. Hard fail.
4. **Score** — a confidence breakdown (static cleanliness, shadow
   findings, replay volume and agreement) condensed to a number;
   proposals below threshold need a human.

This is the same pipeline behind `nautilus rules validate` and
`nautilus rules test` — the CLI runs it against your file, RKM runs it
against system-generated proposals.

## The review queue

Validated proposals wait in a durable queue for human judgment:

```bash
nautilus rkm queue list
nautilus rkm queue show <proposal-id>
nautilus rkm queue diff <proposal-id>
nautilus rkm queue approve <proposal-id>   # or reject
```

The same operations exist over REST (`GET /v1/rkm/queue`,
`POST /v1/rkm/queue/{id}/approve|reject`) — approvals require a
reviewer identity (`X-Nautilus-Reviewer` header), which lands in the
audit trail.

`rkm.auto_promote.enabled` (default **false**) lets high-confidence
proposals skip the human step; the validation evidence is preserved
either way.

## Lineage

Every promoted rule version is recorded in a lineage DAG — which
proposal produced it, what it replaced, who approved it:

```bash
nautilus rkm lineage
nautilus rule history <rule-name>
nautilus rule rollback <rule-name> ...   # restore a prior version
nautilus rule retract <rule-name> ...    # retire a rule (destructive)
```

Because routing decisions cite rule names in the audit `rule_trace`,
lineage closes the loop: any past decision can be traced to the exact
rule version that made it, and that version to the human (or threshold)
that approved it.

## Meta-rules

The curator module watches the rule base itself — rules about rules.
Meta-rule firings emit `meta_rule_fired` audit events with
`rule_module="curator"`, keeping even the system's self-modification
proposals inside the audit trail.
