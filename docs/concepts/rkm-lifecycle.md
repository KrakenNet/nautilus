# RKM: the Rule Lifecycle

The Reflexive Knowledge Module (RKM) is how the rule base evolves
safely: every rule change — human-authored or system-proposed — passes
the same validator pipeline, lands in a reviewable queue, and leaves a
lineage trail.

## The pipeline

```
proposal ──► static ──► shadow ──► sandbox ──► score ──► resolve ──► review queue ──► promote
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
5. **Resolve** — detection alone still leaves every conflict for a
   human, so this stage settles the one subclass that provenance can
   decide on its own: a proposal subsumed by a single existing rule
   that is still live and carries both observation and sandbox
   provenance is marked `superseded`, with the evidence recorded on the
   proposal. It is deterministic — no LLM, no clock — and fail-closed:
   shadowing, salience inversions, and anything with thin or ambiguous
   evidence route to human review. Auto-resolution only ever retires the
   *proposal*, never a live rule, so the active rule base is untouched.

This is the same pipeline behind `nautilus rules validate` and
`nautilus rules test` — the CLI runs it against your file, RKM runs it
against system-generated proposals.

## The review queue

Validated proposals wait in a durable queue for human judgment:

```bash
nautilus rkm queue list
nautilus rkm queue show <proposal-id>
nautilus rkm queue diff <proposal-id>
nautilus rkm queue approve <proposal-id> --url http://localhost:8000
nautilus rkm queue reject <proposal-id> --reason "..."
```

`approve` requires `--url`: approval promotes the rule into the CLIPS
environment of a *running* broker, so there is nothing the CLI can approve
against the queue on disk alone.

The same operations exist over REST (`GET /v1/rkm/queue`,
`POST /v1/rkm/queue/{id}/approve|reject`) — approvals require a
reviewer identity (`X-Nautilus-Reviewer` header), which lands in the
audit trail: the REST routes write to the serving broker's sink, the CLI
to `--config`'s `audit.path` (default `./audit.jsonl`).

Every proposal goes through that human step. `rkm.auto_promote.enabled`
is reserved for a future high-confidence bypass and is **not implemented**;
setting it to `true` is refused at config load rather than silently
ignored.

## Lineage

Every promoted rule version is recorded in a lineage DAG — which
proposal produced it, what it replaced, who approved it:

```bash
nautilus rkm lineage
nautilus rule history <rule-name>
nautilus rule rollback <rule-name> ...   # restore a prior version
nautilus rule retract <rule-name> ...    # retire a rule (destructive)
```

Promotion writes the approved rule into the first directory of
`rules.user_rules_dirs` and loads it into the running engine, so the rule
is still in force after a restart. A broker with no `rules.user_rules_dirs`
refuses the promotion rather than loading a rule that would vanish.

Rollback and retraction are audited the same way, as `rule_rolled_back`
and `rule_retracted`. A rollback is append-only — the restored version is
re-inserted as a new one — and it does not reload the rule into a running
engine, so a live broker keeps serving the newer rule until it restarts.

Because routing decisions cite rule names in the audit `rule_trace`,
lineage closes the loop: any past decision can be traced to the exact
rule version that made it, and that version to the human (or threshold)
that approved it.

## Meta-rules

The curator module is where rules about rules live. Its isolation boundary
is enforced: a rule in any module other than `nautilus-routing` may not
assert, modify or retract a routing-owned template, and `nautilus rules
validate` rejects one that tries. Meta-rule firings emit `meta_rule_fired`
audit events with `rule_module="curator"`.

The shipped meta-ruleset (`pattern-tracker.yaml`) is currently empty: its
rules need negation conditions that fathom-rules 0.11 does not support, so
nothing in the curator module fires yet and `meta_rule_fired` has no
producer outside tests.
