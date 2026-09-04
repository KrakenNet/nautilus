# data-routing-hipaa

HIPAA Privacy Rule constraints for Nautilus data routing.

Load by entry-point name, not by path:

```python
FathomRouter(
    built_in_rules_dir=BUILT_IN_RULES_DIR,
    user_rules_dirs=[],
    rule_packs=["data-routing-hipaa"],
)
```

Pack rules join the built-in `nautilus-routing` module: they match on the same
working memory as the built-in routing rules and must interleave with them by
salience.

## Rules Implemented

| Rule | Basis | Effect | Salience |
|------|-------|--------|----------|
| `minimum-necessary-phi-scope` | 45 CFR 164.502(b) | `scope_constraint` binding any PHI-bearing source to the agent's stated purpose | 140 |
| `deny-phi-outside-tpo` | 45 CFR 164.506 | `denial_record` when PHI is requested for a purpose outside treatment, payment, or health care operations | 185 |

`deny-phi-outside-tpo` is not redundant with the built-in `deny-purpose-mismatch`.
The built-in checks the purpose against each source's own `allowed_purposes`
list; this rule enforces the HIPAA purpose vocabulary itself, so a source
misconfigured to permit `analytics` on PHI is still denied.

## Rules Not Implemented

Nautilus asserts five fact templates per request — `agent`, `intent`, `source`,
`session`/`session_exposure`, and `escalation_rule`. These were dropped because
their conditions cannot be written over those facts:

| Rule | Requires a fact Nautilus does not assert |
|------|------------------------------------------|
| `role-restrictions` | `agent.role`. The `agent` template has `id`, `clearance`, `purpose`, `compartments`, and `sub_category` — no role. |
| `breach-detection` | Access-volume and anomaly facts spanning requests. `session_exposure` records what a session has seen, not rate or deviation. |
| `phi-hierarchy` | A loaded PHI-sensitivity hierarchy. `RulePackLoader` scans only `templates/`, `modules/`, `functions/`, and `rules/` — it never loads a pack `hierarchies/` directory, so the ordering it declared was silently absent. |

## Compliance Disclaimer

This pack is a **reference implementation only** — it is not certified for
production compliance. Organizations must validate rules against their specific
regulatory requirements and engage qualified compliance personnel. This pack is
not a substitute for professional compliance assessment.
