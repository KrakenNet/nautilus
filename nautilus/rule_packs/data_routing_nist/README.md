# data-routing-nist

NIST SP 800-53 access-control rules for Nautilus data routing.

Load by entry-point name, not by path:

```python
FathomRouter(
    built_in_rules_dir=BUILT_IN_RULES_DIR,
    user_rules_dirs=[],
    rule_packs=["data-routing-nist"],
)
```

Pack rules join the built-in `nautilus-routing` module: they match on the same
working memory as the built-in routing rules and must interleave with them by
salience.

## Controls Implemented

| Control | Family | Effect | Salience |
|---------|--------|--------|----------|
| AC-6 | Least Privilege | `scope_constraint` binding the source to the agent's stated purpose, for sources classified `confidential` or above | 140 |
| AC-16 | Security and Privacy Attributes | `denial_record` when a source carries no classification label at all | 180 |

## Controls Not Implemented

Nautilus asserts five fact templates per request — `agent`, `intent`, `source`,
`session`/`session_exposure`, and `escalation_rule`. A control whose condition
cannot be written over those facts cannot be enforced, and a rule that can never
fire is indistinguishable from no rule. These are omitted rather than stubbed:

| Control | Requires a fact Nautilus does not assert |
|---------|------------------------------------------|
| AC-3 Access Enforcement | Nothing — this is already enforced by the built-in `default-classification-deny` rule. A pack copy would only emit duplicate denials. |
| AC-4 Information Flow Enforcement | A destination/flow fact (`flow.authorization`, `destination.security_domain`). Routing has a source but no modelled destination. |
| AC-21 Information Sharing | A sharing-partner fact for the receiving party. |
| AC-23 Data Mining Protection | `request.access_pattern` — volume/pattern data outside the per-request fact set. |
| SC-7 Boundary Protection | `source.boundary_zone`. |
| SC-16 Transmission of Security Attributes | `channel.integrity_level` — Nautilus models no transmission channel. |

Implementing any of these means first extending the broker to assert the fact,
not writing a rule against a fact that never arrives.

## Compliance Disclaimer

This pack is a **reference implementation only** — it is not certified for
production compliance. Organizations must validate rules against their specific
regulatory requirements and engage qualified compliance personnel. This pack is
not a substitute for professional compliance assessment.
