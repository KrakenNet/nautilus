# data-routing-hipaa

HIPAA compliance rule pack for Nautilus data routing.

This is a **reference implementation** of HIPAA Privacy and Security Rule
constraints expressed as Fathom rules. It provides:

- **PHI classification template** (`phi_source_tag`) for tagging data sources
  with PHI sensitivity levels and covered-entity metadata.
- **Minimum necessary rules** -- scope constraints per purpose (treatment,
  payment, operations).
- **PHI access control rules** -- denial rules for unauthorized PHI access.
- **PHI hierarchy** -- de-identified < limited < standard < sensitive.
- **Breach detection rules** -- temporal operator rules for exposure patterns.
- **Role restrictions** -- purpose-based role restrictions.

## Compliance Disclaimer

> Reference implementation only -- not certified for production compliance.
> Organizations must validate rules against their specific regulatory
> requirements and engage qualified compliance personnel.

This pack is designed to be loaded independently or alongside the
`data-routing-nist` pack. Salience bands are shared across packs; rules
within a band fire in declaration order with no cross-pack conflicts.

## Salience Bands

| Band | Range | Purpose |
|------|-------|---------|
| Compliance denials | 170-190 | Hard blocks (PHI without role authorization) |
| Scope constraints | 130-150 | Field/row restrictions (minimum necessary filtering) |
| Escalations | 110-120 | Alerts (breach detection temporal patterns) |

## Registration

Registered via `pyproject.toml` entry point:

```toml
[project.entry-points."fathom.packs"]
data-routing-hipaa = "rule_packs.data_routing_hipaa"
```
