# Rule Packs

Nautilus ships two pre-built Fathom rule packs for policy routing.

## data-routing-nist

NIST clearance and classification rules. Evaluates agent clearance levels
against source classification to determine routing, scoping, or denial.

Registered via entry point: `fathom.packs` → `data-routing-nist`

## data-routing-hipaa

HIPAA-compliant routing rules. Enforces minimum-necessary access controls
and PHI handling requirements.

Registered via entry point: `fathom.packs` → `data-routing-hipaa`

## Loading a rule pack

Rule packs are loaded automatically when referenced in `nautilus.yaml`:

```yaml
rules:
  packs:
    - data-routing-nist
    - data-routing-hipaa
```
