# data-routing-nist

NIST SP 800-53 compliance rules for Nautilus data routing.

This is a **reference implementation** of NIST SP 800-53 access control and system/communications protection controls mapped to Nautilus salience-based routing rules.

## Controls Covered

| Control | Family | Salience Band |
|---------|--------|---------------|
| AC-3 | Access Enforcement | 170-190 (denial) |
| AC-4 | Information Flow Enforcement | 170-190 (denial) |
| AC-6 | Least Privilege | 130-150 (scope constraint) |
| AC-16 | Security and Privacy Attributes | 130-150 (scope constraint) |
| AC-21 | Information Sharing | 110-120 (escalation) |
| AC-23 | Data Mining Protection | 110-120 (escalation) |
| SC-7 | Boundary Protection | 170-190 (denial) |
| SC-16 | Transmission of Security and Privacy Attributes | 170-190 (denial) |

## Structure

```
data-routing-nist/
  pack.yaml              # Pack metadata
  templates/
    nist_control.yaml    # nist_control_mapping template
  modules/
    nist-routing.yaml    # Module definition
  rules/                 # Individual control rule files
  hierarchies/
    cui-sub-extended.yaml  # Extended CUI sub-category hierarchy
```

## Compliance Disclaimer

This pack is a **reference implementation only** -- it is not certified for production compliance. Organizations must validate rules against their specific regulatory requirements and engage qualified compliance personnel. This pack is not a substitute for professional compliance assessment.
