---
name: name-constraints-checker
description: Check CA name constraints and detect trust boundary violations
tools:
  - cert_check_name_constraints
---

# Name Constraints Checker

> **TL;DR:** Check CA name constraints and detect trust boundary violations

## Capabilities

- CA constraint extraction (permitted/excluded DNS, IP, email)
- Leaf name compliance verification
- Trust boundary violation detection
- Full chain constraint walking

## Usage

```
cert_check_name_constraints target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Whether constraints exist
- Constrained CAs with details
- Violation list
- Compliance status

## Workflow

1. Run `cert_check_name_constraints` on target
2. If constraints exist, review constrained CAs
3. Check for violations
4. Violations indicate trust boundary breaches

## Cyberspace Mapping Applications

- Detect over-permissive CAs with no constraints
- Find trust boundary violations in corporate sub-CA deployments
- Map CA constraint policies

## Limitations

- Only checks constraints in the presented chain
- Some CAs use constraints not in the certificate extension

## Related Skills

- [[cert_check_key_usage]] cert_check_key_usage
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_verify_chain]] cert_verify_chain
