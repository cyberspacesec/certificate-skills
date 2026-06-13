---
name: ev-detector
description: Detect Extended Validation (EV) certificates through policy OID analysis
tools:
  - cert_detect_ev
---

# Ev Detector

> **TL;DR:** Detect Extended Validation (EV) certificates through policy OID analysis

## Capabilities

- EV detection via policy OID matching
- CA/B Forum EV OID database
- CA identification
- Reason explanation

## Usage

```
cert_detect_ev target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Whether certificate is EV
- Policy OIDs found
- Issuer organization
- Reason for determination

## Workflow

1. Run `cert_detect_ev` on target
2. If EV, verify issuer organization
3. If not EV, check `cert_check_policy` for DV/OV classification

## Cyberspace Mapping Applications

- Identify high-assurance certificates in the wild
- Map EV certificate adoption across organizations
- Detect potential phishing using non-EV for financial services

## Limitations

- EV determination depends on OID database coverage
- Some CAs use custom EV OIDs not in the database

## Related Skills

- [[cert_check_policy]] cert_check_policy
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_analyze_security]] cert_analyze_security
