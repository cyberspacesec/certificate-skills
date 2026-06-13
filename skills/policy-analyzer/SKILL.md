---
name: policy-analyzer
description: Analyze certificate policy OIDs for DV/OV/EV classification and compliance
tools:
  - cert_check_policy
  - cert_detect_ev
---

# Policy Analyzer

> **TL;DR:** Analyze certificate policy OIDs for DV/OV/EV classification and compliance

## Capabilities

- DV/OV/EV validation type determination
- Known OID database (DigiCert, Let's Encrypt, Sectigo, etc.)
- Unknown OID detection
- Missing Certificate Policies on public CA certs

## Usage

```
cert_check_policy target="example.com"
cert_detect_ev target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Validation type (DV/OV/EV/Unknown)
- Policy OID list with descriptions
- Compliance status
- Issues list

## Workflow

1. Run `cert_check_policy` on target
2. Review validation type
3. Check for unknown OIDs (private CA indicator)
4. Verify compliance (missing policies = BR violation)

## Cyberspace Mapping Applications

- Classify certificate validation level across infrastructure
- Identify private/custom CAs through unknown OIDs
- Track DV/OV/EV adoption rates

## Limitations

- Policy OID database covers major CAs only
- Some CAs use custom OIDs not in database

## Related Skills

- [[cert_detect_ev]] cert_detect_ev
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
