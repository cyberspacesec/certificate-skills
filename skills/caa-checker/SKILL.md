---
name: caa-checker
description: Check DNS CAA records and verify CA authorization for certificate issuance
tools:
  - cert_check_caa
---

# Caa Checker

> **TL;DR:** Check DNS CAA records and verify CA authorization for certificate issuance

## Capabilities

- DNS CAA record querying (issue, issuewild, iodef)
- CA authorization verification
- Misconfiguration detection
- Compliance checking

## Usage

```
cert_check_caa target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name to check CAA records for |

## Output

- CAA records existence
- Record details (flag, tag, value)
- CA authorization status
- IODEF reporting URL

## Workflow

1. Run `cert_check_caa` on target domain
2. If CAA exists, verify issuing CA is authorized
3. If no CAA, any CA can issue (consider adding CAA)
4. Recommend CAA policy for restricted issuance

## Cyberspace Mapping Applications

- Identify which CAs are authorized for a domain
- Detect unauthorized certificate issuance through CAA
- Map CA relationships and trust boundaries

## Limitations

- Requires DNS resolution
- Not all DNS resolvers support CAA type
- CAA is only checked by compliant CAs

## Related Skills

- [[cert_verify_chain]] cert_verify_chain
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
- [[cert_search_ct]] cert_search_ct
