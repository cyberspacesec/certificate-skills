---
name: key-usage-checker
description: Validate certificate key usage compliance with RFC 5280 and CA/B BR requirements
tools:
  - cert_check_key_usage
---

# Key Usage Checker

> **TL;DR:** Validate certificate key usage compliance with RFC 5280 and CA/B BR requirements

## Capabilities

- CA certificate keyCertSign requirement
- Non-CA keyCertSign prohibition
- TLS leaf digitalSignature/keyEncipherment
- ServerAuth EKU check
- Key algorithm consistency

## Usage

```
cert_check_key_usage target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Compliance status
- Key usage and EKU lists
- Is CA flag
- Issues with severity

## Workflow

1. Run `cert_check_key_usage` on target
2. Review key usage lists
3. Check compliance issues
4. Focus on High severity issues

## Cyberspace Mapping Applications

- Detect mis-issued certificates with incorrect key usage
- Identify non-CA certs that can sign other certificates
- Track key usage patterns across CA issuers

## Limitations

- Checks leaf certificate only
- Some legacy certificates may have non-standard key usage

## Related Skills

- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_name_constraints]] cert_check_name_constraints
- [[cert_check_policy]] cert_check_policy
