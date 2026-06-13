---
name: serial-entropy-checker
description: Analyze certificate serial number entropy for CA/B BR compliance (>=64 bits required)
tools:
  - cert_check_serial_entropy
---

# Serial Entropy Checker

> **TL;DR:** Analyze certificate serial number entropy for CA/B BR compliance (>=64 bits required)

## Capabilities

- Serial bit length check (>= 64 bits)
- Shannon entropy estimation
- Hamming weight analysis for bias detection
- Sequential serial detection
- Predictability assessment

## Usage

```
cert_check_serial_entropy target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Serial hex
- Bit length
- Compliance status
- Entropy estimate
- Hamming weight/ratio
- Sequential flag

## Workflow

1. Run `cert_check_serial_entropy` on target
2. Check bit length >= 64 bits
3. Review entropy (>3.0 bits/byte is healthy)
4. Verify not sequential/predictable

## Cyberspace Mapping Applications

- Identify certificates from non-compliant CAs
- Track serial number quality across CA issuers
- Detect CAs using sequential numbering

## Limitations

- Entropy estimation is heuristic
- Some legitimate CAs may have low-entropy serials in older certificates

## Related Skills

- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_key_usage]] cert_check_key_usage
- [[cert_check_policy]] cert_check_policy
