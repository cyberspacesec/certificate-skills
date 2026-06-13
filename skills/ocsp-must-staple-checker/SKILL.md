---
name: ocsp-must-staple-checker
description: Check OCSP Must-Staple (RFC 7633) compliance — Must-Staple without staple causes client hard-fail
tools:
  - cert_check_ocsp_must_staple
---

# Ocsp Must Staple Checker

> **TL;DR:** Check OCSP Must-Staple (RFC 7633) compliance — Must-Staple without staple causes client hard-fail

## Capabilities

- TLS feature extension (OID 1.3.6.1.5.5.7.1.24) detection
- OCSP staple presence verification
- Compliance determination
- Severity classification

## Usage

```
cert_check_ocsp_must_staple target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Has Must-Staple extension
- Has OCSP staple
- Is compliant
- Violation detail

## Workflow

1. Run `cert_check_ocsp_must_staple` on target
2. Check Must-Staple presence
3. If present, verify staple is provided
4. Non-compliance causes client hard-fail

## Cyberspace Mapping Applications

- Identify servers that hard-fail for Must-Staple clients
- Detect misconfigured OCSP stapling
- Track Must-Staple adoption

## Limitations

- Requires TLS handshake to check staple
- Some load balancers may strip OCSP staples

## Related Skills

- [[cert_check_revocation]] cert_check_revocation
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_analyze_security]] cert_analyze_security
