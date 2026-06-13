---
name: bundle-checker
description: Check certificate bundle completeness and diagnose missing intermediates via AIA
tools:
  - cert_check_bundle
---

# Bundle Checker

> **TL;DR:** Check certificate bundle completeness and diagnose missing intermediates via AIA

## Capabilities

- Certificate chain completeness verification
- Missing intermediate diagnosis
- AIA CA Issuers URL fetching
- Chain re-verification after AIA fetch

## Usage

```
cert_check_bundle target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Chain complete status
- Missing intermediates
- AIA fill capability
- AIA resolution status

## Workflow

1. Run `cert_check_bundle` on target
2. If incomplete, review missing intermediates
3. Check AIA URL availability
4. If AIA resolves, server needs to serve the intermediate

## Cyberspace Mapping Applications

- Identify servers with broken certificate chains
- Diagnose TLS connectivity issues
- Track AIA support across CA infrastructure

## Limitations

- AIA fetch depends on URL availability
- Some CAs do not provide AIA URLs
- Fetched intermediates should be verified

## Related Skills

- [[cert_verify_chain]] cert_verify_chain
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
