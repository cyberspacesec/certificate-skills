---
name: wildcard-checker
description: Analyze wildcard certificate patterns and assess security risk
tools:
  - cert_check_wildcard
  - cert_get_trusted_domains
---

# Wildcard Checker

> **TL;DR:** Analyze wildcard certificate patterns and assess security risk

## Capabilities

- Wildcard SAN detection
- Level classification (1-level, 2-level)
- Risk assessment (High/Medium/Low)
- Domain coverage analysis

## Usage

```
cert_check_wildcard target="example.com"
cert_get_trusted_domains target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Is wildcard
- Wildcard level
- Risk level
- Wildcard domains
- Covered base domains

## Workflow

1. Run `cert_check_wildcard` on target
2. If wildcard, review risk level
3. Check wildcard level
4. Use `cert_get_trusted_domains` for full extraction

## Cyberspace Mapping Applications

- Identify wildcard certificate coverage
- Assess wildcard risk for broad subdomain coverage
- Find over-broad wildcard certificates

## Limitations

- Risk assessment is advisory
- Does not enumerate actual subdomains

## Related Skills

- [[cert_get_trusted_domains]] cert_get_trusted_domains
- [[cert_ct_enumerate]] cert_ct_enumerate
- [[cert_scan_cert_security]] cert_scan_cert_security
