---
name: hsts-checker
description: Check HSTS (HTTP Strict Transport Security) status and policy compliance
tools:
  - cert_check_hsts
---

# Hsts Checker

> **TL;DR:** Check HSTS (HTTP Strict Transport Security) status and policy compliance

## Capabilities

- HSTS header detection and parsing
- max-age value verification
- includeSubDomains and preload check
- SSL stripping vulnerability assessment

## Usage

```
cert_check_hsts target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name to check HSTS status |

## Output

- HSTS enabled status
- max-age (seconds and days)
- includeSubDomains status
- preload status
- Raw header value

## Workflow

1. Run `cert_check_hsts` on target
2. If enabled, verify max-age >= 1 year
3. Check includeSubDomains for broad protection
4. If disabled, assess SSL stripping risk

## Cyberspace Mapping Applications

- Assess HSTS coverage across infrastructure
- Identify domains vulnerable to SSL stripping
- Track HSTS adoption and policy quality

## Limitations

- Requires HTTPS connection
- Does not check HSTS preload list submission status

## Related Skills

- [[cert_analyze_security]] cert_analyze_security
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_pfs]] cert_check_pfs
