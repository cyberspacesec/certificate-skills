---
name: ct-subdomain-enumerator
description: Enumerate subdomains through Certificate Transparency logs
tools:
  - cert_ct_enumerate
---

# Ct Subdomain Enumerator

> **TL;DR:** Enumerate subdomains through Certificate Transparency logs

## Capabilities

- Subdomain discovery from CT certificates
- Wildcard certificate detection
- Issuer grouping
- Active/expired tracking
- Organization mapping

## Usage

```
cert_ct_enumerate target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string (required) | Domain name to enumerate subdomains for |

## Output

- Total certificates found
- Active vs expired counts
- Unique subdomain list
- Wildcard domains
- Per-issuer grouping

## Workflow

1. Run `cert_ct_enumerate` on target domain
2. Review unique subdomain list
3. Check wildcard domains
4. Group by issuer for CA relationships

## Cyberspace Mapping Applications

- Passive subdomain enumeration (no direct scanning)
- Discover organizational domain infrastructure
- Track certificate issuance patterns over time

## Limitations

- Only finds subdomains that have certificates
- CT logs may have delays
- Wildcard certificates reveal base domain only

## Related Skills

- [[cert_search_ct]] cert_search_ct
- [[cert_search_ct_fingerprint]] cert_search_ct_fingerprint
- [[cert_check_wildcard]] cert_check_wildcard
