---
name: trusted-domains-extractor
description: Extract all trusted domains from a certificate for cyberspace mapping
tools:
  - cert_get_trusted_domains
  - cert_check_wildcard
---

# Trusted Domains Extractor

> **TL;DR:** Extract all trusted domains from a certificate for cyberspace mapping

## Capabilities

- Complete domain extraction from SAN and CN
- Wildcard detection and base domain identification
- Base domain deduplication
- Organization attribution
- IP address extraction

## Usage

```
cert_get_trusted_domains target="example.com"
cert_check_wildcard target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Common Name
- All domains
- Exact vs wildcard domains
- Unique base domains
- IP addresses
- Organization

## Workflow

1. Run `cert_get_trusted_domains` on target
2. Review all domain names
3. Check wildcard domains
4. Identify base domains for subdomain enumeration
5. Cross-reference with `cert_ct_enumerate`

## Cyberspace Mapping Applications

- Discover subdomains through certificate data
- Link domains to organizations
- Evaluate wildcard certificate risk
- Cross-domain correlation through shared certificates

## Limitations

- Only shows domains in current certificate
- Wildcards represent potential coverage, not actual subdomains

## Related Skills

- [[cert_check_wildcard]] cert_check_wildcard
- [[cert_ct_enumerate]] cert_ct_enumerate
- [[cert_search_ct]] cert_search_ct
- [[cert_info]] cert_info
