---
name: certificate-transparency
description: Search Certificate Transparency logs for domain certificates
tools:
  - cert_search_ct
---

# Certificate Transparency

> **TL;DR:** Search Certificate Transparency logs for domain certificates

## Capabilities

- Domain-based CT log search
- Certificate issuance history
- Issuer identification
- Subdomain discovery via cert SANs
- Active/expired tracking

## Usage

```
cert_search_ct target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name to search CT logs for |

## Output

- Total certificate count
- Certificate details (CN, issuer, validity, SANs)
- SHA-256 fingerprints
- Active vs expired status

## Workflow

1. Run `cert_search_ct` on target domain
2. Review total certificate count
3. Check for unexpected issuers
4. Identify subdomains from SANs
5. Use `cert_ct_enumerate` for focused subdomain enumeration

## Cyberspace Mapping Applications

- Discover subdomains through certificate data (passive reconnaissance)
- Identify unauthorized certificates for a domain
- Track certificate issuance patterns over time

## Limitations

- CT logs may have delays in inclusion
- Rate limiting may apply for frequent queries

## Related Skills

- [[cert_ct_enumerate]] cert_ct_enumerate
- [[cert_search_ct_fingerprint]] cert_search_ct_fingerprint
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
