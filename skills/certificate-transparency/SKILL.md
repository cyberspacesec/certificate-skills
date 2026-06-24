---
name: certificate-transparency
description: Use when searching Certificate Transparency (CT) logs for certificates associated with a domain. Triggers on mentions of CT log search, certificate transparency, find certificates for domain, or CT lookup.
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

## References

- [CT log guide](references/ct-log-guide.md) - Read when explaining CT log sources, query behavior, or certificate discovery limits.

## AI Integration

### CLI (For AI Agents)

```bash
cert-skills search-ct example.com                    # Text output
cert-skills search-ct example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CTSearch("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

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
