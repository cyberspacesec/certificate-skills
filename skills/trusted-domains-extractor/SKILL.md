---
name: trusted-domains-extractor
description: Use when extracting all domain names trusted by a certificate for cyberspace mapping, including wildcard expansions and base domain identification. Triggers on mentions of trusted domains, cert domains, extract domains, domain extraction, or cert namespace.
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

## AI Integration

### CLI (For AI Agents)

```bash
cert-skills get-trusted-domains example.com                    # Text output
cert-skills get-trusted-domains example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.GetTrustedDomains("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

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
