---
name: certificate-compare
description: Use when comparing two SSL/TLS certificates to determine if they are identical or different. Triggers on mentions of compare certificates, cert diff, certificate match, or check if two certs are the same.
tools:
  - cert_compare
---

# Certificate Compare

> **TL;DR:** Compare two SSL/TLS certificates to determine if they are identical or different

## Capabilities

- Fingerprint comparison (SHA-256, SHA-1, MD5)
- Subject and issuer comparison
- Validity period and key algorithm comparison
- Mixed: domain vs domain, file vs file, domain vs file

## Usage

```
cert_compare target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target1` | string (required) | First certificate target (domain or file path) |
| `target2` | string (required) | Second certificate target (domain or file path) |

## Output

- Whether certificates are identical or different
- Fingerprint comparison
- Differences in subject, issuer, validity, key details

## Workflow

1. Obtain two certificate targets (domains or local files)
2. Run `cert_compare` with both targets
3. Review fingerprint match results
4. Check specific differences if certificates differ

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills compare example.com                    # Text output
cert-skills compare example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CompareCertsFromDomains("a.com", "b.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Verify certificate deployment consistency across load balancers
- Detect unauthorized certificate replacements
- Compare certificates across related domains for shared issuers

## Limitations

- Both targets must be accessible
- Cannot compare more than two certificates at once

## Related Skills

- [[cert_fingerprint_domain]] cert_fingerprint_domain
- [[cert_fingerprint_file]] cert_fingerprint_file
- [[cert_info]] cert_info
