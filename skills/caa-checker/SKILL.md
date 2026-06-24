---
name: caa-checker
description: Use when checking DNS CAA (Certification Authority Authorization) records to verify CA authorization for certificate issuance. Triggers on mentions of CAA records, CAA check, certificate authorization, CAA misconfiguration, or unauthorized certificate issuance.
tools:
  - cert_check_caa
---

# Caa Checker

> **TL;DR:** Check DNS CAA records and verify CA authorization for certificate issuance

## Capabilities

- DNS CAA record querying (issue, issuewild, iodef)
- CA authorization verification
- Misconfiguration detection
- Compliance checking

## Usage

```
cert_check_caa target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name to check CAA records for |

## Output

- CAA records existence
- Record details (flag, tag, value)
- CA authorization status
- IODEF reporting URL

## Workflow

1. Run `cert_check_caa` on target domain
2. If CAA exists, verify issuing CA is authorized
3. If no CAA, any CA can issue (consider adding CAA)
4. Recommend CAA policy for restricted issuance

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills check-caa example.com                    # Text output
cert-skills check-caa example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckCAA("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Identify which CAs are authorized for a domain
- Detect unauthorized certificate issuance through CAA
- Map CA relationships and trust boundaries

## Limitations

- Requires DNS resolution
- Not all DNS resolvers support CAA type
- CAA is only checked by compliant CAs

## Related Skills

- [[cert_verify_chain]] cert_verify_chain
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
- [[cert_search_ct]] cert_search_ct
