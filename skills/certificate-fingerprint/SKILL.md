---
name: certificate-fingerprint
description: Use when generating certificate fingerprints (SHA-256, SHA-1, MD5, public key SHA-256) for SSL pinning, verification, or tracking. Triggers on mentions of cert fingerprint, SSL pin, SPKI hash, certificate hash, or fingerprint generation.
tools:
  - cert_fingerprint_domain
  - cert_fingerprint_file
---

# Certificate Fingerprint

> **TL;DR:** Generate certificate fingerprints (SHA-256, SHA-1, MD5, SPKI) for pinning and verification

## Capabilities

- SHA-256, SHA-1, MD5 certificate fingerprints
- Public key SHA-256 for SSL pinning
- Domain-based or file-based input

## Usage

```
cert_fingerprint_domain target="example.com"
cert_fingerprint_file target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target (domain)` | string (required) | Domain name or IP with optional port |
| `file_path (file)` | string (required) | Path to certificate file (PEM or DER) |

## Output

- SHA-256 fingerprint
- SHA-1 fingerprint
- MD5 fingerprint
- Public key SHA-256 (for SSL pinning)

## Workflow

1. Run `cert_fingerprint_domain` or `cert_fingerprint_file`
2. Record fingerprints for comparison
3. Use `cert_validate_fingerprint` to verify format
4. Use `cert_compare` to compare across domains

## AI Integration

### CLI (For AI Agents)

```bash
cert-skills fingerprint example.com                    # Text output
cert-skills fingerprint example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.GenerateFingerprints(cert)
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Build fingerprint databases for certificate tracking
- Detect unauthorized certificate changes via fingerprint monitoring
- Correlate certificates across domains via SPKI hash

## Limitations

- Fingerprints change on certificate renewal
- SPKI hash remains stable across renewals for same key

## Related Skills

- [[cert_validate_fingerprint]] cert_validate_fingerprint
- [[cert_compare]] cert_compare
- [[cert_info]] cert_info
