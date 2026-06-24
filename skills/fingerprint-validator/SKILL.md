---
name: fingerprint-validator
description: Use when validating certificate fingerprint format correctness for SHA-256, SHA-1, or MD5. Triggers on mentions of validate fingerprint, check hash format, verify fingerprint, or fingerprint format check.
tools:
  - cert_validate_fingerprint
---

# Fingerprint Validator

> **TL;DR:** Validate certificate fingerprint format correctness for SHA-256, SHA-1, or MD5

## Capabilities

- SHA-256 format validation (64 hex chars)
- SHA-1 format validation (40 hex chars)
- MD5 format validation (32 hex chars)
- Colon separator handling

## Usage

```
cert_validate_fingerprint target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `fingerprint` | string (required) | Fingerprint hex string (colons optional) |
| `hash_type` | string (required) | Hash algorithm: sha256, sha1, or md5 |

## Output

- Whether fingerprint is valid
- Error description if invalid

## Workflow

1. Obtain fingerprint from `cert_fingerprint_domain` or manual source
2. Run `cert_validate_fingerprint` with fingerprint and hash type
3. If valid, use with `cert_search_ct_fingerprint`

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills validate-fingerprint example.com                    # Text output
cert-skills validate-fingerprint example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.ValidateFingerprint(fp, hashType)
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Validate fingerprint data before database storage
- Ensure fingerprint consistency in bulk imports

## Limitations

- Validates format only, not whether fingerprint matches a real certificate

## Related Skills

- [[cert_fingerprint_domain]] cert_fingerprint_domain
- [[cert_fingerprint_file]] cert_fingerprint_file
- [[cert_search_ct_fingerprint]] cert_search_ct_fingerprint
