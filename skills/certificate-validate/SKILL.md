---
name: certificate-validate
description: Use when validating that a certificate and private key file match and are correctly formatted PEM files. Triggers on mentions of validate cert key pair, check PEM format, verify certificate matches key, or cert-key validation.
tools:
  - cert_validate_files
---

# Certificate Validate

> **TL;DR:** Validate that certificate and private key files match and are correctly formatted

## Capabilities

- PEM format validation
- Public key matching verification
- RSA, ECDSA, Ed25519 support
- Detailed error reporting

## Usage

```
cert_validate_files target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `cert_path` | string (required) | Path to certificate PEM file |
| `key_path` | string (required) | Path to private key PEM file |

## Output

- PEM format validity for both files
- Whether public key matches private key
- Key type identification
- Error details if validation fails

## Workflow

1. Obtain certificate and key file paths
2. Run `cert_validate_files` with both paths
3. Check PEM format validity
4. Verify key pair matches

## References

- [Validation details](references/validation-details.md) - Read when explaining certificate-key matching, PEM parsing, or validation failures.

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills validate example.com                    # Text output
cert-skills validate example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.ValidateCertificateFiles(certPath, keyPath)
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Validate certificate-key pairs before deployment
- Bulk validation of certificate collections
- Detect misconfigured TLS deployments

## Limitations

- Requires local file access
- Does not verify certificate chain or trust

## Related Skills

- [[cert_parse]] cert_parse
- [[cert_generate]] cert_generate
- [[cert_fingerprint_file]] cert_fingerprint_file
