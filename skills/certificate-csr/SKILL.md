---
name: certificate-csr
description: Use when generating a Certificate Signing Request (CSR) for submitting to a Certificate Authority. Triggers on mentions of generate CSR, create signing request, CSR generation, or certificate request.
tools:
  - cert_generate_csr
---

# Certificate Csr

> **TL;DR:** Generate a Certificate Signing Request (CSR) for submitting to a CA

## Capabilities

- RSA 2048/4096-bit, ECDSA P-256/P-384/P-521, Ed25519 keys
- Subject Alternative Names support
- Private key generated but NOT saved to disk

## Usage

```
cert_generate_csr target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `common_name` | string (required) | Primary domain name for the CSR |
| `key_type` | string | Key algorithm: rsa (default), ecdsa, ed25519 |
| `dns_names` | array | Additional DNS names for SANs |

## Output

- PEM-encoded CSR text content
- Suitable for submission to Let's Encrypt, DigiCert, etc.

## Workflow

1. Determine domain name and key requirements
2. Run `cert_generate_csr` with parameters
3. Copy the CSR output
4. Submit CSR to your Certificate Authority

## References

- [CSR parameters](references/csr-parameters.md) - Read when choosing subject fields, SANs, key algorithms, or CSR options.

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills generate-csr example.com                    # Text output
cert-skills generate-csr example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.GenerateCSR(commonName, opts...)
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Generate CSRs for bulk domain certificate provisioning
- Standardize key algorithms across infrastructure
- Automate CSR generation for CI/CD pipelines

## Limitations

- Private key is NOT saved to disk for security
- Must save private key separately before closing session

## Related Skills

- [[cert_generate]] cert_generate
- [[cert_validate_files]] cert_validate_files
- [[cert_parse]] cert_parse
