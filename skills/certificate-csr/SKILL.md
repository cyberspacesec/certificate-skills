---
name: certificate-csr
description: Generate a Certificate Signing Request (CSR) for submitting to a CA
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
