---
name: certificate-generator
description: Generate self-signed SSL/TLS certificates for testing and development
tools:
  - cert_generate
---

# Certificate Generator

> **TL;DR:** Generate self-signed SSL/TLS certificates for testing and development

## Capabilities

- RSA 2048/4096-bit, ECDSA P-256/P-384/P-521, Ed25519 keys
- CA certificate generation
- Custom Subject Alternative Names (DNS, IP)
- Configurable validity period

## Usage

```
cert_generate target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `common_name` | string (required) | Common Name (CN) for the certificate |
| `key_type` | string | rsa (default), ecdsa, ed25519 |
| `is_ca` | boolean | Generate CA certificate (default: false) |
| `dns_names` | array | DNS SANs |
| `validity_days` | number | Certificate validity (default: 365) |

## Output

- Certificate PEM file path
- Private key PEM file path
- Fingerprints of generated certificate

## Workflow

1. Determine certificate requirements (key type, SANs, validity)
2. Run `cert_generate` with parameters
3. Use `cert_parse` to verify generated certificate
4. Deploy certificate to test server

## Cyberspace Mapping Applications

- Generate test certificates for security lab environments
- Create CA certificates for internal PKI testing
- Produce certificates with specific weaknesses for vulnerability testing

## Limitations

- Self-signed certificates are NOT for production use
- Browsers will show security warnings for self-signed certs

## Related Skills

- [[cert_generate_csr]] cert_generate_csr
- [[cert_parse]] cert_parse
- [[cert_validate_files]] cert_validate_files
- [[cert_fingerprint_file]] cert_fingerprint_file
