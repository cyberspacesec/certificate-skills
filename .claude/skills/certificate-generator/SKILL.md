---
name: certificate-generator
description: Use when generating self-signed SSL/TLS certificates for testing and development. Triggers on mentions of generate cert, self-signed certificate, create test cert, make SSL cert, or generate CA certificate.
allowed-tools: ["mcp__certificate-hacker__cert_generate"]
---

# certificate-generator

## When to Use

- User needs a self-signed certificate for testing or development
- User wants to generate a CA (Certificate Authority) certificate
- User asks to create a certificate with specific key type (RSA, ECDSA, Ed25519)
- User needs a test certificate with Subject Alternative Names

## When NOT to Use

- User needs a production certificate (self-signed certs are NOT for production)
- User wants a Certificate Signing Request (use certificate-csr instead)
- User wants to validate an existing certificate (use certificate-validate instead)

## Instructions

1. Determine the user's requirements:
   - Common Name (CN) — required, typically the domain name
   - Key type: rsa (default), ecdsa, or ed25519
   - Key size: RSA 2048/4096, ECDSA P-256/P-384/P-521
   - Is CA certificate? (default: false)
   - DNS SANs: additional domain names
   - IP SANs: IP addresses
   - Validity period in days (default: 365)
2. Run the MCP tool:
   `cert_generate(common_name="test.local", key_type="ecdsa", key_size=256, dns_names=["www.test.local"], ip_addresses=["127.0.0.1"])`
3. Report the saved file paths (certificate PEM and private key PEM)
4. Remind the user: self-signed certificates are for testing only
5. Suggest certificate-parse to verify the generated certificate

**CLI equivalent:**
`cert-skills generate -n test.local -k ecdsa -o json`

**⚠️ WARNING:** Self-signed certificates are for testing/development only, NOT for production use.

## Anti-Patterns

- Don't generate self-signed certificates for production — always warn the user
- Don't forget to include SANs — modern browsers reject certificates without SANs
- Don't generate CA certificates unless specifically requested
- Don't use short key sizes (<2048 for RSA, <256 for ECDSA)
