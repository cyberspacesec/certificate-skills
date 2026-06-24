---
name: ca-signer
description: Sign terminal/leaf certificates using a CA certificate and private key. Creates server, client, or dual-purpose certificates.
allowed-tools:
  - mcp__certificate-hacker__cert_sign_certificate
---

# CA Certificate Signer

## When to Use
- Sign a server certificate using a CA (e.g., after creating a root CA)
- Create client authentication certificates
- Generate dual-purpose (server+client) certificates signed by a CA
- Build a PKI hierarchy with CA-signed certificates

## When NOT to Use
- Generating self-signed certificates (use `certificate-generator` instead)
- Generating CA certificates (use `certificate-generator` or `intermediate-ca-generator`)
- Creating CSRs for public CAs (use `certificate-csr` instead)

## Instructions
1. Ensure you have a CA certificate and its private key (generated via `certificate-generator --is-ca` or `intermediate-ca-generator`)
2. Call `cert_sign_certificate` with the CA cert/key paths and desired certificate parameters
3. The `key_usage` parameter determines the certificate type: "server" (TLS server auth), "client" (client auth), or "both"
4. Subject fields (organization, country, etc.) default to inheriting from the CA certificate
5. The output includes the certificate path, key path, fingerprints, and serial number

## Anti-Patterns
- Do not use CA keys for end-entity certificates
- Do not create excessively long validity periods (>825 days for public certs)
- Do not reuse serial numbers across certificates
