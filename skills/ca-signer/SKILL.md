---
name: ca-signer
description: Sign terminal/leaf certificates using a CA certificate and private key. Creates server, client, or dual-purpose certificates.
tools:
  - cert_sign_certificate
---

# CA Certificate Signer

## Capabilities
- Sign server authentication certificates using a CA
- Sign client authentication certificates
- Sign dual-purpose (server+client) certificates
- Inherit subject fields from the CA certificate
- Support RSA, ECDSA, and Ed25519 key types
- Generate certificates with proper key usage extensions

## Usage

### CLI
```bash
# Sign a server certificate
cert-skills sign-cert --ca-cert ca.pem --ca-key ca-key.pem --common-name app.example.com

# Sign with custom key type
cert-skills sign-cert --ca-cert ca.pem --ca-key ca-key.pem -n app.example.com --key-type ecdsa

# Sign a client certificate
cert-skills sign-cert --ca-cert ca.pem --ca-key ca-key.pem -n client.example.com --key-usage client

# Sign with SANs
cert-skills sign-cert --ca-cert ca.pem --ca-key ca-key.pem -n app.example.com --dns-names app.example.com,api.example.com
```

### MCP
```
cert_sign_certificate(ca_cert_path, ca_key_path, common_name, key_usage, key_type, ...)
```

## Workflow
1. Generate a root CA: `cert-skills generate --common-name "My Root CA" --is-ca --validity-days 3650`
2. Sign end-entity certificates: `cert-skills sign-cert --ca-cert My-Root-CA.pem --ca-key My-Root-CA-key.pem -n server.local`
3. Validate the chain: `cert-skills verify-chain server.local`

## AI Integration
Use this skill when the user needs to create certificates signed by a CA, build PKI hierarchies, or generate TLS server/client certificates for testing.
