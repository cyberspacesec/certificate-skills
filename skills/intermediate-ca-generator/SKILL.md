---
name: intermediate-ca-generator
description: Generate intermediate CA certificates signed by a parent/root CA. Creates multi-tier PKI hierarchies.
tools:
  - cert_generate_intermediate_ca
---

# Intermediate CA Generator

## Capabilities
- Generate intermediate CA certificates signed by a root CA
- Create multi-tier PKI hierarchies (Root → Intermediate → Leaf)
- Configure path length constraints
- Support RSA 4096, ECDSA P-384, and Ed25519 keys
- Inherit subject fields from parent CA

## Usage

### CLI
```bash
# Generate intermediate CA
cert-skills generate-intermediate-ca \
  --parent-cert root-ca.pem --parent-key root-ca-key.pem \
  -n "My Intermediate CA"

# With ECDSA key
cert-skills generate-intermediate-ca \
  --parent-cert root-ca.pem --parent-key root-ca-key.pem \
  -n "Sub CA" --key-type ecdsa

# Allow further intermediate CAs
cert-skills generate-intermediate-ca \
  --parent-cert root-ca.pem --parent-key root-ca-key.pem \
  -n "Sub CA" --path-len -1
```

### MCP
```
cert_generate_intermediate_ca(parent_cert_path, parent_key_path, common_name, key_type, ...)
```

## Workflow
1. Generate root CA: `cert-skills generate --common-name "Root CA" --is-ca --validity-days 3650 --key-size 4096`
2. Generate intermediate CA: `cert-skills generate-intermediate-ca --parent-cert Root-CA.pem --parent-key Root-CA-key.pem -n "Intermediate CA"`
3. Sign leaf certificates: `cert-skills sign-cert --ca-cert Intermediate-CA.pem --ca-key Intermediate-CA-key.pem -n server.local`

## AI Integration
Use this skill when building multi-tier PKI hierarchies, creating intermediate CAs for different departments or purposes, or setting up certificate chains for testing.
