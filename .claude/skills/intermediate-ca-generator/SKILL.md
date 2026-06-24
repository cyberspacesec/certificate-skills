---
name: intermediate-ca-generator
description: Generate intermediate CA certificates signed by a parent/root CA. Creates multi-tier PKI hierarchies.
allowed-tools:
  - mcp__certificate-skills__cert_generate_intermediate_ca
---

# Intermediate CA Generator

## When to Use
- Create a multi-tier PKI hierarchy (Root CA → Intermediate CA → End-entity)
- Generate an intermediate CA for a specific department or purpose
- Build certificate chains for testing and development

## When NOT to Use
- Generating a root CA (use `certificate-generator` with `--is-ca`)
- Signing end-entity/leaf certificates (use `ca-signer`)
- Generating self-signed server certificates (use `certificate-generator`)

## Instructions
1. First generate a root CA using `certificate-generator` with `is_ca=true`
2. Call `cert_generate_intermediate_ca` with the root CA cert/key paths
3. Set `path_len_constraint` to control whether the intermediate CA can issue further intermediate CAs (0 = no, -1 = unlimited)
4. Use longer key sizes (RSA 4096, ECDSA P-384) for intermediate CAs
5. Set appropriate validity (typically 5 years / 1825 days)

## Anti-Patterns
- Do not use short key sizes for intermediate CAs (minimum RSA 4096, ECDSA P-384)
- Do not set unlimited path length unless necessary
- Do not share intermediate CA private keys
