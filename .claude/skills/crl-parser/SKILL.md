---
name: crl-parser
description: Use when parsing Certificate Revocation List (CRL) files, displaying revoked certificates, verifying CRL signatures, or checking whether a certificate appears in a CRL. Triggers on mentions of parse CRL, inspect revocation list, CRL signature, revoked serial, or check cert in CRL.
allowed-tools:
  - mcp__certificate-skills__cert_parse_crl
  - mcp__certificate-skills__cert_verify_crl_signature
  - mcp__certificate-skills__cert_check_revoked_by_crl
---

# CRL Parser

## When to Use
- Parse a CRL file to view its contents
- Verify that a CRL was signed by a specific CA
- Check if a certificate is listed as revoked in a CRL

## When NOT to Use
- Generating new CRLs (use `crl-generator`)
- Checking OCSP revocation (use `certificate-revocation`)

## Instructions
1. Call `cert_parse_crl` with the CRL file path to view its contents
2. Use `cert_verify_crl_signature` to verify the CRL was signed by a specific CA
3. Use `cert_check_revoked_by_crl` to check if a specific certificate is revoked

## Anti-Patterns
- Do not assume CRL is authoritative without verifying its signature
