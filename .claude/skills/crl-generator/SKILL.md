---
name: crl-generator
description: Use when generating Certificate Revocation Lists (CRLs), listing revoked certificate serials, or assigning RFC 5280 revocation reason codes. Triggers on mentions of generate CRL, create revocation list, revoke certificate by serial, CRL signing, or revocation reason.
allowed-tools:
  - mcp__certificate-skills__cert_generate_crl
  - mcp__certificate-skills__cert_parse_crl
  - mcp__certificate-skills__cert_verify_crl_signature
  - mcp__certificate-skills__cert_check_revoked_by_crl
---

# CRL Generator

## When to Use
- Generate a CRL to publish a list of revoked certificates
- Revoke a compromised certificate by its serial number
- Verify CRL signatures against CA certificates
- Check if a specific certificate is revoked in a CRL

## When NOT to Use
- Checking OCSP revocation status (use `certificate-revocation`)
- Generating CA certificates (use `certificate-generator`)

## Instructions
1. Call `cert_generate_crl` with CA cert/key and a list of serial numbers to revoke
2. Optionally specify revocation reasons: key-compromise, ca-compromise, superseded, etc.
3. Use `cert_parse_crl` to inspect an existing CRL
4. Use `cert_verify_crl_signature` to verify CRL authenticity
5. Use `cert_check_revoked_by_crl` to check if a specific cert is revoked

## Revocation Reason Codes (RFC 5280)
- unspecified (0), key-compromise (1), ca-compromise (2), affiliation-changed (3)
- superseded (4), cessation-of-operation (5), certificate-hold (6)
- privilege-withdrawn (9), aa-compromise (10)

## Anti-Patterns
- Do not generate CRLs without proper CA authorization
- Do not forget to publish updated CRLs regularly
