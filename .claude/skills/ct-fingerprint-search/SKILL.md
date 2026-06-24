---
name: ct-fingerprint-search
description: Use when searching Certificate Transparency logs by SHA-256 certificate fingerprint. Triggers on mentions of CT fingerprint search, find cert by hash, track certificate fingerprint, or fingerprint CT lookup.
allowed-tools: ["mcp__certificate-skills__cert_search_ct_fingerprint"]
---

# ct-fingerprint-search

## When to Use

- User has a certificate fingerprint and wants to find it in CT logs
- User needs to verify CT log inclusion for a specific certificate
- User wants to track a specific certificate across CT logs
- User asks to find all instances of a known certificate

## When NOT to Use

- User wants to search by domain name (use certificate-transparency instead)
- User wants to generate a fingerprint (use certificate-fingerprint first)
- User has a fingerprint but hasn't validated it (use fingerprint-validator first)

## Instructions

1. Obtain the SHA-256 fingerprint (from certificate-fingerprint or user input)
2. Validate the fingerprint format first using fingerprint-validator
3. Run the MCP tool:
   `cert_search_ct_fingerprint(fingerprint="AB:CD:EF:...")`
4. Report: total certificates found, certificate details, CT log inclusion
5. If the certificate is found, show CN, issuer, and validity
6. If not found, the certificate may not be publicly trusted or CT-logged

**CLI equivalent:**
`cert-skills search-ct-fingerprint -f "AB:CD:EF:..." -o json`

**Tip:** Use certificate-fingerprint to generate the fingerprint first, then search CT logs.

## Anti-Patterns

- Don't search with an invalid fingerprint — validate first
- Don't assume absence from CT logs means the certificate doesn't exist — it may be private/internal
- Don't confuse fingerprint search with domain search — they serve different purposes
