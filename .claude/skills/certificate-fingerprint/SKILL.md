---
name: certificate-fingerprint
description: Use when generating certificate fingerprints (SHA-256, SHA-1, MD5, public key SHA-256) for SSL pinning, verification, or tracking. Triggers on mentions of cert fingerprint, SSL pin, SPKI hash, certificate hash, or fingerprint generation.
allowed-tools: ["mcp__certificate-skills__cert_fingerprint_domain", "mcp__certificate-skills__cert_fingerprint_file"]
---

# certificate-fingerprint

## When to Use

- User needs certificate fingerprints for SSL pinning
- User wants SHA-256, SHA-1, or MD5 hashes of a certificate
- User asks for public key hash (SPKI) for pinning
- User wants to track or identify a certificate by its fingerprint

## When NOT to Use

- User wants to validate a fingerprint format (use fingerprint-validator instead)
- User wants to search CT logs by fingerprint (use ct-fingerprint-search instead)
- User wants full certificate details (use certificate-info instead)

## Instructions

1. Determine the source: domain or local file
2. For a domain, run:
   `cert_fingerprint_domain(target="DOMAIN")`
3. For a local file, run:
   `cert_fingerprint_file(file_path="/path/to/cert.pem")`
4. Present all fingerprints: SHA-256, SHA-1, MD5, and public key SHA-256
5. Highlight the public key SHA-256 for SSL pinning use cases
6. If the user wants to validate a fingerprint format, suggest fingerprint-validator
7. If the user wants to search CT logs, suggest ct-fingerprint-search

**CLI equivalent:**
`cert-skills fingerprint DOMAIN -o json`

**For SSL pinning:** Use the public key SHA-256 (SPKI hash) — it survives certificate renewal if the key stays the same

## Anti-Patterns

- Don't use SHA-1 or MD5 for security purposes — they are for compatibility only
- Don't confuse certificate fingerprint with public key fingerprint — they serve different purposes
- Don't use the certificate SHA-256 for pinning — use public key SHA-256 instead
