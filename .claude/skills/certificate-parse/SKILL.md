---
name: certificate-parse
description: Use when parsing a local certificate file (PEM or DER format) to display detailed information including subject, issuer, validity, SANs, key usage, and fingerprints. Triggers on mentions of parse cert file, read PEM, inspect certificate file, or decode DER.
allowed-tools: ["mcp__certificate-hacker__cert_parse"]
---

# certificate-parse

## When to Use

- User has a local certificate file (.pem, .crt, .cer, .der) and wants to inspect it
- User asks to decode or parse a certificate file
- User needs to check the details of a downloaded certificate
- User wants fingerprints of a local certificate file

## When NOT to Use

- User wants to inspect a remote domain's certificate (use certificate-info instead)
- User wants to generate a certificate (use certificate-generator instead)
- User wants to validate a cert-key pair (use certificate-validate instead)

## Instructions

1. Get the file path from the user
2. Run the MCP tool on the file:
   `cert_parse(file_path="/path/to/cert.pem")`
3. Present: subject, issuer, validity dates, SANs, key usage, extended key usage
4. Show fingerprints (SHA-256, SHA-1, MD5)
5. If the certificate is expired or expiring soon, highlight this
6. If the user needs fingerprint extraction, note the public key SHA-256 for pinning

**CLI equivalent:**
`cert-skills parse /path/to/cert.pem -o json`

**Supported formats:** PEM, DER, .pem, .crt, .cer, .der

## Anti-Patterns

- Don't use this for remote domains — use certificate-info instead
- Don't assume the file is PEM format — DER is also supported
- Don't skip the validity check — expired certificates are a critical finding
