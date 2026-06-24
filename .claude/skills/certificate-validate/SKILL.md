---
name: certificate-validate
description: Use when validating that a certificate and private key file match and are correctly formatted PEM files. Triggers on mentions of validate cert key pair, check PEM format, verify certificate matches key, or cert-key validation.
allowed-tools: ["mcp__certificate-skills__cert_validate_files"]
---

# certificate-validate

## When to Use

- User has a certificate and private key file and needs to verify they match
- User wants to check if PEM files are correctly formatted
- User is deploying a certificate and wants to ensure cert-key pairing is correct
- User sees SSL errors and suspects cert-key mismatch

## When NOT to Use

- User wants to validate a remote domain's certificate (use chain-verifier instead)
- User wants to parse a certificate file (use certificate-parse instead)
- User wants to generate a certificate (use certificate-generator instead)

## Instructions

1. Get both file paths from the user
2. Run the MCP tool:
   `cert_validate_files(cert_path="/path/to/cert.pem", key_path="/path/to/key.pem")`
3. Report: PEM validity for both files, key pair match status
4. If validation fails, explain the specific error (format error vs key mismatch)
5. If key types don't match or files are malformed, suggest regeneration

**CLI equivalent:**
`cert-skills validate -c /path/to/cert.pem -k /path/to/key.pem -o json`

**Supported key types:** RSA, ECDSA, Ed25519

## Anti-Patterns

- Don't assume a format error means the key is wrong — it might just be encoding
- Don't skip this check before deploying certificates — mismatched pairs cause immediate failures
- Don't expose private key contents in error messages
