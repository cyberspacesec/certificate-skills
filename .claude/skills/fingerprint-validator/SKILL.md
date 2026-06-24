---
name: fingerprint-validator
description: Use when validating certificate fingerprint format correctness for SHA-256, SHA-1, or MD5. Triggers on mentions of validate fingerprint, check hash format, verify fingerprint, or fingerprint format check.
allowed-tools: ["mcp__certificate-hacker__cert_validate_fingerprint"]
---

# fingerprint-validator

## When to Use

- User has a fingerprint string and wants to verify it's correctly formatted
- User needs to validate a fingerprint before using it in a search or comparison
- User asks if a hash string is a valid SHA-256, SHA-1, or MD5 fingerprint

## When NOT to Use

- User wants to generate fingerprints (use certificate-fingerprint instead)
- User wants to search CT logs (use ct-fingerprint-search instead — but validate first)

## Instructions

1. Get the fingerprint string and hash type from the user
2. Run the MCP tool:
   `cert_validate_fingerprint(fingerprint="AB:CD:EF...", hash_type="sha256")`
3. Report whether the fingerprint is valid or invalid
4. If invalid, explain the specific format error
5. If valid, suggest next steps: ct-fingerprint-search or certificate-comparison

**CLI equivalent:**
`cert-skills validate-fingerprint -f "AB:CD:EF..." -t sha256`

**Hash type options:** sha256 (64 hex chars), sha1 (40 hex chars), md5 (32 hex chars)

## Anti-Patterns

- Don't skip validation before CT search — invalid fingerprints waste API calls
- Don't assume colon-separated format is required — both formats are accepted
- Don't validate against the wrong hash type — SHA-256 fingerprints are 64 chars, not 40
