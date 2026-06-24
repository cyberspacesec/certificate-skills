---
name: cert-cloner
description: Clone certificates by copying subject info and generating new keys. For authorized security testing only.
allowed-tools:
  - mcp__certificate-hacker__cert_clone_certificate
---

# Certificate Cloner

## When to Use
- Clone a certificate for security testing (authorized penetration testing only)
- Create a modified copy of a certificate with different subject info
- Generate test certificates that match a target's subject structure
- Security research on certificate validation implementations

## When NOT to Use
- Generating new certificates from scratch (use `certificate-generator` or `ca-signer`)
- Legitimate certificate issuance (use proper CA workflows)
- Any unauthorized or malicious purpose

## Instructions
1. Call `cert_clone_certificate` with the source certificate path
2. The clone will have the same subject info and extensions but different key pair and serial number
3. Use `modify_subject=true` with `new_common_name` to modify the CN
4. Optionally specify CA cert/key to get a CA-signed clone instead of self-signed

## WARNING
Cloned certificates are for AUTHORIZED SECURITY TESTING ONLY. They will:
- Have different fingerprints than the original
- NOT be trusted by standard PKI systems
- Be detectable by proper certificate validation

## Anti-Patterns
- Do not use for impersonation or fraud
- Do not use cloned certificates in production systems
- Do not bypass proper certificate validation in security tests
