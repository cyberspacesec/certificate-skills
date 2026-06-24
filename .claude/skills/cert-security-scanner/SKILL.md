---
name: cert-security-scanner
description: Use when scanning for certificate-specific security issues (18 checks from CERT-001 to CERT-018), checking for weak signatures, short keys, hostname mismatches, distrusted CAs, or compliance violations. Triggers on mentions of cert security scan, CERT checks, certificate compliance, or PKI audit.
allowed-tools: ["mcp__certificate-hacker__cert_scan_cert_security"]
---

# cert-security-scanner

## When to Use

- User wants comprehensive certificate security checks (all 18 CERT-xxx checks)
- User asks about certificate compliance or PKI audit
- User needs to check for weak signatures, short keys, or hostname mismatches
- User wants to verify no distrusted CA is in the chain
- User mentions CERT-001 through CERT-018 checks

## When NOT to Use

- User wants only a security score (use certificate-analysis instead)
- User needs TLS vulnerability scanning (use tls-vulnerability-scanner instead)
- User asks about a single specific check (use the specialized skill directly)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_scan_cert_security(target="DOMAIN")`
2. Check the summary: total checks, passed, failed, is_secure status
3. Focus on Critical and High severity failures first
4. Present each failure with its CERT code, description, and severity
5. For CERT-014 (Distrusted CA), emphasize this as a Critical finding
6. For CERT-015 (OCSP Must-Staple) or CERT-016 (Key Usage), explain the compliance implications
7. Suggest the relevant specialized skill for any failed check

**CERT Check Reference:**
- CERT-001~005: Weak signature, short RSA, weak ECDSA, missing SAN, hostname mismatch
- CERT-006~010: Excessive validity, self-signed, expired, expiring soon, CN not in SANs
- CERT-011~013: Wildcard risk, internal name, untrusted chain
- CERT-014~018: Distrusted CA, OCSP Must-Staple, key usage, serial entropy, name constraints

**CLI equivalent:**
`cert-skills scan-cert-security DOMAIN -o json`

## Anti-Patterns

- Don't treat all 18 checks as equally important — prioritize Critical > High > Medium > Low
- Don't run this when the user only needs one specific check — use the targeted skill
- Don't ignore the is_secure summary flag
