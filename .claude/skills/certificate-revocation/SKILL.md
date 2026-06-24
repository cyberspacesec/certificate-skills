---
name: certificate-revocation
description: Use when checking certificate revocation status via OCSP (Online Certificate Status Protocol) and CRL (Certificate Revocation List). Triggers on mentions of cert revocation, OCSP check, CRL check, revoked certificate, or certificate revoked.
allowed-tools: ["mcp__certificate-hacker__cert_check_revocation"]
---

# certificate-revocation

## When to Use

- User wants to check if a certificate has been revoked
- User asks about OCSP or CRL status
- User suspects a certificate may be compromised
- User needs to verify certificate revocation status before trusting a connection
- User asks about certificate revocation reason

## When NOT to Use

- User wants OCSP Must-Staple check (use ocsp-must-staple-checker instead)
- User wants full cert security scan (use cert-security-scanner instead)
- User wants certificate info (use certificate-info instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_revocation(target="DOMAIN")`
2. Check OCSP status first (real-time, more reliable):
   - Good → certificate is not revoked
   - Revoked → certificate has been revoked (show reason)
   - Unknown → OCSP responder couldn't determine status
3. If OCSP returns Unknown, check CRL status
4. If revoked, report: revocation reason, OCSP responder URL, CRL distribution points
5. Present the overall revocation verdict

**CLI equivalent:**
`cert-skills check-revocation DOMAIN -o json`

**OCSP vs CRL:** OCSP provides real-time status; CRL is a downloaded list. OCSP is preferred but may be unavailable.

## Anti-Patterns

- Don't assume OCSP Unknown means the cert is valid — it means the status couldn't be determined
- Don't skip CRL check when OCSP is unavailable — it's the fallback
- Don't confuse revocation check with OCSP Must-Staple — they're related but different
