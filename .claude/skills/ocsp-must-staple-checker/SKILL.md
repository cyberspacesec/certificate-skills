---
name: ocsp-must-staple-checker
description: Use when checking OCSP Must-Staple (RFC 7633) compliance. A certificate with Must-Staple that fails to provide an OCSP staple causes hard-failures in compliant clients. Triggers on mentions of OCSP Must-Staple, RFC 7633, OCSP stapling, or must-staple violation.
allowed-tools: ["mcp__certificate-hacker__cert_check_ocsp_must_staple"]
---

# ocsp-must-staple-checker

## When to Use

- User wants to check OCSP Must-Staple compliance
- User asks about RFC 7633 compliance
- User sees OCSP stapling errors
- User needs to verify that Must-Staple certificates actually provide staples
- User is troubleshooting TLS connection failures that may be related to OCSP

## When NOT to Use

- User wants to check OCSP revocation status (use certificate-revocation instead)
- User wants full cert security scan (use cert-security-scanner instead — includes CERT-015)
- User wants certificate info (use certificate-info instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_ocsp_must_staple(target="DOMAIN")`
2. Report: does the certificate have the Must-Staple extension?
3. If Must-Staple is present, check: is an OCSP staple actually provided?
4. If Must-Staple but no staple → **non-compliant** — this causes hard-failures in browsers
5. If Must-Staple and staple present → compliant
6. If no Must-Staple extension → not applicable, no requirement to staple

**CLI equivalent:**
`cert-skills check-ocsp-must-staple DOMAIN -o json`

**Critical finding:** Must-Staple without a staple causes browsers that support RFC 7633 to hard-fail the connection. This is worse than no Must-Staple at all.

## Anti-Patterns

- Don't confuse OCSP Must-Staple with OCSP stapling — Must-Staple is a certificate extension requiring stapling
- Don't treat Must-Staple without staple as a minor issue — it causes hard connection failures
- Don't recommend adding Must-Staple without ensuring the server supports OCSP stapling
