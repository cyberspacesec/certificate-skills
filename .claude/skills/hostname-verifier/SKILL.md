---
name: hostname-verifier
description: Use when verifying certificate hostname matching and RFC 6125 compliance. Triggers on mentions of hostname mismatch, cert hostname check, SSL name verification, CN SAN match, or hostname validation.
allowed-tools: ["mcp__certificate-skills__cert_verify_hostname"]
---

# hostname-verifier

## When to Use

- User sees a hostname mismatch error
- User wants to verify that a certificate matches the requested hostname
- User asks about CN vs SAN matching
- User needs to check wildcard certificate hostname matching
- User is debugging SSL/TLS connection errors

## When NOT to Use

- User wants full cert security scan (use cert-security-scanner instead)
- User wants certificate info (use certificate-info instead)
- User wants chain verification (use chain-verifier instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_verify_hostname(target="DOMAIN")`
2. Report: does the hostname match?
3. If match, report the match type (exact or wildcard)
4. If mismatch, provide details and the closest match suggestion
5. Explain the mismatch cause: missing SAN, CN-only, wrong domain in cert
6. Suggest cert-security-scanner for comprehensive checks (includes CERT-005 hostname mismatch)

**CLI equivalent:**
`cert-skills verify-hostname DOMAIN -o json`

**RFC 6125:** Modern clients check SANs first; CN is only checked if no SANs exist.

## Anti-Patterns

- Don't assume CN matching is sufficient — SANs are the modern standard
- Don't ignore wildcard matching rules — wildcards only match one level
- Don't confuse hostname verification with chain verification
