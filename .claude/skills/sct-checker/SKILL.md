---
name: sct-checker
description: Use when verifying Signed Certificate Timestamps (SCTs) for Certificate Transparency compliance per CA/Browser Forum requirements. Triggers on mentions of SCT, Signed Certificate Timestamp, CT compliance, SCT count, or certificate transparency proof.
allowed-tools: ["mcp__certificate-hacker__cert_check_sct"]
---

# sct-checker

## When to Use

- User wants to verify SCT compliance on a certificate
- User asks about Certificate Transparency proof (SCTs)
- User needs to check if a certificate meets CA/B Forum CT requirements
- User is auditing certificate issuance compliance
- User asks about embedded SCTs in certificates

## When NOT to Use

- User wants to search CT logs (use certificate-transparency instead)
- User wants full cert security scan (use cert-security-scanner instead)
- User wants certificate info (use certificate-info instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_sct(target="DOMAIN")`
2. Report: are SCTs present?
3. Check SCT count against CA/B Forum requirements:
   - Certificates valid ≤15 months: at least 2 SCTs
   - Certificates valid 15-27 months: at least 3 SCTs
   - Certificates valid 27-39 months: at least 4 SCTs
4. If compliant, confirm CT requirements are met
5. If non-compliant, explain the risk: browsers may reject the certificate
6. Review SCT details: log operator diversity, timestamps

**CLI equivalent:**
`cert-skills check-sct DOMAIN -o json`

**SCT importance:** Missing SCTs indicate the certificate may not have been properly logged in CT logs, which is a CA/B Forum requirement.

## Anti-Patterns

- Don't assume 2 SCTs is always sufficient — the required count depends on certificate validity
- Don't confuse SCT compliance with CT log search — SCTs are embedded in the certificate
- Don't ignore log operator diversity — all SCTs from the same operator reduces trust
