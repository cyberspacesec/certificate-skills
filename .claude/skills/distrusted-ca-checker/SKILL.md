---
name: distrusted-ca-checker
description: Use when detecting certificates issued by known distrusted or compromised Certificate Authorities (DigiNotar, WoSign, StartCom, Symantec legacy, CNNIC, TrustCor, DarkMatter). Triggers on mentions of distrusted CA, compromised CA, untrusted certificate authority, or CA distrust check.
allowed-tools: ["mcp__certificate-skills__cert_check_distrusted_ca"]
---

# distrusted-ca-checker

## When to Use

- User wants to check if a certificate chain includes a distrusted CA
- User asks about compromised or distrusted certificate authorities
- User needs to verify no DigiNotar, WoSign, or Symantec legacy CA in the chain
- User is doing a security audit and CA trust verification

## When NOT to Use

- User wants a full cert security scan (use cert-security-scanner instead — it includes CERT-014)
- User wants chain verification (use chain-verifier instead)
- User wants policy analysis (use policy-analyzer instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_distrusted_ca(target="DOMAIN")`
2. If a distrusted CA is found, this is a **Critical** finding:
   - Report the CA name, reason for distrust, and distrust date
   - Explain the security implications
   - Recommend immediate certificate replacement
3. If no distrusted CA found, confirm the chain is clean
4. Suggest cert-security-scanner for comprehensive checks

**CLI equivalent:**
`cert-skills check-distrusted-ca DOMAIN -o json`

**Known distrusted CAs in database:** DigiNotar, WoSign, StartCom, Symantec legacy, CNNIC, TrustCor, DarkMatter, and others (13 total)

## Anti-Patterns

- Don't treat a distrusted CA finding as low severity — it's always Critical
- Don't ignore the reason for distrust — some are due to compromise (DigiNotar), others due to audit failures (Symantec)
- Don't assume a clean result means the CA is trustworthy — only known distrusted CAs are checked
