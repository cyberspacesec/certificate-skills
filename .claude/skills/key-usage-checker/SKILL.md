---
name: key-usage-checker
description: Use when validating certificate key usage compliance with RFC 5280 and CA/Browser Forum Baseline Requirements. Triggers on mentions of key usage, EKU, key usage compliance, RFC 5280, or CA/B BR key usage.
allowed-tools: ["mcp__certificate-skills__cert_check_key_usage"]
---

# key-usage-checker

## When to Use

- User wants to verify certificate key usage compliance
- User asks about Key Usage or Extended Key Usage extensions
- User needs to check if a CA certificate has keyCertSign
- User is auditing PKI compliance per RFC 5280 or CA/B BR
- User sees key usage errors in TLS handshake

## When NOT to Use

- User wants full cert security scan (use cert-security-scanner instead — includes CERT-016)
- User wants certificate info (use certificate-info instead)
- User wants policy analysis (use policy-analyzer instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_key_usage(target="DOMAIN")`
2. Report: compliance status
3. Show the key usage and EKU lists
4. Report the isCA flag status
5. If non-compliant, explain which requirement is violated:
   - CA without keyCertSign → invalid CA
   - Non-CA with keyCertSign → invalid leaf
   - TLS leaf without digitalSignature/keyEncipherment → cannot be used for TLS
   - Missing serverAuth EKU → not valid for TLS server auth
6. Focus on High severity issues

**CLI equivalent:**
`cert-skills check-key-usage DOMAIN -o json`

**Key Usage vs EKU:** Key Usage (basic constraints on the key), Extended Key Usage (purpose-specific like serverAuth, codeSigning).

## Anti-Patterns

- Don't treat all key usage issues as equal — CA without keyCertSign is more severe than missing optional EKUs
- Don't confuse Key Usage with Extended Key Usage — they serve different purposes
- Don't assume compliance means the certificate is secure — it only means key usage is correct
