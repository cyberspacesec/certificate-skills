---
name: serial-entropy-checker
description: Use when analyzing certificate serial number entropy for CA/B Browser Forum Baseline Requirements compliance (≥64 bits required). Triggers on mentions of serial entropy, serial number, cert serial, predictable serial, or BR serial compliance.
allowed-tools: ["mcp__certificate-hacker__cert_check_serial_entropy"]
---

# serial-entropy-checker

## When to Use

- User wants to check certificate serial number entropy
- User asks if a serial number is predictable or sequential
- User is auditing CA compliance with BR requirements
- User suspects weak serial number generation

## When NOT to Use

- User wants full cert security scan (use cert-security-scanner instead — includes CERT-017)
- User wants certificate info (use certificate-info instead)
- User wants key usage compliance (use key-usage-checker instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_serial_entropy(target="DOMAIN")`
2. Report: bit length, compliance status
3. Check: bit length ≥ 64 bits (BR requirement)
4. Check: Shannon entropy > 3.0 bits/byte (healthy randomness)
5. Check: Hamming weight and ratio (bias detection)
6. Check: sequential pattern flag
7. If non-compliant, explain the risk: predictable serials enable collision attacks

**CLI equivalent:**
`cert-skills check-serial-entropy DOMAIN -o json`

**Why serial entropy matters:** Predictable serial numbers can enable certificate forgery attacks (see CVE-2008-5077).

## Anti-Patterns

- Don't assume a short serial is always non-compliant — check the bit length, not the hex length
- Don't confuse Shannon entropy with bit length — both must be checked
- Don't treat this as a Critical finding for leaf certificates — it's primarily a CA concern
