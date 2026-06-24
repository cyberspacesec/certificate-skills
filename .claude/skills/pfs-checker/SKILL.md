---
name: pfs-checker
description: Use when checking Perfect Forward Secrecy (PFS) support through ECDHE/DHE key exchange analysis. Triggers on mentions of PFS, Perfect Forward Secrecy, forward secrecy, ECDHE, DHE, or key exchange check.
allowed-tools: ["mcp__certificate-skills__cert_check_pfs"]
---

# pfs-checker

## When to Use

- User wants to verify PFS support on a server
- User asks about ECDHE or DHE key exchange
- User is assessing the impact of private key compromise on past sessions
- User needs to check if cipher suites support forward secrecy

## When NOT to Use

- User wants full TLS protocol scan (use tls-scanner instead)
- User wants cipher suite enumeration (use tls-scanner with cert_scan_ciphers)
- User wants vulnerability scanning (use tls-vulnerability-scanner instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_pfs(target="DOMAIN")`
2. Report: PFS support status
3. If PFS is supported, report the key exchange type (ECDHE or DHE)
4. If no PFS, warn that past sessions can be decrypted if the private key is compromised
5. If DHE-based, suggest upgrading to ECDHE for better performance
6. Cross-reference with tls-scanner for detailed cipher suite analysis

**CLI equivalent:**
`cert-skills check-pfs DOMAIN -o json`

**PFS importance:** Without PFS, compromise of the server's private key allows decryption of all past and future TLS sessions.

## Anti-Patterns

- Don't assume DHE is as good as ECDHE — ECDHE is faster and equally secure
- Don't confuse PFS support with cipher suite security — they're related but different
- Don't report no PFS as Critical — it's a best practice, not a vulnerability
