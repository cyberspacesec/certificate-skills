---
name: name-constraints-checker
description: Use when checking CA certificate Name Constraints and verifying leaf certificate names comply with parent CA constraints. Triggers on mentions of name constraints, trust boundary, CA namespace restriction, or name constraint violation.
allowed-tools: ["mcp__certificate-skills__cert_check_name_constraints"]
---

# name-constraints-checker

## When to Use

- User wants to check CA name constraints
- User asks about trust boundary violations
- User needs to verify that certificates are issued within their CA's permitted namespace
- User is auditing a PKI hierarchy for compliance
- User asks about permitted/excluded subtrees in certificates

## When NOT to Use

- User wants full cert security scan (use cert-security-scanner instead — includes CERT-018)
- User wants key usage compliance (use key-usage-checker instead)
- User wants chain verification (use chain-verifier instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_name_constraints(target="DOMAIN")`
2. Report: whether constraints exist on any CA in the chain
3. If constraints exist, show the constrained CAs and their permitted/excluded subtrees
4. Check for violations: leaf certificate names outside the CA's permitted namespace
5. Violations indicate trust boundary breaches — this is a **High severity** finding
6. Explain the security implication: the CA has issued certificates outside its authorized scope

**CLI equivalent:**
`cert-skills check-name-constraints DOMAIN -o json`

**Name constraints:** Restrict which domains/IPs/emails a CA is allowed to issue certificates for.

## Anti-Patterns

- Don't assume no constraints is a problem — many CAs don't have name constraints
- Don't confuse name constraints with hostname verification — they're different checks
- Don't treat violations as informational — they indicate potential misissuance
