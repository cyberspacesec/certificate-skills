---
name: policy-analyzer
description: Use when analyzing certificate policy OIDs for DV/OV/EV classification and compliance checking. Triggers on mentions of certificate policy, DV OV EV, validation type, policy OID, or certificate classification.
allowed-tools: ["mcp__certificate-skills__cert_check_policy", "mcp__certificate-skills__cert_detect_ev"]
---

# policy-analyzer

## When to Use

- User wants to know if a certificate is DV, OV, or EV
- User asks about certificate policy OIDs
- User needs to classify certificate validation type
- User detects unknown policy OIDs that may indicate a private CA
- User wants to verify Certificate Policies extension on public CA certs

## When NOT to Use

- User only needs EV detection (use ev-detector instead — simpler)
- User wants full cert security scan (use cert-security-scanner instead)
- User wants key usage compliance (use key-usage-checker instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_policy(target="DOMAIN")`
2. Report the validation type: DV, OV, EV, or Unknown
3. Show the policy OID list with descriptions
4. Flag unknown OIDs — these may indicate a private CA or non-standard issuer
5. Check compliance: public CA certificates without Certificate Policies extension violate BR
6. If the user specifically needs EV detection, also run cert_detect_ev

**CLI equivalent:**
`cert-skills check-policy DOMAIN -o json`

**DV vs OV vs EV:** DV = Domain Validated (automated), OV = Organization Validated (manual org check), EV = Extended Validation (strictest identity verification).

## Anti-Patterns

- Don't assume Unknown validation type means insecure — it may be a private CA
- Don't confuse policy analysis with EV detection — policy covers all types
- Don't ignore missing Certificate Policies on public CA certs — it's a BR violation
