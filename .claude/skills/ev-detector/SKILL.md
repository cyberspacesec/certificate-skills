---
name: ev-detector
description: Use when detecting Extended Validation (EV) certificates through policy OID analysis. Triggers on mentions of EV certificate, Extended Validation, EV detection, certificate validation level, or EV check.
allowed-tools: ["mcp__certificate-hacker__cert_detect_ev"]
---

# ev-detector

## When to Use

- User asks if a certificate is Extended Validation (EV)
- User wants to know the validation level of a certificate (DV/OV/EV)
- User needs to verify EV status for compliance or trust decisions
- User asks about certificate policy OIDs

## When NOT to Use

- User wants full policy analysis (use policy-analyzer instead — covers DV/OV/EV)
- User wants certificate security checks (use cert-security-scanner instead)
- User wants certificate info (use certificate-info instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_detect_ev(target="DOMAIN")`
2. Report whether the certificate is EV or not
3. If EV, show the matching policy OIDs and issuer organization
4. If not EV, suggest policy-analyzer for DV/OV classification
5. Explain what EV means: highest identity assurance, organization name in browser bar

**CLI equivalent:**
`cert-skills detect-ev DOMAIN -o json`

**EV vs OV vs DV:** EV provides highest assurance (organization verified), OV verifies organization, DV only verifies domain control.

## Anti-Patterns

- Don't assume non-EV means insecure — OV and DV are valid for most use cases
- Don't confuse EV detection with full policy analysis — use policy-analyzer for DV/OV classification
- Don't rely solely on EV status for trust decisions — check other security factors too
