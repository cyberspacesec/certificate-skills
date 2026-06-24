---
name: caa-checker
description: Use when checking DNS CAA (Certification Authority Authorization) records to verify CA authorization for certificate issuance. Triggers on mentions of CAA records, CAA check, certificate authorization, CAA misconfiguration, or unauthorized certificate issuance.
allowed-tools: ["mcp__certificate-hacker__cert_check_caa"]
---

# caa-checker

## When to Use

- User wants to check CAA records for a domain
- User asks about certificate issuance authorization
- User needs to verify if the issuing CA is authorized by CAA policy
- User suspects unauthorized certificate issuance
- User is configuring CAA records and wants to verify them

## When NOT to Use

- User wants full cert security scan (use cert-security-scanner instead)
- User wants DNS record check (this only checks CAA, not other DNS records)
- User wants chain verification (use chain-verifier instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_caa(target="DOMAIN")`
2. Report: do CAA records exist?
3. If CAA exists, show record details (flag, tag, value)
4. Check if the issuing CA is authorized by the CAA policy
5. If no CAA records, warn that any CA can issue certificates for this domain
6. Recommend adding CAA records to restrict certificate issuance

**CLI equivalent:**
`cert-skills check-caa DOMAIN -o json`

**CAA tags:** issue (allow CA to issue), issuewild (allow CA to issue wildcard), iodef (report incident to URL)

## Anti-Patterns

- Don't assume no CAA means vulnerable — it means unrestricted, which is common
- Don't confuse CAA with CT — CAA prevents issuance, CT detects it after the fact
- Don't recommend CAA without explaining that it must be supported by the CA
