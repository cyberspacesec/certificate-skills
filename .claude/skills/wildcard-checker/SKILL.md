---
name: wildcard-checker
description: Use when analyzing wildcard certificate patterns and assessing security risk. Triggers on mentions of wildcard certificate, wildcard cert, wildcard SSL, *.domain, or wildcard risk.
allowed-tools: ["mcp__certificate-skills__cert_check_wildcard", "mcp__certificate-skills__cert_get_trusted_domains"]
---

# wildcard-checker

## When to Use

- User wants to check if a certificate is a wildcard
- User asks about wildcard certificate security risks
- User needs to understand wildcard level and coverage
- User is evaluating whether to use wildcard or individual certificates
- User asks about *.domain.com certificates

## When NOT to Use

- User wants to extract all domains (use trusted-domains-extractor instead — broader)
- User wants certificate info (use certificate-info instead)
- User wants subdomain enumeration (use ct-subdomain-enumerator instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_wildcard(target="DOMAIN")`
2. Report: is the certificate a wildcard?
3. If wildcard, classify the level (1-level, 2-level)
4. Report the risk assessment: High/Medium/Low
5. Show wildcard domains and their covered base domains
6. For full domain extraction, also run:
   `cert_get_trusted_domains(target="DOMAIN")`
7. Advise: wildcard certs are convenient but have broader attack surface — a single key compromise affects all subdomains

**CLI equivalent:**
`cert-skills check-wildcard DOMAIN -o json`

**Wildcard risk:** High = *.com (covers everything), Medium = *.example.com (covers one level), Low = not wildcard.

## Anti-Patterns

- Don't assume all wildcard certs are bad — they're useful for internal services with many subdomains
- Don't confuse wildcard level with risk level — they're related but not identical
- Don't recommend removing wildcard certs without considering operational impact
