---
name: trusted-domains-extractor
description: Use when extracting all domain names trusted by a certificate for cyberspace mapping, including wildcard expansions and base domain identification. Triggers on mentions of trusted domains, cert domains, extract domains, domain extraction, or cert namespace.
allowed-tools: ["mcp__certificate-skills__cert_get_trusted_domains", "mcp__certificate-skills__cert_check_wildcard"]
---

# trusted-domains-extractor

## When to Use

- User wants to extract all domains from a certificate
- User is doing cyberspace mapping and needs to understand a certificate's namespace
- User wants to identify base domains from wildcard certificates
- User needs to find all domains an organization has certificates for
- User asks about wildcard coverage and scope

## When NOT to Use

- User wants subdomain enumeration (use ct-subdomain-enumerator instead — broader scope)
- User wants certificate info (use certificate-info instead)
- User wants security analysis (use certificate-analysis instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_get_trusted_domains(target="DOMAIN")`
2. Report: Common Name, all domains (exact and wildcard)
3. Identify unique base domains — useful for further reconnaissance
4. Extract IP addresses if present
5. Show organization attribution if available
6. For wildcard analysis, also run:
   `cert_check_wildcard(target="DOMAIN")`
7. Cross-reference with ct-subdomain-enumerator for comprehensive domain discovery

**CLI equivalent:**
`cert-skills get-trusted-domains DOMAIN -o json`

**For cyberspace mapping:** Certificate domain extraction reveals the namespace an organization controls, including hidden subdomains.

## Anti-Patterns

- Don't confuse trusted domains with active domains — certificates may cover domains not currently in use
- Don't assume wildcard domains mean all subdomains are active — they just mean the cert is valid for them
- Don't skip the organization attribution — it reveals who controls the certificate
