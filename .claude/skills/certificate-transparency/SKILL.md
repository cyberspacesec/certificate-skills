---
name: certificate-transparency
description: Use when searching Certificate Transparency (CT) logs for certificates associated with a domain. Triggers on mentions of CT log search, certificate transparency, find certificates for domain, or CT lookup.
allowed-tools: ["mcp__certificate-skills__cert_search_ct"]
---

# certificate-transparency

## When to Use

- User wants to find all certificates issued for a domain
- User asks about certificate transparency logs
- User needs to check for unauthorized certificate issuance
- User wants to discover subdomains via certificate SANs
- User asks about certificate issuance history

## When NOT to Use

- User wants focused subdomain enumeration (use ct-subdomain-enumerator instead — better for recon)
- User wants to search by fingerprint (use ct-fingerprint-search instead)
- User wants to verify a specific certificate (use certificate-info instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_search_ct(domain="DOMAIN")`
2. Report the total number of certificates found
3. Highlight: unexpected issuers, expired vs active counts, unusual SANs
4. Present key findings: subdomains discovered via SANs, issuer distribution
5. If subdomain enumeration is the primary goal, suggest ct-subdomain-enumerator for focused results
6. If the user found a suspicious certificate, suggest certificate-compare or chain-verifier

**CLI equivalent:**
`cert-skills search-ct DOMAIN -o json`

**For cyberspace mapping:** CT logs reveal all publicly-trusted certificates ever issued for a domain, including wildcards and subdomains.

## Anti-Patterns

- Don't confuse CT search with subdomain enumeration — CT search returns certificates, enumerate extracts subdomains
- Don't assume all certificates in CT logs are currently active — check validity dates
- Don't ignore expired certificates — they may indicate past compromise or misconfiguration
