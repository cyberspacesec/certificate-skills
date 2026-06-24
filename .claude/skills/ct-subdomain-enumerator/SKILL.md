---
name: ct-subdomain-enumerator
description: Use when enumerating subdomains through Certificate Transparency logs for reconnaissance and cyberspace mapping. Triggers on mentions of subdomain enum, CT subdomain discovery, find subdomains, domain recon, or subdomain search.
allowed-tools: ["mcp__certificate-hacker__cert_ct_enumerate"]
---

# ct-subdomain-enumerator

## When to Use

- User wants to discover subdomains of a domain
- User asks for subdomain enumeration or reconnaissance
- User needs to map the domain infrastructure via certificates
- User wants to find wildcard certificates and their scope

## When NOT to Use

- User wants general CT log search (use certificate-transparency instead)
- User wants to search by fingerprint (use ct-fingerprint-search instead)
- User needs DNS-based enumeration (this is certificate-based only)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_ct_enumerate(domain="DOMAIN")`
2. Report the unique subdomain list
3. Highlight wildcard domains and their base domains
4. Show issuer grouping — reveals CA relationships and potential org attribution
5. Note active vs expired certificate counts
6. For cyberspace mapping, suggest combining with jarm-fingerprint or ja3-fingerprint for service identification

**CLI equivalent:**
`cert-skills ct-enumerate DOMAIN -o json`

**For reconnaissance:** CT enumeration is passive — no direct connection to targets. Combine with active scanning for full coverage.

## Anti-Patterns

- Don't assume all discovered subdomains are currently active — check certificate validity
- Don't ignore wildcard certificates — they indicate broad subdomain coverage
- Don't rely solely on CT for subdomain discovery — combine with DNS enumeration for completeness
