---
name: jarm-fingerprint
description: Use when generating JARM TLS server fingerprints for server identification, C2 infrastructure detection, and cyberspace mapping. Triggers on mentions of JARM, JARM fingerprint, JARM hash, C2 detection, or server fingerprinting.
allowed-tools: ["mcp__certificate-hacker__cert_jarm"]
---

# jarm-fingerprint

## When to Use

- User wants to identify a server by its TLS fingerprint
- User asks about JARM fingerprinting or JARM hash
- User needs to detect C2 infrastructure (Cobalt Strike, Metasploit)
- User wants to compare server fingerprints for infrastructure correlation

## When NOT to Use

- User wants client fingerprinting (use ja3-fingerprint instead)
- User wants certificate details (use certificate-info instead)
- User wants vulnerability scanning (use tls-vulnerability-scanner instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_jarm(target="DOMAIN")`
2. Report the JARM hash fingerprint
3. If the user is doing C2 detection, compare against known JARM hashes:
   - Cobalt Strike: specific JARM patterns
   - Metasploit: specific JARM patterns
   - Other C2 frameworks have known signatures
4. Combine with ja3-fingerprint for comprehensive TLS fingerprinting
5. For cyberspace mapping, JARM can identify same-backend servers across different domains

**CLI equivalent:**
`cert-skills jarm DOMAIN -o json`

**For C2 detection:** JARM is effective at identifying malicious infrastructure even behind CDN proxies.

## Anti-Patterns

- Don't use JARM alone for attribution — same JARM may indicate same software, not same operator
- Don't assume a JARM match with known C2 means confirmed malicious — verify with other evidence
- Don't confuse JARM (server fingerprint) with JA3 (client fingerprint)
