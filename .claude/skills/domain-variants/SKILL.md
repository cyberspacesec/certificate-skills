---
name: domain-variants
description: Generate certificates for domain variants (homoglyphs, subdomains, TLD changes, etc.) for phishing detection research.
allowed-tools:
  - mcp__certificate-hacker__cert_generate_domain_variants
---

# Domain Variant Generator

## When to Use
- Detect potential phishing domains through visual similarity
- Research typosquatting and domain abuse patterns
- Test certificate validation against lookalike domains
- Cyberspace mapping and threat intelligence

## When NOT to Use
- Generating certificates for legitimate domains (use `certificate-generator`)
- Creating certificates for actual phishing or fraud
- Any unauthorized or malicious purpose

## Instructions
1. Call `cert_generate_domain_variants` with a base domain
2. Select variant types: homoglyph (visual character substitution), subdomain, tld, hyphenation, insertion
3. Optionally use CA signing for more realistic test certificates
4. Review generated variants to identify potential phishing risks

## Variant Types
- **homoglyph**: Visual character substitution (e.g., 'a' → 'à', 'o' → 'ο')
- **subdomain**: Common prefix additions (www, mail, admin, etc.)
- **tld**: Different top-level domains (.com → .net, .org, .io, etc.)
- **hyphenation**: Insert hyphens at various positions
- **insertion**: Single character insertions

## WARNING
This tool is for AUTHORIZED SECURITY RESEARCH ONLY. Maximum 50 variants per request.

## Anti-Patterns
- Do not use for creating actual phishing infrastructure
- Do not use variant domains to deceive users
- Always have proper authorization before testing
