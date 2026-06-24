---
name: certificate-compare
description: Use when comparing two SSL/TLS certificates to determine if they are identical or different. Triggers on mentions of compare certificates, cert diff, certificate match, or check if two certs are the same.
allowed-tools: ["mcp__certificate-hacker__cert_compare"]
---

# certificate-compare

## When to Use

- User wants to compare two certificates (domains, files, or mixed)
- User asks if two domains use the same certificate
- User needs to check if a certificate has been renewed or changed
- User wants to diff certificate details (subject, issuer, validity, key)

## When NOT to Use

- User wants certificate info for a single domain (use certificate-info instead)
- User wants security analysis (use certificate-analysis instead)
- User has only one certificate target (comparison requires two)

## Instructions

1. Get both certificate targets from the user (can be domains or file paths)
2. Run the MCP tool:
   `cert_compare(target1="domain1.com", target2="domain2.com")`
   Or mix types: `cert_compare(target1="domain.com", target2="/path/to/cert.pem")`
3. Report whether certificates are identical or different
4. If different, present the specific differences (fingerprints, subject, issuer, validity, key)
5. If identical, confirm with matching fingerprints

**CLI equivalent:**
`cert-skills compare -1 domain1.com -2 domain2.com -o json`

**Supported combinations:** domain vs domain, file vs file, domain vs file

## Anti-Patterns

- Don't assume 'different' means one is wrong — certificate renewal is normal
- Don't skip fingerprint comparison — it's the most reliable identity check
- Don't compare certificates from unrelated domains without context
