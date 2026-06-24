---
name: bundle-checker
description: Use when checking certificate bundle completeness and diagnosing missing intermediate certificates via AIA (Authority Information Access). Triggers on mentions of cert bundle, missing intermediate, chain incomplete, AIA fetch, or certificate chain bundle.
allowed-tools: ["mcp__certificate-skills__cert_check_bundle"]
---

# bundle-checker

## When to Use

- User sees 'certificate chain incomplete' errors
- User wants to verify certificate bundle completeness
- User asks about missing intermediate certificates
- User needs to check AIA CA Issuers URL availability
- User is troubleshooting TLS handshake failures due to chain issues

## When NOT to Use

- User wants chain verification (use chain-verifier instead)
- User wants full cert security scan (use cert-security-scanner instead)
- User wants certificate info (use certificate-info instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_bundle(target="DOMAIN")`
2. Report: is the chain complete?
3. If incomplete, identify which intermediates are missing
4. Check if AIA CA Issuers URLs are available to fetch the missing certificates
5. If AIA resolves, explain that the server needs to be configured to serve the intermediate
6. Provide remediation guidance: configure the server to include all intermediates in the chain

**CLI equivalent:**
`cert-skills check-bundle DOMAIN -o json`

**Common issue:** Servers often forget to include intermediate certificates, causing 'untrusted chain' errors in browsers that don't have the intermediate cached.

## Anti-Patterns

- Don't assume AIA fetching solves the problem — the server should serve the intermediate directly
- Don't confuse bundle completeness with chain trust — a complete bundle can still be untrusted
- Don't skip this check when troubleshooting TLS errors — missing intermediates are very common
