---
name: hsts-checker
description: Use when checking HSTS (HTTP Strict Transport Security) status and policy compliance for a domain. Triggers on mentions of HSTS, HTTP Strict Transport Security, HSTS check, HSTS preload, SSL stripping, or HSTS policy.
allowed-tools: ["mcp__certificate-hacker__cert_check_hsts"]
---

# hsts-checker

## When to Use

- User wants to check if HSTS is enabled on a domain
- User asks about HSTS policy compliance (max-age, includeSubDomains, preload)
- User is assessing SSL stripping vulnerability
- User needs to verify HSTS preload status
- User asks about HTTP to HTTPS redirect enforcement

## When NOT to Use

- User wants general security analysis (use certificate-analysis instead)
- User wants certificate info (use certificate-info instead)
- User wants vulnerability scanning (use tls-vulnerability-scanner instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_check_hsts(target="DOMAIN")`
2. Report: HSTS enabled status
3. If enabled, check policy details:
   - max-age: should be ≥ 1 year (31536000 seconds) for compliance
   - includeSubDomains: protects all subdomains
   - preload: eligible for browser HSTS preload lists
4. If disabled, warn about SSL stripping vulnerability
5. Provide recommendations for HSTS policy configuration

**CLI equivalent:**
`cert-skills check-hsts DOMAIN -o json`

**HSTS best practices:** max-age ≥ 31536000, includeSubDomains enabled, submit to preload list for maximum protection.

## Anti-Patterns

- Don't assume no HSTS header means no HTTPS — HTTPS may work without HSTS
- Don't recommend enabling HSTS without warning about the commitment — it's hard to reverse
- Don't ignore includeSubDomains — without it, subdomains are vulnerable to SSL stripping
