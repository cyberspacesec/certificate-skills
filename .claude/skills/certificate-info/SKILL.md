---
name: certificate-info
description: Use when retrieving SSL/TLS certificate and connection information from a domain, checking certificate chain details, TLS version, cipher suite, or handshake timing. Triggers on mentions of cert info, SSL certificate details, TLS connection info, or certificate chain inspection.
allowed-tools: ["mcp__certificate-hacker__cert_info"]
---

# certificate-info

## When to Use

- User asks for certificate details of a domain
- User wants to check TLS version and cipher suite
- User needs to inspect the full certificate chain
- User asks about OCSP stapling or HTTP/2 support
- User wants handshake timing information

## When NOT to Use

- User wants a security assessment (use certificate-analysis instead)
- User wants vulnerability scanning (use tls-vulnerability-scanner instead)
- User has a local certificate file (use certificate-parse instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_info(target="DOMAIN")`
2. Present the TLS connection details (version, cipher suite, HTTP/2, OCSP stapling)
3. Show the certificate chain from leaf to root
4. Highlight any certificate that is expired, self-signed, or has mismatched hostname
5. Include fingerprints for each certificate in the chain
6. If the user wants deeper analysis, suggest certificate-analysis or cert-security-scanner

**CLI equivalent:**
`cert-skills info DOMAIN -o json`

**Supports multiple targets:**
`cert_info(target="domain1.com")` — single domain

## Anti-Patterns

- Don't confuse info with analysis — info shows raw data, analysis provides scoring
- Don't skip the chain inspection — incomplete chains are a common issue
- Don't ignore handshake timing — slow handshakes may indicate configuration problems
