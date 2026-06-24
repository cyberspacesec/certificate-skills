---
name: tls-scanner
description: Use when scanning TLS protocol versions and cipher suites for security assessment. Triggers on mentions of TLS scan, protocol scan, cipher scan, TLS version check, or cipher suite analysis.
allowed-tools: ["mcp__certificate-skills__cert_scan_protocols", "mcp__certificate-skills__cert_scan_ciphers"]
---

# tls-scanner

## When to Use

- User wants to know which TLS versions a server supports
- User asks about cipher suite enumeration
- User needs to check for insecure TLS versions (1.0, 1.1)
- User wants to identify weak cipher suites
- User is hardening TLS configuration

## When NOT to Use

- User wants vulnerability scanning (use tls-vulnerability-scanner instead)
- User wants PFS check only (use pfs-checker instead — more focused)
- User wants security scoring (use certificate-analysis instead)

## Instructions

1. First, scan protocol versions:
   `cert_scan_protocols(target="DOMAIN")`
2. Report which TLS versions are supported (1.0, 1.1, 1.2, 1.3)
3. Flag: TLS 1.0 and 1.1 are insecure and should be disabled
4. Then, scan cipher suites for each version:
   `cert_scan_ciphers(target="DOMAIN", tls_version=0x0303)` (TLS 1.2)
   `cert_scan_ciphers(target="DOMAIN", tls_version=0x0304)` (TLS 1.3)
5. Report: secure vs weak cipher classification
6. Flag: export-grade ciphers, NULL ciphers, RC4, 3DES
7. Recommend: disable TLS 1.0/1.1, prefer AES-GCM or ChaCha20 cipher suites

**CLI equivalent:**
`cert-skills scan-protocols DOMAIN -o json`
`cert-skills scan-ciphers DOMAIN -o json`

**TLS version codes:** 1.0=0x0301, 1.1=0x0302, 1.2=0x0303, 1.3=0x0304

## Anti-Patterns

- Don't scan cipher suites without first checking protocol versions — start with protocols
- Don't treat TLS 1.2-only as insecure — TLS 1.3 is preferred but 1.2 with good ciphers is fine
- Don't recommend disabling TLS 1.2 — many clients still need it
