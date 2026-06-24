---
name: ja3-fingerprint
description: Use when generating JA3/JA3S TLS fingerprints for client and server identification, malware C2 detection, and cyberspace mapping. Triggers on mentions of JA3, JA3S, JA3 fingerprint, client fingerprint, or TLS client hello analysis.
allowed-tools: ["mcp__certificate-skills__cert_ja3"]
---

# ja3-fingerprint

## When to Use

- User wants to fingerprint a TLS client or server
- User asks about JA3 or JA3S fingerprints
- User needs to identify malware C2 by TLS fingerprint
- User wants to classify TLS implementations
- User asks about client hello analysis

## When NOT to Use

- User wants server-only fingerprinting (JARM may be more appropriate — use jarm-fingerprint)
- User wants certificate details (use certificate-info instead)
- User wants vulnerability scanning (use tls-vulnerability-scanner instead)

## Instructions

1. Run the MCP tool on the target domain:
   `cert_ja3(target="DOMAIN")`
2. Report both JA3 (client) and JA3S (server) hashes
3. Present the raw fingerprint strings for database comparison
4. If the user is doing C2 detection, compare against known JA3/JA3S databases
5. For cyberspace mapping, JA3S can identify server software; JA3 identifies client software
6. Combine with jarm-fingerprint for comprehensive server fingerprinting

**CLI equivalent:**
`cert-skills ja3 DOMAIN -o json`

**JA3 vs JA3S:** JA3 fingerprints the Client Hello (identifies the client); JA3S fingerprints the Server Hello (identifies the server).

## Anti-Patterns

- Don't confuse JA3 (client) with JA3S (server) — they fingerprint different sides
- Don't use JA3 alone for definitive attribution — same JA3 may indicate same TLS library, not same actor
- Don't ignore the raw fingerprint strings — they contain more detail than just the hash
