---
name: jarm-fingerprint
description: Generate JARM TLS fingerprint for server identification and C2 detection
tools:
  - cert_jarm
---

# Jarm Fingerprint

> **TL;DR:** Generate JARM TLS fingerprint for server identification and C2 detection

## Capabilities

- JARM fingerprint via 10 TLS Client Hello probes
- Server software identification
- C2 infrastructure detection
- Works with TLS 1.3 servers

## Usage

```
cert_jarm target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- JARM hash fingerprint
- Target domain and port

## Workflow

1. Run `cert_jarm` on target domain
2. Record JARM hash
3. Compare against known JARM databases (Cobalt Strike, Metasploit)
4. Combine with `cert_ja3` for comprehensive fingerprinting

## Cyberspace Mapping Applications

- Identify malicious infrastructure through JARM
- Detect Cobalt Strike, Metasploit, and other C2 frameworks
- Cluster servers with identical JARM hashes

## Limitations

- JARM requires 10 separate TLS connections
- CDN-fronted servers show CDN JARM, not origin

## Related Skills

- [[cert_ja3]] cert_ja3
- [[cert_scan_protocols]] cert_scan_protocols
- [[cert_scan_ciphers]] cert_scan_ciphers
