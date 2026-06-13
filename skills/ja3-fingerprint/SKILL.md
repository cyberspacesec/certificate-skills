---
name: ja3-fingerprint
description: Generate JA3/JA3S TLS fingerprints for client and server identification
tools:
  - cert_ja3
---

# Ja3 Fingerprint

> **TL;DR:** Generate JA3/JA3S TLS fingerprints for client and server identification

## Capabilities

- JA3 client fingerprint generation
- JA3S server fingerprint generation
- TLS client hello analysis
- C2 infrastructure detection

## Usage

```
cert_ja3 target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- JA3 hash (client fingerprint)
- JA3S hash (server fingerprint)
- JA3/JA3S raw strings

## Workflow

1. Run `cert_ja3` on target domain
2. Record JA3/JA3S hashes
3. Compare against known JA3 databases
4. Use for C2 detection or service identification

## Cyberspace Mapping Applications

- Identify C2 infrastructure through JA3 fingerprinting
- Detect malware communication patterns
- Map server software diversity across organizations

## Limitations

- TLS 1.3 uses encrypted server hello (limited JA3S)
- Some TLS implementations randomize extensions

## Related Skills

- [[cert_jarm]] cert_jarm
- [[cert_scan_protocols]] cert_scan_protocols
- [[cert_scan_ciphers]] cert_scan_ciphers
