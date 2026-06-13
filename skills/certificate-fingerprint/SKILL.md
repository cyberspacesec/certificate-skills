---
name: certificate-fingerprint
description: Generate certificate fingerprints (SHA-256, SHA-1, MD5, SPKI) for pinning and verification
tools:
  - cert_fingerprint_domain
  - cert_fingerprint_file
---

# Certificate Fingerprint

> **TL;DR:** Generate certificate fingerprints (SHA-256, SHA-1, MD5, SPKI) for pinning and verification

## Capabilities

- SHA-256, SHA-1, MD5 certificate fingerprints
- Public key SHA-256 for SSL pinning
- Domain-based or file-based input

## Usage

```
cert_fingerprint_domain target="example.com"
cert_fingerprint_file target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target (domain)` | string (required) | Domain name or IP with optional port |
| `file_path (file)` | string (required) | Path to certificate file (PEM or DER) |

## Output

- SHA-256 fingerprint
- SHA-1 fingerprint
- MD5 fingerprint
- Public key SHA-256 (for SSL pinning)

## Workflow

1. Run `cert_fingerprint_domain` or `cert_fingerprint_file`
2. Record fingerprints for comparison
3. Use `cert_validate_fingerprint` to verify format
4. Use `cert_compare` to compare across domains

## Cyberspace Mapping Applications

- Build fingerprint databases for certificate tracking
- Detect unauthorized certificate changes via fingerprint monitoring
- Correlate certificates across domains via SPKI hash

## Limitations

- Fingerprints change on certificate renewal
- SPKI hash remains stable across renewals for same key

## Related Skills

- [[cert_validate_fingerprint]] cert_validate_fingerprint
- [[cert_compare]] cert_compare
- [[cert_info]] cert_info
