---
name: ct-fingerprint-search
description: Search Certificate Transparency logs by certificate fingerprint
tools:
  - cert_search_ct_fingerprint
---

# Ct Fingerprint Search

> **TL;DR:** Search Certificate Transparency logs by certificate fingerprint

## Capabilities

- SHA-256 fingerprint-based search
- CT log inclusion verification
- Certificate tracking across CT logs
- Duplicate certificate detection

## Usage

```
cert_search_ct_fingerprint target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `fingerprint` | string (required) | SHA-256 fingerprint (hex, with or without colons) |

## Output

- Total certificate count
- Certificate details (CN, issuer, validity)
- SHA-256 fingerprints

## Workflow

1. Obtain fingerprint from `cert_fingerprint_domain` or `cert_fingerprint_file`
2. Run `cert_search_ct_fingerprint` with the fingerprint
3. Verify CT log inclusion
4. Check for duplicate certificates across domains

## Cyberspace Mapping Applications

- Track a known certificate across CT logs
- Find identical certificates deployed on multiple domains
- Trace compromised certificates through CT infrastructure

## Limitations

- Requires exact fingerprint match
- CT log search may be rate-limited

## Related Skills

- [[cert_search_ct]] cert_search_ct
- [[cert_fingerprint_domain]] cert_fingerprint_domain
- [[cert_validate_fingerprint]] cert_validate_fingerprint
