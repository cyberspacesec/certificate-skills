---
name: certificate-info
description: Retrieve and display detailed SSL/TLS certificate and connection information
tools:
  - cert_info
---

# Certificate Info

> **TL;DR:** Retrieve and display detailed SSL/TLS certificate and connection information

## Capabilities

- Full certificate chain details
- TLS version and cipher suite
- HTTP/2 support detection
- OCSP stapling status
- Handshake timing
- Batch processing of multiple targets

## Usage

```
cert_info target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain, domain:port, or file path. Supports multiple targets. |

## Output

- TLS version and cipher suite
- HTTP/2 and OCSP stapling status
- Full certificate chain details
- Fingerprints for each certificate

## Workflow

1. Run `cert_info` on target domain or file
2. Review TLS connection details
3. Check certificate chain for completeness
4. Use `cert_analyze_security` for deeper analysis

## Cyberspace Mapping Applications

- Rapid certificate reconnaissance for target domains
- Map TLS configurations across infrastructure
- Identify certificate authorities used by target organizations

## Limitations

- Network required for domain targets
- File mode provides cert-only info (no TLS details)

## Related Skills

- [[cert_parse]] cert_parse
- [[cert_analyze_security]] cert_analyze_security
- [[cert_fingerprint_domain]] cert_fingerprint_domain
- [[cert_download]] cert_download
