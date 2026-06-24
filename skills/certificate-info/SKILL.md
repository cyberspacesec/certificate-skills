---
name: certificate-info
description: Use when retrieving SSL/TLS certificate and connection information from a domain, checking certificate chain details, TLS version, cipher suite, or handshake timing. Triggers on mentions of cert info, SSL certificate details, TLS connection info, or certificate chain inspection.
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

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills info example.com                    # Text output
cert-skills info example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.GetCertFromDomain("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

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
