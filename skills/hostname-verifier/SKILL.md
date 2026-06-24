---
name: hostname-verifier
description: Use when verifying certificate hostname matching and RFC 6125 compliance. Triggers on mentions of hostname mismatch, cert hostname check, SSL name verification, CN SAN match, or hostname validation.
tools:
  - cert_verify_hostname
---

# Hostname Verifier

> **TL;DR:** Verify certificate hostname matching and RFC 6125 compliance

## Capabilities

- SAN/CN hostname matching
- Wildcard match detection (RFC 6125)
- Mismatch details with suggestions
- CN vs SAN issue identification

## Usage

```
cert_verify_hostname target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Whether hostname matches
- Match type (exact/wildcard)
- Mismatch details
- Closest match suggestion

## Workflow

1. Run `cert_verify_hostname` on target
2. If mismatch, review details
3. Check closest match suggestion
4. Verify with `cert_scan_cert_security`

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills verify-hostname example.com                    # Text output
cert-skills verify-hostname example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.VerifyHostname("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Identify misconfigured certificates with hostname mismatches
- Detect potentially malicious certificates
- Validate certificate deployment across infrastructure

## Limitations

- Wildcard matching follows RFC 6125 (one label only)
- Does not check all SANs, only the requested hostname

## Related Skills

- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_wildcard]] cert_check_wildcard
- [[cert_get_trusted_domains]] cert_get_trusted_domains
