---
name: tls-scanner
description: Use when scanning TLS protocol versions and cipher suites for security assessment. Triggers on mentions of TLS scan, protocol scan, cipher scan, TLS version check, or cipher suite analysis.
tools:
  - cert_scan_protocols
  - cert_scan_ciphers
---

# Tls Scanner

> **TL;DR:** Scan TLS protocol versions and cipher suites for security assessment

## Capabilities

- TLS protocol version scanning (1.0 through 1.3)
- Cipher suite enumeration per version
- Secure vs weak cipher classification
- Export-grade cipher detection

## Usage

```
cert_scan_protocols target="example.com"
cert_scan_ciphers target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |
| `tls_version` | number | TLS version for cipher scan (1.2=0x0303, 1.3=0x0304) |

## Output

- Supported TLS versions
- Cipher suites per version
- Secure vs weak classification
- Export-grade warnings

## Workflow

1. Run `cert_scan_protocols` to identify versions
2. Run `cert_scan_ciphers` for each version
3. Focus on weak and export-grade ciphers
4. Verify TLS 1.3 support

## References

- [Scan output](references/scan-output.md) - Read when interpreting protocol support, cipher findings, or JSON scan fields.

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills scan-protocols example.com                    # Text output
cert-skills scan-protocols example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.TLSProtocolScan("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Assess TLS configuration security across infrastructure
- Identify servers supporting deprecated protocols (TLS 1.0/1.1)
- Find weak cipher suites vulnerable to attack

## Limitations

- Scanning requires multiple TLS connections
- Server may behave differently under load

## Related Skills

- [[cert_scan_vulnerabilities]] cert_scan_vulnerabilities
- [[cert_check_pfs]] cert_check_pfs
- [[cert_analyze_security]] cert_analyze_security
