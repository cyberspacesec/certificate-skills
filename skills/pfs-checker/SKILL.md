---
name: pfs-checker
description: Use when checking Perfect Forward Secrecy (PFS) support through ECDHE/DHE key exchange analysis. Triggers on mentions of PFS, Perfect Forward Secrecy, forward secrecy, ECDHE, DHE, or key exchange check.
tools:
  - cert_check_pfs
---

# Pfs Checker

> **TL;DR:** Check Perfect Forward Secrecy (PFS) support through ECDHE/DHE key exchange

## Capabilities

- PFS support detection
- Key exchange type (ECDHE/DHE/None)
- Cipher suite reporting
- PFS strength assessment

## Usage

```
cert_check_pfs target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- PFS support status
- Key exchange type
- Negotiated cipher suite
- TLS version
- Security notes

## Workflow

1. Run `cert_check_pfs` on target
2. If no PFS, assess risk of key compromise
3. If DHE-based, consider upgrading to ECDHE
4. Cross-reference with `cert_scan_ciphers`

## AI Integration

### CLI (For AI Agents)

```bash
cert-skills check-pfs example.com                    # Text output
cert-skills check-pfs example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckPFS("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Assess forward secrecy coverage across infrastructure
- Identify servers vulnerable to private key compromise
- Track PFS adoption trends

## Limitations

- Only checks negotiated cipher suite
- PFS depends on both client and server support

## Related Skills

- [[cert_scan_ciphers]] cert_scan_ciphers
- [[cert_scan_protocols]] cert_scan_protocols
- [[cert_analyze_security]] cert_analyze_security
