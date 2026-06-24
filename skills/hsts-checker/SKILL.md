---
name: hsts-checker
description: Use when checking HSTS (HTTP Strict Transport Security) status and policy compliance for a domain. Triggers on mentions of HSTS, HTTP Strict Transport Security, HSTS check, HSTS preload, SSL stripping, or HSTS policy.
tools:
  - cert_check_hsts
---

# Hsts Checker

> **TL;DR:** Check HSTS (HTTP Strict Transport Security) status and policy compliance

## Capabilities

- HSTS header detection and parsing
- max-age value verification
- includeSubDomains and preload check
- SSL stripping vulnerability assessment

## Usage

```
cert_check_hsts target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name to check HSTS status |

## Output

- HSTS enabled status
- max-age (seconds and days)
- includeSubDomains status
- preload status
- Raw header value

## Workflow

1. Run `cert_check_hsts` on target
2. If enabled, verify max-age >= 1 year
3. Check includeSubDomains for broad protection
4. If disabled, assess SSL stripping risk

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills check-hsts example.com                    # Text output
cert-skills check-hsts example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckHSTS("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Assess HSTS coverage across infrastructure
- Identify domains vulnerable to SSL stripping
- Track HSTS adoption and policy quality

## Limitations

- Requires HTTPS connection
- Does not check HSTS preload list submission status

## Related Skills

- [[cert_analyze_security]] cert_analyze_security
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_pfs]] cert_check_pfs
