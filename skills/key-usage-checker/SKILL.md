---
name: key-usage-checker
description: Use when validating certificate key usage compliance with RFC 5280 and CA/Browser Forum Baseline Requirements. Triggers on mentions of key usage, EKU, key usage compliance, RFC 5280, or CA/B BR key usage.
tools:
  - cert_check_key_usage
---

# Key Usage Checker

> **TL;DR:** Validate certificate key usage compliance with RFC 5280 and CA/B BR requirements

## Capabilities

- CA certificate keyCertSign requirement
- Non-CA keyCertSign prohibition
- TLS leaf digitalSignature/keyEncipherment
- ServerAuth EKU check
- Key algorithm consistency

## Usage

```
cert_check_key_usage target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Compliance status
- Key usage and EKU lists
- Is CA flag
- Issues with severity

## Workflow

1. Run `cert_check_key_usage` on target
2. Review key usage lists
3. Check compliance issues
4. Focus on High severity issues

## AI Integration

### CLI (For AI Agents)

```bash
cert-skills check-key-usage example.com                    # Text output
cert-skills check-key-usage example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckKeyUsageCompliance("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Detect mis-issued certificates with incorrect key usage
- Identify non-CA certs that can sign other certificates
- Track key usage patterns across CA issuers

## Limitations

- Checks leaf certificate only
- Some legacy certificates may have non-standard key usage

## Related Skills

- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_name_constraints]] cert_check_name_constraints
- [[cert_check_policy]] cert_check_policy
