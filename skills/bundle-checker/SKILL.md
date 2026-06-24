---
name: bundle-checker
description: Use when checking certificate bundle completeness and diagnosing missing intermediate certificates via AIA (Authority Information Access). Triggers on mentions of cert bundle, missing intermediate, chain incomplete, AIA fetch, or certificate chain bundle.
tools:
  - cert_check_bundle
---

# Bundle Checker

> **TL;DR:** Check certificate bundle completeness and diagnose missing intermediates via AIA

## Capabilities

- Certificate chain completeness verification
- Missing intermediate diagnosis
- AIA CA Issuers URL fetching
- Chain re-verification after AIA fetch

## Usage

```
cert_check_bundle target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Chain complete status
- Missing intermediates
- AIA fill capability
- AIA resolution status

## Workflow

1. Run `cert_check_bundle` on target
2. If incomplete, review missing intermediates
3. Check AIA URL availability
4. If AIA resolves, server needs to serve the intermediate

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills check-bundle example.com                    # Text output
cert-skills check-bundle example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckBundleCompleteness("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Identify servers with broken certificate chains
- Diagnose TLS connectivity issues
- Track AIA support across CA infrastructure

## Limitations

- AIA fetch depends on URL availability
- Some CAs do not provide AIA URLs
- Fetched intermediates should be verified

## Related Skills

- [[cert_verify_chain]] cert_verify_chain
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
