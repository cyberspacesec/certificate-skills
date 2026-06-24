---
name: certificate-analysis
description: Use when performing SSL/TLS security analysis on a domain, checking certificate security scoring (0-100), auditing TLS configuration, or identifying certificate vulnerabilities. Triggers on mentions of SSL audit, TLS security score, certificate analysis, security assessment, or cert security review.
tools:
  - cert_analyze_security
---

# Certificate Analysis

> **TL;DR:** Perform comprehensive SSL/TLS security analysis with 0-100 scoring

## Capabilities

- Security scoring (0-100) with Critical/High/Medium/Good levels
- Certificate validity and expiration checks
- TLS version and cipher suite assessment
- HSTS detection and OCSP stapling check
- Actionable recommendations for remediation

## Usage

```
cert_analyze_security target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain or IP with optional port (e.g., 'example.com:8443') |

## Output

- Overall security score (0-100)
- Security level classification
- Certificate analysis details
- TLS connection analysis
- Expiration status
- Issues list with severity
- Recommendations

## Workflow

1. Run `cert_analyze_security` on target domain
2. Check overall score and security level
3. Review individual issues by severity
4. Follow recommendations for remediation

## AI Integration

### CLI (For AI Agents)

```bash
# Install cert-skills first; see the repository README for installation options
cert-skills analyze example.com                    # Text output
cert-skills analyze example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.AnalyzeSecurity("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Bulk security assessment of discovered infrastructure
- Track certificate security posture across organizations
- Identify high-risk domains in large-scale scans
- Compare security scores across service providers

## Limitations

- Requires network connectivity to target
- Score is advisory, not a formal audit
- Some checks depend on server TLS configuration

## Related Skills

- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_scan_vulnerabilities]] cert_scan_vulnerabilities
- [[cert_batch_analyze]] cert_batch_analyze
