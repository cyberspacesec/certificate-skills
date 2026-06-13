---
name: certificate-analysis
description: Perform comprehensive SSL/TLS security analysis with 0-100 scoring
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
