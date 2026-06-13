---
name: certificate-batch-analysis
description: Batch analyze SSL/TLS security for multiple domains simultaneously
tools:
  - cert_batch_analyze
---

# Certificate Batch Analysis

> **TL;DR:** Batch analyze SSL/TLS security for multiple domains simultaneously

## Capabilities

- Multi-domain analysis (up to hundreds of targets)
- Per-domain security scores (0-100)
- Summary statistics with severity distribution
- Efficient concurrent processing

## Usage

```
cert_batch_analyze target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `targets` | array (required) | List of domain names or IP addresses with optional ports |

## Output

- Per-domain: security score, severity, issues, recommendations
- Summary: counts per level, average score, total analyzed

## Workflow

1. Prepare list of target domains
2. Run `cert_batch_analyze` with all targets
3. Review summary for overall posture
4. Drill into individual low-scoring domains
5. Use `cert_analyze_security` for deep analysis of problem domains

## Cyberspace Mapping Applications

- Bulk security assessment across discovered infrastructure
- Track certificate security posture across organizations
- Identify high-risk domains in large-scale scans

## Limitations

- Network dependent - slow targets may timeout
- Individual domain analysis is less detailed than single scan

## Related Skills

- [[cert_analyze_security]] cert_analyze_security
- [[cert_expiry_monitor]] cert_expiry_monitor
- [[cert_scan_cert_security]] cert_scan_cert_security
