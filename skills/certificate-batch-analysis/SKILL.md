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

## Installation

### Download Binary

```bash
# Linux x86_64
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_linux_x86_64.tar.gz | tar xz

# macOS Apple Silicon
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_darwin_aarch64.tar.gz | tar xz

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_windows_x86_64.zip" -OutFile "cert-skills.zip"
Expand-Archive cert-skills.zip
```

### Build from Source

```bash
git clone https://github.com/cyberspacesec/certificate-skills.git
cd certificate-skills
go build -trimpath -ldflags "-s -w" -o cert-skills ./cmd/
```

### Install Globally

```bash
sudo mv cert-skills /usr/local/bin/
```

### Verify Installation

```bash
cert-skills --version
```

### Install as Go Module

```bash
go get github.com/cyberspacesec/certificate-skills/pkg
```


## AI Integration

### CLI (For AI Agents)

```bash
# Install first: see Installation section above
cert-skills batch-analyze example.com                    # Text output
cert-skills batch-analyze example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.BatchAnalyzeSecurity([]string{"a.com", "b.com"})
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

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
