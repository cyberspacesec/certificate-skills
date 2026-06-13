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
