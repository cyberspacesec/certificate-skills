---
name: cert-security-scanner
description: Scan certificate-specific security issues (18 checks from weak signatures to name constraints)
tools:
  - cert_scan_cert_security
---

# Cert Security Scanner

> **TL;DR:** Scan certificate-specific security issues (18 checks from weak signatures to name constraints)

## Capabilities

- CERT-001~005: Weak signature, short RSA key, weak ECDSA, missing SAN, hostname mismatch
- CERT-006~010: Excessive validity, self-signed, expired, expiring soon, CN not in SANs
- CERT-011~013: Wildcard risk, internal name, untrusted chain
- CERT-014~018: Distrusted CA, OCSP Must-Staple, key usage, serial entropy, name constraints

## Usage

```
cert_scan_cert_security target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- 18 check results (pass/fail)
- Severity per check (Critical/High/Medium/Low)
- Detailed description per finding
- Summary: total, passed, failed, is_secure

## Workflow

1. Run `cert_scan_cert_security` on target
2. Review summary for overall status
3. Focus on Critical and High severity failures
4. Use specific check tools for deeper analysis (cert_check_distrusted_ca, cert_check_key_usage, etc.)

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
cert-skills scan-cert-security example.com                    # Text output
cert-skills scan-cert-security example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.ScanCertSecurity("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Bulk identify weak/misconfigured certificates across infrastructure
- Detect expired or soon-to-expire certificates in the wild
- Find self-signed or untrusted certificates on public services

## Limitations

- Requires network connectivity
- Some checks may have false positives on private PKI

## Related Skills

- [[cert_analyze_security]] cert_analyze_security
- [[cert_scan_vulnerabilities]] cert_scan_vulnerabilities
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
- [[cert_check_key_usage]] cert_check_key_usage
