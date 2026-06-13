---
name: tls-scanner
description: Scan TLS protocol versions and cipher suites for security assessment
tools:
  - cert_scan_protocols
  - cert_scan_ciphers
---

# Tls Scanner

> **TL;DR:** Scan TLS protocol versions and cipher suites for security assessment

## Capabilities

- TLS protocol version scanning (1.0 through 1.3)
- Cipher suite enumeration per version
- Secure vs weak cipher classification
- Export-grade cipher detection

## Usage

```
cert_scan_protocols target="example.com"
cert_scan_ciphers target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |
| `tls_version` | number | TLS version for cipher scan (1.2=0x0303, 1.3=0x0304) |

## Output

- Supported TLS versions
- Cipher suites per version
- Secure vs weak classification
- Export-grade warnings

## Workflow

1. Run `cert_scan_protocols` to identify versions
2. Run `cert_scan_ciphers` for each version
3. Focus on weak and export-grade ciphers
4. Verify TLS 1.3 support

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

- Assess TLS configuration security across infrastructure
- Identify servers supporting deprecated protocols (TLS 1.0/1.1)
- Find weak cipher suites vulnerable to attack

## Limitations

- Scanning requires multiple TLS connections
- Server may behave differently under load

## Related Skills

- [[cert_scan_vulnerabilities]] cert_scan_vulnerabilities
- [[cert_check_pfs]] cert_check_pfs
- [[cert_analyze_security]] cert_analyze_security
