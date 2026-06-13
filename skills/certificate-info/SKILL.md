---
name: certificate-info
description: Retrieve and display detailed SSL/TLS certificate and connection information
tools:
  - cert_info
---

# Certificate Info

> **TL;DR:** Retrieve and display detailed SSL/TLS certificate and connection information

## Capabilities

- Full certificate chain details
- TLS version and cipher suite
- HTTP/2 support detection
- OCSP stapling status
- Handshake timing
- Batch processing of multiple targets

## Usage

```
cert_info target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain, domain:port, or file path. Supports multiple targets. |

## Output

- TLS version and cipher suite
- HTTP/2 and OCSP stapling status
- Full certificate chain details
- Fingerprints for each certificate

## Workflow

1. Run `cert_info` on target domain or file
2. Review TLS connection details
3. Check certificate chain for completeness
4. Use `cert_analyze_security` for deeper analysis

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

- Rapid certificate reconnaissance for target domains
- Map TLS configurations across infrastructure
- Identify certificate authorities used by target organizations

## Limitations

- Network required for domain targets
- File mode provides cert-only info (no TLS details)

## Related Skills

- [[cert_parse]] cert_parse
- [[cert_analyze_security]] cert_analyze_security
- [[cert_fingerprint_domain]] cert_fingerprint_domain
- [[cert_download]] cert_download
