---
name: bundle-checker
description: Check certificate bundle completeness and diagnose missing intermediates via AIA
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
