---
name: hostname-verifier
description: Verify certificate hostname matching and RFC 6125 compliance
tools:
  - cert_verify_hostname
---

# Hostname Verifier

> **TL;DR:** Verify certificate hostname matching and RFC 6125 compliance

## Capabilities

- SAN/CN hostname matching
- Wildcard match detection (RFC 6125)
- Mismatch details with suggestions
- CN vs SAN issue identification

## Usage

```
cert_verify_hostname target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Whether hostname matches
- Match type (exact/wildcard)
- Mismatch details
- Closest match suggestion

## Workflow

1. Run `cert_verify_hostname` on target
2. If mismatch, review details
3. Check closest match suggestion
4. Verify with `cert_scan_cert_security`

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

- Identify misconfigured certificates with hostname mismatches
- Detect potentially malicious certificates
- Validate certificate deployment across infrastructure

## Limitations

- Wildcard matching follows RFC 6125 (one label only)
- Does not check all SANs, only the requested hostname

## Related Skills

- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_wildcard]] cert_check_wildcard
- [[cert_get_trusted_domains]] cert_get_trusted_domains
