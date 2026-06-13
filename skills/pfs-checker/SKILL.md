---
name: pfs-checker
description: Check Perfect Forward Secrecy (PFS) support through ECDHE/DHE key exchange
tools:
  - cert_check_pfs
---

# Pfs Checker

> **TL;DR:** Check Perfect Forward Secrecy (PFS) support through ECDHE/DHE key exchange

## Capabilities

- PFS support detection
- Key exchange type (ECDHE/DHE/None)
- Cipher suite reporting
- PFS strength assessment

## Usage

```
cert_check_pfs target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- PFS support status
- Key exchange type
- Negotiated cipher suite
- TLS version
- Security notes

## Workflow

1. Run `cert_check_pfs` on target
2. If no PFS, assess risk of key compromise
3. If DHE-based, consider upgrading to ECDHE
4. Cross-reference with `cert_scan_ciphers`

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

- Assess forward secrecy coverage across infrastructure
- Identify servers vulnerable to private key compromise
- Track PFS adoption trends

## Limitations

- Only checks negotiated cipher suite
- PFS depends on both client and server support

## Related Skills

- [[cert_scan_ciphers]] cert_scan_ciphers
- [[cert_scan_protocols]] cert_scan_protocols
- [[cert_analyze_security]] cert_analyze_security
