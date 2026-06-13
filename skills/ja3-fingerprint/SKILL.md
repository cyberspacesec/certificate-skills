---
name: ja3-fingerprint
description: Generate JA3/JA3S TLS fingerprints for client and server identification
tools:
  - cert_ja3
---

# Ja3 Fingerprint

> **TL;DR:** Generate JA3/JA3S TLS fingerprints for client and server identification

## Capabilities

- JA3 client fingerprint generation
- JA3S server fingerprint generation
- TLS client hello analysis
- C2 infrastructure detection

## Usage

```
cert_ja3 target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- JA3 hash (client fingerprint)
- JA3S hash (server fingerprint)
- JA3/JA3S raw strings

## Workflow

1. Run `cert_ja3` on target domain
2. Record JA3/JA3S hashes
3. Compare against known JA3 databases
4. Use for C2 detection or service identification

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

- Identify C2 infrastructure through JA3 fingerprinting
- Detect malware communication patterns
- Map server software diversity across organizations

## Limitations

- TLS 1.3 uses encrypted server hello (limited JA3S)
- Some TLS implementations randomize extensions

## Related Skills

- [[cert_jarm]] cert_jarm
- [[cert_scan_protocols]] cert_scan_protocols
- [[cert_scan_ciphers]] cert_scan_ciphers
