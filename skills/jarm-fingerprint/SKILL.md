---
name: jarm-fingerprint
description: Generate JARM TLS fingerprint for server identification and C2 detection
tools:
  - cert_jarm
---

# Jarm Fingerprint

> **TL;DR:** Generate JARM TLS fingerprint for server identification and C2 detection

## Capabilities

- JARM fingerprint via 10 TLS Client Hello probes
- Server software identification
- C2 infrastructure detection
- Works with TLS 1.3 servers

## Usage

```
cert_jarm target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- JARM hash fingerprint
- Target domain and port

## Workflow

1. Run `cert_jarm` on target domain
2. Record JARM hash
3. Compare against known JARM databases (Cobalt Strike, Metasploit)
4. Combine with `cert_ja3` for comprehensive fingerprinting

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

- Identify malicious infrastructure through JARM
- Detect Cobalt Strike, Metasploit, and other C2 frameworks
- Cluster servers with identical JARM hashes

## Limitations

- JARM requires 10 separate TLS connections
- CDN-fronted servers show CDN JARM, not origin

## Related Skills

- [[cert_ja3]] cert_ja3
- [[cert_scan_protocols]] cert_scan_protocols
- [[cert_scan_ciphers]] cert_scan_ciphers
