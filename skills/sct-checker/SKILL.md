---
name: sct-checker
description: Verify Signed Certificate Timestamps (SCTs) for Certificate Transparency compliance
tools:
  - cert_check_sct
---

# Sct Checker

> **TL;DR:** Verify Signed Certificate Timestamps (SCTs) for Certificate Transparency compliance

## Capabilities

- Embedded SCT extraction
- CA/B Forum CT compliance checking
- Validity-based SCT count requirements
- SCT detail parsing (log ID, timestamp, source)

## Usage

```
cert_check_sct target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Has SCTs flag
- SCT count
- Meets CA/B requirement
- SCT details

## Workflow

1. Run `cert_check_sct` on target
2. Check if SCTs are present
3. Verify count meets CA/B requirement
4. Review SCT details for log operator diversity

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

- Identify certificates that may not comply with CT requirements
- Detect potentially misissued certificates
- Map CT log coverage across infrastructure

## Limitations

- Only checks embedded SCTs
- Does not validate SCT signatures

## Related Skills

- [[cert_search_ct]] cert_search_ct
- [[cert_ct_enumerate]] cert_ct_enumerate
- [[cert_scan_cert_security]] cert_scan_cert_security
