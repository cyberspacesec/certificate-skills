---
name: ev-detector
description: Detect Extended Validation (EV) certificates through policy OID analysis
tools:
  - cert_detect_ev
---

# Ev Detector

> **TL;DR:** Detect Extended Validation (EV) certificates through policy OID analysis

## Capabilities

- EV detection via policy OID matching
- CA/B Forum EV OID database
- CA identification
- Reason explanation

## Usage

```
cert_detect_ev target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Whether certificate is EV
- Policy OIDs found
- Issuer organization
- Reason for determination

## Workflow

1. Run `cert_detect_ev` on target
2. If EV, verify issuer organization
3. If not EV, check `cert_check_policy` for DV/OV classification

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

- Identify high-assurance certificates in the wild
- Map EV certificate adoption across organizations
- Detect potential phishing using non-EV for financial services

## Limitations

- EV determination depends on OID database coverage
- Some CAs use custom EV OIDs not in the database

## Related Skills

- [[cert_check_policy]] cert_check_policy
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_analyze_security]] cert_analyze_security
