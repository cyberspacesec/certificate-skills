---
name: policy-analyzer
description: Analyze certificate policy OIDs for DV/OV/EV classification and compliance
tools:
  - cert_check_policy
  - cert_detect_ev
---

# Policy Analyzer

> **TL;DR:** Analyze certificate policy OIDs for DV/OV/EV classification and compliance

## Capabilities

- DV/OV/EV validation type determination
- Known OID database (DigiCert, Let's Encrypt, Sectigo, etc.)
- Unknown OID detection
- Missing Certificate Policies on public CA certs

## Usage

```
cert_check_policy target="example.com"
cert_detect_ev target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Validation type (DV/OV/EV/Unknown)
- Policy OID list with descriptions
- Compliance status
- Issues list

## Workflow

1. Run `cert_check_policy` on target
2. Review validation type
3. Check for unknown OIDs (private CA indicator)
4. Verify compliance (missing policies = BR violation)

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

- Classify certificate validation level across infrastructure
- Identify private/custom CAs through unknown OIDs
- Track DV/OV/EV adoption rates

## Limitations

- Policy OID database covers major CAs only
- Some CAs use custom OIDs not in database

## Related Skills

- [[cert_detect_ev]] cert_detect_ev
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
