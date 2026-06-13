---
name: certificate-revocation
description: Check certificate revocation status via OCSP and CRL
tools:
  - cert_check_revocation
---

# Certificate Revocation

> **TL;DR:** Check certificate revocation status via OCSP and CRL

## Capabilities

- OCSP (Online Certificate Status Protocol) checking
- CRL (Certificate Revocation List) verification
- Revocation reason identification
- Overall status determination (Good/Revoked/Unknown)

## Usage

```
cert_check_revocation target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- OCSP status (Good/Revoked/Unknown)
- CRL status
- Revocation reason if revoked
- OCSP responder URL
- CRL distribution points

## Workflow

1. Run `cert_check_revocation` on target
2. Check OCSP status first (real-time)
3. If Unknown, check CRL status
4. Review revocation reason if revoked

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

- Detect revoked certificates still deployed in the wild
- Track certificate revocation patterns
- Identify certificates revoked due to compromise

## Limitations

- OCSP may return Unknown for some certificates
- CRL files can be large
- Revocation checking is not 100% reliable (soft-fail problem)

## Related Skills

- [[cert_check_ocsp_must_staple]] cert_check_ocsp_must_staple
- [[cert_analyze_security]] cert_analyze_security
- [[cert_check_bundle]] cert_check_bundle
