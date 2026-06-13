---
name: fingerprint-validator
description: Validate certificate fingerprint format correctness for SHA-256, SHA-1, or MD5
tools:
  - cert_validate_fingerprint
---

# Fingerprint Validator

> **TL;DR:** Validate certificate fingerprint format correctness for SHA-256, SHA-1, or MD5

## Capabilities

- SHA-256 format validation (64 hex chars)
- SHA-1 format validation (40 hex chars)
- MD5 format validation (32 hex chars)
- Colon separator handling

## Usage

```
cert_validate_fingerprint target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `fingerprint` | string (required) | Fingerprint hex string (colons optional) |
| `hash_type` | string (required) | Hash algorithm: sha256, sha1, or md5 |

## Output

- Whether fingerprint is valid
- Error description if invalid

## Workflow

1. Obtain fingerprint from `cert_fingerprint_domain` or manual source
2. Run `cert_validate_fingerprint` with fingerprint and hash type
3. If valid, use with `cert_search_ct_fingerprint`

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

- Validate fingerprint data before database storage
- Ensure fingerprint consistency in bulk imports

## Limitations

- Validates format only, not whether fingerprint matches a real certificate

## Related Skills

- [[cert_fingerprint_domain]] cert_fingerprint_domain
- [[cert_fingerprint_file]] cert_fingerprint_file
- [[cert_search_ct_fingerprint]] cert_search_ct_fingerprint
