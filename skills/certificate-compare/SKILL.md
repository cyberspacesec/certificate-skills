---
name: certificate-compare
description: Compare two SSL/TLS certificates to determine if they are identical or different
tools:
  - cert_compare
---

# Certificate Compare

> **TL;DR:** Compare two SSL/TLS certificates to determine if they are identical or different

## Capabilities

- Fingerprint comparison (SHA-256, SHA-1, MD5)
- Subject and issuer comparison
- Validity period and key algorithm comparison
- Mixed: domain vs domain, file vs file, domain vs file

## Usage

```
cert_compare target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target1` | string (required) | First certificate target (domain or file path) |
| `target2` | string (required) | Second certificate target (domain or file path) |

## Output

- Whether certificates are identical or different
- Fingerprint comparison
- Differences in subject, issuer, validity, key details

## Workflow

1. Obtain two certificate targets (domains or local files)
2. Run `cert_compare` with both targets
3. Review fingerprint match results
4. Check specific differences if certificates differ

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

- Verify certificate deployment consistency across load balancers
- Detect unauthorized certificate replacements
- Compare certificates across related domains for shared issuers

## Limitations

- Both targets must be accessible
- Cannot compare more than two certificates at once

## Related Skills

- [[cert_fingerprint_domain]] cert_fingerprint_domain
- [[cert_fingerprint_file]] cert_fingerprint_file
- [[cert_info]] cert_info
