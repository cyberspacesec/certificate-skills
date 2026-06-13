---
name: certificate-validate
description: Validate that certificate and private key files match and are correctly formatted
tools:
  - cert_validate_files
---

# Certificate Validate

> **TL;DR:** Validate that certificate and private key files match and are correctly formatted

## Capabilities

- PEM format validation
- Public key matching verification
- RSA, ECDSA, Ed25519 support
- Detailed error reporting

## Usage

```
cert_validate_files target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `cert_path` | string (required) | Path to certificate PEM file |
| `key_path` | string (required) | Path to private key PEM file |

## Output

- PEM format validity for both files
- Whether public key matches private key
- Key type identification
- Error details if validation fails

## Workflow

1. Obtain certificate and key file paths
2. Run `cert_validate_files` with both paths
3. Check PEM format validity
4. Verify key pair matches

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


## AI Integration

### CLI (For AI Agents)

```bash
# Install first: see Installation section above
cert-skills validate example.com                    # Text output
cert-skills validate example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.ValidateCertificateFiles(certPath, keyPath)
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Validate certificate-key pairs before deployment
- Bulk validation of certificate collections
- Detect misconfigured TLS deployments

## Limitations

- Requires local file access
- Does not verify certificate chain or trust

## Related Skills

- [[cert_parse]] cert_parse
- [[cert_generate]] cert_generate
- [[cert_fingerprint_file]] cert_fingerprint_file
