---
name: certificate-csr
description: Generate a Certificate Signing Request (CSR) for submitting to a CA
tools:
  - cert_generate_csr
---

# Certificate Csr

> **TL;DR:** Generate a Certificate Signing Request (CSR) for submitting to a CA

## Capabilities

- RSA 2048/4096-bit, ECDSA P-256/P-384/P-521, Ed25519 keys
- Subject Alternative Names support
- Private key generated but NOT saved to disk

## Usage

```
cert_generate_csr target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `common_name` | string (required) | Primary domain name for the CSR |
| `key_type` | string | Key algorithm: rsa (default), ecdsa, ed25519 |
| `dns_names` | array | Additional DNS names for SANs |

## Output

- PEM-encoded CSR text content
- Suitable for submission to Let's Encrypt, DigiCert, etc.

## Workflow

1. Determine domain name and key requirements
2. Run `cert_generate_csr` with parameters
3. Copy the CSR output
4. Submit CSR to your Certificate Authority

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
cert-skills generate-csr example.com                    # Text output
cert-skills generate-csr example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.GenerateCSR(commonName, opts...)
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Generate CSRs for bulk domain certificate provisioning
- Standardize key algorithms across infrastructure
- Automate CSR generation for CI/CD pipelines

## Limitations

- Private key is NOT saved to disk for security
- Must save private key separately before closing session

## Related Skills

- [[cert_generate]] cert_generate
- [[cert_validate_files]] cert_validate_files
- [[cert_parse]] cert_parse
