---
name: certificate-generator
description: Generate self-signed SSL/TLS certificates for testing and development
tools:
  - cert_generate
---

# Certificate Generator

> **TL;DR:** Generate self-signed SSL/TLS certificates for testing and development

## Capabilities

- RSA 2048/4096-bit, ECDSA P-256/P-384/P-521, Ed25519 keys
- CA certificate generation
- Custom Subject Alternative Names (DNS, IP)
- Configurable validity period

## Usage

```
cert_generate target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `common_name` | string (required) | Common Name (CN) for the certificate |
| `key_type` | string | rsa (default), ecdsa, ed25519 |
| `is_ca` | boolean | Generate CA certificate (default: false) |
| `dns_names` | array | DNS SANs |
| `validity_days` | number | Certificate validity (default: 365) |

## Output

- Certificate PEM file path
- Private key PEM file path
- Fingerprints of generated certificate

## Workflow

1. Determine certificate requirements (key type, SANs, validity)
2. Run `cert_generate` with parameters
3. Use `cert_parse` to verify generated certificate
4. Deploy certificate to test server

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
cert-skills generate example.com                    # Text output
cert-skills generate example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.GenerateSelfSignedCert(opts...)
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Generate test certificates for security lab environments
- Create CA certificates for internal PKI testing
- Produce certificates with specific weaknesses for vulnerability testing

## Limitations

- Self-signed certificates are NOT for production use
- Browsers will show security warnings for self-signed certs

## Related Skills

- [[cert_generate_csr]] cert_generate_csr
- [[cert_parse]] cert_parse
- [[cert_validate_files]] cert_validate_files
- [[cert_fingerprint_file]] cert_fingerprint_file
