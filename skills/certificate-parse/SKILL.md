---
name: certificate-parse
description: Parse local certificate files (PEM/DER) and display detailed information
tools:
  - cert_parse
---

# Certificate Parse

> **TL;DR:** Parse local certificate files (PEM/DER) and display detailed information

## Capabilities

- PEM and DER format parsing
- Full certificate details extraction
- Chain parsing from PEM bundle
- Fingerprint generation

## Usage

```
cert_parse target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `file_path` | string (required) | Path to certificate file (.pem, .crt, .cer, .der) |

## Output

- Subject and issuer details
- Validity period
- SANs (DNS, IP)
- Key usage and extended key usage
- Fingerprints (SHA-256, SHA-1, MD5)

## Workflow

1. Download or obtain certificate file
2. Run `cert_parse` on the file
3. Review certificate details
4. Use `cert_fingerprint_file` for fingerprint extraction

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
cert-skills parse example.com                    # Text output
cert-skills parse example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.GetCertFromFile("cert.pem")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Batch parse certificates from CT log downloads
- Extract metadata from certificate collections
- Validate certificate files before deployment

## Limitations

- Local file access required
- Cannot parse password-protected PKCS#12 files

## Related Skills

- [[cert_info]] cert_info
- [[cert_fingerprint_file]] cert_fingerprint_file
- [[cert_download]] cert_download
