---
name: certificate-fingerprint
description: Generate certificate fingerprints (SHA-256, SHA-1, MD5, SPKI) for pinning and verification
tools:
  - cert_fingerprint_domain
  - cert_fingerprint_file
---

# Certificate Fingerprint

> **TL;DR:** Generate certificate fingerprints (SHA-256, SHA-1, MD5, SPKI) for pinning and verification

## Capabilities

- SHA-256, SHA-1, MD5 certificate fingerprints
- Public key SHA-256 for SSL pinning
- Domain-based or file-based input

## Usage

```
cert_fingerprint_domain target="example.com"
cert_fingerprint_file target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target (domain)` | string (required) | Domain name or IP with optional port |
| `file_path (file)` | string (required) | Path to certificate file (PEM or DER) |

## Output

- SHA-256 fingerprint
- SHA-1 fingerprint
- MD5 fingerprint
- Public key SHA-256 (for SSL pinning)

## Workflow

1. Run `cert_fingerprint_domain` or `cert_fingerprint_file`
2. Record fingerprints for comparison
3. Use `cert_validate_fingerprint` to verify format
4. Use `cert_compare` to compare across domains

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
cert-skills fingerprint example.com                    # Text output
cert-skills fingerprint example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.GenerateFingerprints(cert)
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Build fingerprint databases for certificate tracking
- Detect unauthorized certificate changes via fingerprint monitoring
- Correlate certificates across domains via SPKI hash

## Limitations

- Fingerprints change on certificate renewal
- SPKI hash remains stable across renewals for same key

## Related Skills

- [[cert_validate_fingerprint]] cert_validate_fingerprint
- [[cert_compare]] cert_compare
- [[cert_info]] cert_info
