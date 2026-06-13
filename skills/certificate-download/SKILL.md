---
name: certificate-download
description: Download SSL/TLS certificate chain from a remote domain and save to PEM files
tools:
  - cert_download
---

# Certificate Download

> **TL;DR:** Download SSL/TLS certificate chain from a remote domain and save to PEM files

## Capabilities

- Full certificate chain download
- Separate leaf and chain files
- Custom output directory
- PEM format output

## Usage

```
cert_download target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |
| `output_dir` | string | Output directory for saved files |

## Output

- Saved certificate PEM file paths
- Chain length
- Target domain

## Workflow

1. Run `cert_download` on target domain
2. Verify saved files exist
3. Use `cert_parse` to inspect downloaded certificate
4. Use `cert_fingerprint_file` on the saved file

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
cert-skills download example.com                    # Text output
cert-skills download example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.DownloadCertsFromDomain("example.com", dir)
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Collect certificates for offline analysis
- Build certificate databases for cyberspace mapping
- Archive certificates from discovered infrastructure

## Limitations

- Only downloads the chain the server presents
- Missing intermediates won't be fetched

## Related Skills

- [[cert_info]] cert_info
- [[cert_parse]] cert_parse
- [[cert_check_bundle]] cert_check_bundle
- [[cert_fingerprint_file]] cert_fingerprint_file
