---
name: ct-fingerprint-search
description: Search Certificate Transparency logs by certificate fingerprint
tools:
  - cert_search_ct_fingerprint
---

# Ct Fingerprint Search

> **TL;DR:** Search Certificate Transparency logs by certificate fingerprint

## Capabilities

- SHA-256 fingerprint-based search
- CT log inclusion verification
- Certificate tracking across CT logs
- Duplicate certificate detection

## Usage

```
cert_search_ct_fingerprint target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `fingerprint` | string (required) | SHA-256 fingerprint (hex, with or without colons) |

## Output

- Total certificate count
- Certificate details (CN, issuer, validity)
- SHA-256 fingerprints

## Workflow

1. Obtain fingerprint from `cert_fingerprint_domain` or `cert_fingerprint_file`
2. Run `cert_search_ct_fingerprint` with the fingerprint
3. Verify CT log inclusion
4. Check for duplicate certificates across domains

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
cert-skills search-ct-by-fingerprint example.com                    # Text output
cert-skills search-ct-by-fingerprint example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CTSearchByFingerprint(fp)
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Track a known certificate across CT logs
- Find identical certificates deployed on multiple domains
- Trace compromised certificates through CT infrastructure

## Limitations

- Requires exact fingerprint match
- CT log search may be rate-limited

## Related Skills

- [[cert_search_ct]] cert_search_ct
- [[cert_fingerprint_domain]] cert_fingerprint_domain
- [[cert_validate_fingerprint]] cert_validate_fingerprint
