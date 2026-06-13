---
name: ct-subdomain-enumerator
description: Enumerate subdomains through Certificate Transparency logs
tools:
  - cert_ct_enumerate
---

# Ct Subdomain Enumerator

> **TL;DR:** Enumerate subdomains through Certificate Transparency logs

## Capabilities

- Subdomain discovery from CT certificates
- Wildcard certificate detection
- Issuer grouping
- Active/expired tracking
- Organization mapping

## Usage

```
cert_ct_enumerate target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string (required) | Domain name to enumerate subdomains for |

## Output

- Total certificates found
- Active vs expired counts
- Unique subdomain list
- Wildcard domains
- Per-issuer grouping

## Workflow

1. Run `cert_ct_enumerate` on target domain
2. Review unique subdomain list
3. Check wildcard domains
4. Group by issuer for CA relationships

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
cert-skills ct-enumerate example.com                    # Text output
cert-skills ct-enumerate example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CTEnumerateSubdomains("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Passive subdomain enumeration (no direct scanning)
- Discover organizational domain infrastructure
- Track certificate issuance patterns over time

## Limitations

- Only finds subdomains that have certificates
- CT logs may have delays
- Wildcard certificates reveal base domain only

## Related Skills

- [[cert_search_ct]] cert_search_ct
- [[cert_search_ct_fingerprint]] cert_search_ct_fingerprint
- [[cert_check_wildcard]] cert_check_wildcard
