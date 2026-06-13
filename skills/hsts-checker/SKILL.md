---
name: hsts-checker
description: Check HSTS (HTTP Strict Transport Security) status and policy compliance
tools:
  - cert_check_hsts
---

# Hsts Checker

> **TL;DR:** Check HSTS (HTTP Strict Transport Security) status and policy compliance

## Capabilities

- HSTS header detection and parsing
- max-age value verification
- includeSubDomains and preload check
- SSL stripping vulnerability assessment

## Usage

```
cert_check_hsts target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name to check HSTS status |

## Output

- HSTS enabled status
- max-age (seconds and days)
- includeSubDomains status
- preload status
- Raw header value

## Workflow

1. Run `cert_check_hsts` on target
2. If enabled, verify max-age >= 1 year
3. Check includeSubDomains for broad protection
4. If disabled, assess SSL stripping risk

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
cert-skills check-hsts example.com                    # Text output
cert-skills check-hsts example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckHSTS("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Assess HSTS coverage across infrastructure
- Identify domains vulnerable to SSL stripping
- Track HSTS adoption and policy quality

## Limitations

- Requires HTTPS connection
- Does not check HSTS preload list submission status

## Related Skills

- [[cert_analyze_security]] cert_analyze_security
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_pfs]] cert_check_pfs
