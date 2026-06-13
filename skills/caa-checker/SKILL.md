---
name: caa-checker
description: Check DNS CAA records and verify CA authorization for certificate issuance
tools:
  - cert_check_caa
---

# Caa Checker

> **TL;DR:** Check DNS CAA records and verify CA authorization for certificate issuance

## Capabilities

- DNS CAA record querying (issue, issuewild, iodef)
- CA authorization verification
- Misconfiguration detection
- Compliance checking

## Usage

```
cert_check_caa target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name to check CAA records for |

## Output

- CAA records existence
- Record details (flag, tag, value)
- CA authorization status
- IODEF reporting URL

## Workflow

1. Run `cert_check_caa` on target domain
2. If CAA exists, verify issuing CA is authorized
3. If no CAA, any CA can issue (consider adding CAA)
4. Recommend CAA policy for restricted issuance

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
cert-skills check-caa example.com                    # Text output
cert-skills check-caa example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckCAA("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Identify which CAs are authorized for a domain
- Detect unauthorized certificate issuance through CAA
- Map CA relationships and trust boundaries

## Limitations

- Requires DNS resolution
- Not all DNS resolvers support CAA type
- CAA is only checked by compliant CAs

## Related Skills

- [[cert_verify_chain]] cert_verify_chain
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
- [[cert_search_ct]] cert_search_ct
