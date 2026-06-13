---
name: serial-entropy-checker
description: Analyze certificate serial number entropy for CA/B BR compliance (>=64 bits required)
tools:
  - cert_check_serial_entropy
---

# Serial Entropy Checker

> **TL;DR:** Analyze certificate serial number entropy for CA/B BR compliance (>=64 bits required)

## Capabilities

- Serial bit length check (>= 64 bits)
- Shannon entropy estimation
- Hamming weight analysis for bias detection
- Sequential serial detection
- Predictability assessment

## Usage

```
cert_check_serial_entropy target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Serial hex
- Bit length
- Compliance status
- Entropy estimate
- Hamming weight/ratio
- Sequential flag

## Workflow

1. Run `cert_check_serial_entropy` on target
2. Check bit length >= 64 bits
3. Review entropy (>3.0 bits/byte is healthy)
4. Verify not sequential/predictable

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
cert-skills check-serial-entropy example.com                    # Text output
cert-skills check-serial-entropy example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckSerialEntropy("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Identify certificates from non-compliant CAs
- Track serial number quality across CA issuers
- Detect CAs using sequential numbering

## Limitations

- Entropy estimation is heuristic
- Some legitimate CAs may have low-entropy serials in older certificates

## Related Skills

- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_key_usage]] cert_check_key_usage
- [[cert_check_policy]] cert_check_policy
