---
name: distrusted-ca-checker
description: Detect certificates issued by known distrusted/compromised Certificate Authorities
tools:
  - cert_check_distrusted_ca
---

# Distrusted Ca Checker

> **TL;DR:** Detect certificates issued by known distrusted/compromised Certificate Authorities

## Capabilities

- DigiNotar (2011 CA compromise)
- WoSign/StartCom (mis-issuance)
- Symantec legacy (audit failures)
- CNNIC, TrustCor, DarkMatter detection
- 13 known distrusted CAs in database

## Usage

```
cert_check_distrusted_ca target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Whether chain contains distrusted CA
- Distrusted CA details (name, reason, date, severity)
- Chain position
- Fingerprint

## Workflow

1. Run `cert_check_distrusted_ca` on target
2. If distrusted CA found, review reason and severity
3. Check distrust date for timeline
4. Use `cert_scan_cert_security` for comprehensive scan

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
cert-skills check-distrusted-ca example.com                    # Text output
cert-skills check-distrusted-ca example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckDistrustedCA("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Detect infrastructure using untrusted certificates
- Find services still trusting compromised CAs
- Map CA trust relationships across organizations

## Limitations

- Database covers major public distrust events only
- Private/internal CAs are not evaluated

## Related Skills

- [[cert_verify_chain]] cert_verify_chain
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_check_policy]] cert_check_policy
