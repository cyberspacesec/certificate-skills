---
name: name-constraints-checker
description: Check CA name constraints and detect trust boundary violations
tools:
  - cert_check_name_constraints
---

# Name Constraints Checker

> **TL;DR:** Check CA name constraints and detect trust boundary violations

## Capabilities

- CA constraint extraction (permitted/excluded DNS, IP, email)
- Leaf name compliance verification
- Trust boundary violation detection
- Full chain constraint walking

## Usage

```
cert_check_name_constraints target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Whether constraints exist
- Constrained CAs with details
- Violation list
- Compliance status

## Workflow

1. Run `cert_check_name_constraints` on target
2. If constraints exist, review constrained CAs
3. Check for violations
4. Violations indicate trust boundary breaches

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
cert-skills check-name-constraints example.com                    # Text output
cert-skills check-name-constraints example.com -o json           # JSON output for AI parsing
```

### Go SDK (For programmatic use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.CheckNameConstraints("example.com")
```

### MCP Tool (For Claude Code)

This skill is available as the MCP tools listed in the frontmatter above.

## Cyberspace Mapping Applications

- Detect over-permissive CAs with no constraints
- Find trust boundary violations in corporate sub-CA deployments
- Map CA constraint policies

## Limitations

- Only checks constraints in the presented chain
- Some CAs use constraints not in the certificate extension

## Related Skills

- [[cert_check_key_usage]] cert_check_key_usage
- [[cert_scan_cert_security]] cert_scan_cert_security
- [[cert_verify_chain]] cert_verify_chain
