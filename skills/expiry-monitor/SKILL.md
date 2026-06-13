---
name: expiry-monitor
description: Monitor certificate expiration across multiple targets with urgency classification
tools:
  - cert_expiry_monitor
---

# Expiry Monitor

> **TL;DR:** Monitor certificate expiration across multiple targets with urgency classification

## Capabilities

- Multi-target monitoring (domains + files)
- Urgency: Expired/Critical(<=7d)/Warning(<=30d)/Healthy
- Mixed input support
- Batch processing

## Usage

```
cert_expiry_monitor target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `targets` | array (required) | List of domain names, domain:port, or certificate file paths |

## Output

- Per-target: expiry date, days remaining, status
- Summary: total count, per-status counts

## Workflow

1. Prepare list of targets
2. Run `cert_expiry_monitor` with all targets
3. Focus on Expired and Critical first
4. Use `cert_info` for detailed analysis

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

## Cyberspace Mapping Applications

- Track certificate lifecycle across infrastructure
- Identify expiring certificates proactively
- Alert on expired certificates in production

## Limitations

- Network required for domain targets
- Does not send notifications (polling only)

## Related Skills

- [[cert_info]] cert_info
- [[cert_analyze_security]] cert_analyze_security
- [[cert_check_revocation]] cert_check_revocation
