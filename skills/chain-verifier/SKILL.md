---
name: chain-verifier
description: Verify certificate chain validates to a trusted root
tools:
  - cert_verify_chain
---

# Chain Verifier

> **TL;DR:** Verify certificate chain validates to a trusted root

## Capabilities

- Full chain verification against system trust store
- Chain path display from leaf to root
- Intermediate certificate analysis
- Specific failure reason identification

## Usage

```
cert_verify_chain target="example.com"
```

## Input

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string (required) | Domain name or IP with optional port |

## Output

- Chain validity status
- Chain length and paths
- Verification errors
- Certificate subjects at each level

## Workflow

1. Run `cert_verify_chain` on target
2. If invalid, use `cert_check_bundle` to diagnose
3. If valid, review the trust path
4. Check for distrusted CAs with `cert_check_distrusted_ca`

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

- Identify servers with broken certificate chains
- Detect misconfigured TLS deployments
- Map certificate authority usage patterns

## Limitations

- Uses system trust store (varies by OS)
- Missing intermediates cause failure (see cert_check_bundle)

## Related Skills

- [[cert_check_bundle]] cert_check_bundle
- [[cert_check_distrusted_ca]] cert_check_distrusted_ca
- [[cert_analyze_security]] cert_analyze_security
