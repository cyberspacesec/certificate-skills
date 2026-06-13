# cert-skills 🔒

**AI-Native Certificate Security Toolkit & SDK**

A comprehensive SSL/TLS certificate security toolkit and Go SDK — designed for AI agents, security researchers, and cyberspace mapping operations. Works as a CLI, Go library, and MCP server.

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Server-green.svg)](https://modelcontextprotocol.io)
[![Release](https://img.shields.io/github/v/release/cyberspacesec/certificate-skills?include_prereleases)](https://github.com/cyberspacesec/certificate-skills/releases/latest)

> 🤖 **AI-Native**: This project is designed as an AI-first toolkit. It ships as an MCP server with 40 tools that AI agents can directly invoke, plus a Go SDK for programmatic use and a CLI for humans.

---

## 🌍 Languages

**English** (default) | [简体中文](#-简体中文)

---

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [CLI Usage](#-cli-usage)
- [Go SDK](#-go-sdk)
- [AI Integration (MCP)](#-ai-integration-mcp)
- [Security Checks](#-security-checks)
- [Skills](#-skills)
- [Architecture](#-architecture)

---

## ✨ Features

### 🔍 Certificate Intelligence
| Capability | Description |
|-----------|-------------|
| Certificate Info | Retrieve detailed SSL/TLS certificate and connection information |
| Certificate Parse | Parse local certificate files (PEM/DER) |
| Certificate Download | Download certificate chains from remote domains |
| Certificate Compare | Compare two certificates (fingerprint, subject, issuer, validity) |
| Fingerprint Generation | SHA-256, SHA-1, MD5, and SPKI fingerprints |
| Fingerprint Validation | Validate fingerprint format correctness |
| Batch Analysis | Analyze multiple domains simultaneously |

### 🛡️ Security Analysis
| Capability | Description |
|-----------|-------------|
| Security Scoring | 0-100 security score with severity levels |
| 18 Cert Security Checks | Weak signatures → name constraints (CERT-001 to CERT-018) |
| 11 TLS Vulnerability Scans | Heartbleed, POODLE, ROBOT, CCS, FREAK, Logjam, Sweet32, BEAST, CRIME, DROWN, Renegotiation |
| Distrusted CA Detection | DigiNotar, WoSign, StartCom, Symantec, CNNIC, TrustCor, DarkMatter |
| OCSP Must-Staple | RFC 7633 compliance check |
| Key Usage Compliance | RFC 5280 and CA/B BR validation |
| Serial Entropy Analysis | CA/B BR 64-bit entropy requirement |
| Name Constraints | CA trust boundary violation detection |
| Certificate Policy Analysis | DV/OV/EV classification via policy OIDs |
| Bundle Completeness | Missing intermediate diagnosis with AIA fetch |

### 🔐 PKI Operations
| Capability | Description |
|-----------|-------------|
| Certificate Generation | Self-signed certs with RSA/ECDSA/Ed25519 keys |
| CSR Generation | Certificate Signing Requests for CA submission |
| Certificate Validation | Validate cert-key pair matching |
| Chain Verification | Verify certificate chain to trusted root |

### 🌐 Cyberspace Mapping
| Capability | Description |
|-----------|-------------|
| CT Log Search | Search Certificate Transparency logs by domain or fingerprint |
| CT Subdomain Enumeration | Discover subdomains through CT certificates |
| JARM Fingerprinting | Server identification and C2 detection |
| JA3/JA3S Fingerprinting | Client and server TLS fingerprinting |
| EV Detection | Extended Validation certificate detection |
| HSTS Check | HTTP Strict Transport Security status |
| CAA Check | DNS CAA record verification |
| SCT Verification | Signed Certificate Timestamp compliance |
| Wildcard Analysis | Wildcard certificate risk assessment |
| Trusted Domain Extraction | Extract all domains from a certificate |
| PFS Check | Perfect Forward Secrecy support |
| Session Resumption | TLS session ID and ticket support |
| Expiry Monitor | Multi-target certificate expiration monitoring |
| Revocation Check | OCSP and CRL revocation status |

---

## 🚀 Quick Start

```bash
# Install (Linux/macOS)
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_linux_x86_64.tar.gz | tar xz
sudo mv cert-skills /usr/local/bin/

# Analyze a domain
cert-skills analyze google.com

# Security scan
cert-skills scan-cert-security example.com

# Search CT logs
cert-skills search-ct example.com

# JARM fingerprint
cert-skills jarm suspicious-server.com
```

---

## 📦 Installation

### Pre-built Binaries (Recommended)

Download from [GitHub Releases](https://github.com/cyberspacesec/certificate-skills/releases/latest):

```bash
# Linux x86_64
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_linux_x86_64.tar.gz | tar xz
sudo mv cert-skills /usr/local/bin/

# Linux ARM64 (AWS Graviton, Raspberry Pi 5, etc.)
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_linux_aarch64.tar.gz | tar xz
sudo mv cert-skills /usr/local/bin/

# macOS Apple Silicon
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_darwin_aarch64.tar.gz | tar xz
sudo mv cert-skills /usr/local/bin/

# macOS Intel
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_darwin_x86_64.tar.gz | tar xz
sudo mv cert-skills /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_windows_x86_64.zip" -OutFile "cert-skills.zip"
Expand-Archive cert-skills.zip
```

### Available Platforms

| OS | Architecture | File |
|----|-------------|------|
| Linux | x86_64 | `certificate-skills_*_linux_x86_64.tar.gz` |
| Linux | ARM64 | `certificate-skills_*_linux_aarch64.tar.gz` |
| Linux | ARM v7 | `certificate-skills_*_linux_arm.tar.gz` |
| Linux | i386 | `certificate-skills_*_linux_i386.tar.gz` |
| macOS | Apple Silicon | `certificate-skills_*_darwin_aarch64.tar.gz` |
| macOS | Intel | `certificate-skills_*_darwin_x86_64.tar.gz` |
| Windows | x86_64 | `certificate-skills_*_windows_x86_64.zip` |
| Windows | i386 | `certificate-skills_*_windows_i386.zip` |
| FreeBSD | x86_64 | `certificate-skills_*_freebsd_x86_64.tar.gz` |

Two binaries per platform: **`cert-skills`** (CLI) and **`cert-skills-mcp`** (MCP server).

### Build from Source

```bash
# Requires Go 1.23+
git clone https://github.com/cyberspacesec/certificate-skills.git
cd certificate-skills

# Build CLI
go build -trimpath -ldflags "-s -w" -o cert-skills ./cmd/

# Build MCP Server
go build -trimpath -ldflags "-s -w" -o cert-skills-mcp ./cmd/mcp/

# Or install globally
go install ./cmd/
```

### Go Module

```bash
go get github.com/cyberspacesec/certificate-skills/pkg
```

---

## 🖥️ CLI Usage

```bash
# Security analysis
cert-skills analyze google.com                         # Full security scoring (0-100)
cert-skills scan-cert-security google.com              # 18 cert security checks
cert-skills scan-vulns google.com                      # 11 TLS vulnerability scans
cert-skills scan-protocols google.com                  # TLS version scan
cert-skills scan-ciphers google.com                    # Cipher suite scan

# Certificate operations
cert-skills info google.com                            # Certificate information
cert-skills info google.com baidu.com                  # Batch info
cert-skills fingerprint google.com                     # SHA-256/SHA-1/MD5/SPKI
cert-skills compare -1 google.com -2 baidu.com         # Compare certificates
cert-skills download google.com                        # Download cert chain
cert-skills parse cert.pem                             # Parse local file
cert-skills validate -c cert.pem -k key.pem            # Validate cert-key pair

# PKI operations
cert-skills generate -n test.local -k ecdsa            # Generate self-signed
cert-skills generate-csr -n example.com                # Generate CSR

# Security checks
cert-skills check-distrusted-ca example.com            # Distrusted CA detection
cert-skills check-ocsp-must-staple example.com         # OCSP Must-Staple
cert-skills check-key-usage example.com                # Key usage compliance
cert-skills check-serial-entropy example.com           # Serial entropy
cert-skills check-policy example.com                   # Policy OID analysis
cert-skills check-name-constraints example.com         # Name constraints
cert-skills check-bundle example.com                   # Bundle completeness
cert-skills check-revocation example.com               # OCSP/CRL revocation
cert-skills check-hsts example.com                     # HSTS status
cert-skills check-caa example.com                      # CAA records
cert-skills check-sct example.com                      # SCT compliance

# Cyberspace mapping
cert-skills search-ct example.com                      # Search CT logs
cert-skills ct-enumerate example.com                   # Enumerate subdomains
cert-skills jarm example.com                           # JARM fingerprint
cert-skills ja3 example.com                            # JA3 fingerprint
cert-skills detect-ev example.com                      # EV detection
cert-skills check-wildcard example.com                 # Wildcard analysis
cert-skills get-trusted-domains example.com            # Extract domains
cert-skills verify-hostname example.com                # Hostname verification
cert-skills verify-chain example.com                   # Chain verification
cert-skills check-pfs example.com                      # PFS support
cert-skills expiry-monitor -t "a.com,b.com"            # Expiry monitoring

# Output formats
cert-skills info google.com -o json                    # JSON output
```

---

## 📚 Go SDK

### Online Analysis (requires network)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"

// Full security analysis with scoring
result, err := pkg.AnalyzeSecurity("google.com")

// Certificate security scan (18 checks)
certResult, err := pkg.ScanCertSecurity("google.com")

// TLS vulnerability scan (11 checks)
vulnResult, err := pkg.VulnerabilityScan("google.com")

// Check for distrusted CAs
distrustedResult, err := pkg.CheckDistrustedCA("google.com")

// Key usage compliance
keyUsageResult, err := pkg.CheckKeyUsageCompliance("google.com")

// Serial number entropy
entropyResult, err := pkg.CheckSerialEntropy("google.com")

// JARM/JA3 fingerprinting
jarmResult, err := pkg.JARMScan("google.com")
ja3Result, err := pkg.JA3Scan("google.com")

// CT log search
ctResult, err := pkg.CTSearch("example.com")

// Subdomain enumeration
subdomains, err := pkg.CTEnumerateSubdomains("example.com")

// HSTS check
hstsResult, err := pkg.CheckHSTS("example.com")

// Revocation check
revResult, err := pkg.CheckRevocation("example.com")
```

### Offline Analysis (no network required)

```go
// Parse a certificate from file or memory
cert, err := pkg.GetCertFromFile("cert.pem")

// Offline analysis functions work with *x509.Certificate
keyUsage := pkg.CheckKeyUsageFromCert(cert)
policy := pkg.CheckPolicyFromCert(cert)
serial := pkg.AnalyzeSerialNumberFromCert(cert)
security, err := pkg.ScanCertSecurityFromChain(cert, "example.com", nil)

// Check distrusted CAs in a chain
distrusted := pkg.CheckDistrustedCAFromCert(chain)

// Check name constraints
constraints := pkg.CheckNameConstraintsFromCert(chain)
```

### Structured Error Handling

```go
import "errors"

result, err := pkg.AnalyzeSecurity("unreachable.example.com")
if err != nil {
    if errors.Is(err, pkg.ErrConnectionFailed) {
        // Connection failure
    } else if errors.Is(err, pkg.ErrDNSResolution) {
        // DNS failure
    } else if errors.Is(err, pkg.ErrCertNotFound) {
        // No certificate found
    } else if errors.Is(err, pkg.ErrCertParseFailed) {
        // Parse error
    }
}
```

### Full SDK Reference

| Function | Description | Network |
|----------|-------------|---------|
| `AnalyzeSecurity(target)` | Full security analysis (0-100 score) | ✅ |
| `AnalyzeSecurityFromCert(cert, host)` | Offline security analysis | ❌ |
| `ScanCertSecurity(target)` | 18 cert security checks | ✅ |
| `ScanCertSecurityFromChain(cert, host, state)` | Offline cert security checks | ❌ |
| `VulnerabilityScan(target)` | 11 TLS vulnerability scans | ✅ |
| `BatchAnalyzeSecurity(targets)` | Batch security analysis | ✅ |
| `CheckDistrustedCA(target)` | Distrusted CA detection | ✅ |
| `CheckDistrustedCAFromCert(chain)` | Offline distrusted CA check | ❌ |
| `CheckKeyUsageCompliance(target)` | Key usage compliance | ✅ |
| `CheckKeyUsageFromCert(cert)` | Offline key usage check | ❌ |
| `CheckPolicyAnalysis(target)` | Policy OID analysis | ✅ |
| `CheckPolicyFromCert(cert)` | Offline policy analysis | ❌ |
| `CheckNameConstraints(target)` | Name constraints check | ✅ |
| `CheckNameConstraintsFromCert(chain)` | Offline name constraints | ❌ |
| `CheckSerialEntropy(target)` | Serial entropy analysis | ✅ |
| `AnalyzeSerialNumberFromCert(cert)` | Offline serial analysis | ❌ |
| `CheckOCSPMustStaple(target)` | OCSP Must-Staple check | ✅ |
| `CheckBundleCompleteness(target)` | Bundle completeness check | ✅ |
| `CheckRevocation(target)` | OCSP/CRL revocation check | ✅ |
| `CheckHSTS(target)` | HSTS status check | ✅ |
| `CheckCAA(target)` | CAA record check | ✅ |
| `CheckSCT(target)` | SCT compliance check | ✅ |
| `CheckPFS(target)` | PFS support check | ✅ |
| `CheckSessionResumption(target)` | Session resumption check | ✅ |
| `CheckWildcard(target)` | Wildcard analysis | ✅ |
| `DetectEV(target)` | EV certificate detection | ✅ |
| `VerifyCertChain(target)` | Chain verification | ✅ |
| `VerifyHostname(target)` | Hostname verification | ✅ |
| `CertExpiryMonitor(targets)` | Expiration monitoring | ✅ |
| `GetTrustedDomains(target)` | Domain extraction | ✅ |
| `CTSearch(domain)` | CT log domain search | ✅ |
| `CTSearchByFingerprint(fp)` | CT log fingerprint search | ✅ |
| `CTEnumerateSubdomains(domain)` | CT subdomain enumeration | ✅ |
| `JARMScan(target)` | JARM fingerprinting | ✅ |
| `JA3Scan(target)` | JA3/JA3S fingerprinting | ✅ |
| `GenerateSelfSignedCert(...)` | Certificate generation | ❌ |
| `GenerateCSR(...)` | CSR generation | ❌ |
| `DownloadCertsFromDomain(target)` | Certificate download | ✅ |
| `CompareCerts(cert1, cert2)` | Certificate comparison | ❌ |
| `GenerateFingerprints(cert)` | Fingerprint generation | ❌ |
| `ValidateCertificateFiles(cert, key)` | Cert-key validation | ❌ |
| `ValidateFingerprint(fp, type)` | Fingerprint format validation | ❌ |

---

## 🤖 AI Integration (MCP)

### One-Click Setup for Claude Code

Add this to your `.claude/settings.json`:

```json
{
  "mcpServers": {
    "certificate-skills": {
      "command": "cert-skills-mcp",
      "args": []
    }
  }
}
```

Or if you don't have the binary installed, use npx:

```json
{
  "mcpServers": {
    "certificate-skills": {
      "command": "npx",
      "args": ["-y", "certificate-skills-mcp"]
    }
  }
}
```

### MCP Transport Modes

```bash
# stdio (default, for Claude Code)
cert-skills-mcp

# HTTP (modern MCP transport)
cert-skills-mcp --transport http --addr :8080

# SSE (legacy MCP transport)
cert-skills-mcp --transport sse --addr :8080
```

### Available MCP Tools (40)

<details>
<summary>📋 Click to expand full tool list</summary>

| Tool | Description |
|------|-------------|
| `cert_info` | Certificate and connection information |
| `cert_parse` | Parse local certificate file |
| `cert_download` | Download certificate chain |
| `cert_generate` | Generate self-signed certificate |
| `cert_generate_csr` | Generate CSR |
| `cert_analyze_security` | Full security analysis with scoring |
| `cert_batch_analyze` | Batch analyze multiple domains |
| `cert_fingerprint_domain` | Generate fingerprints from domain |
| `cert_fingerprint_file` | Generate fingerprints from file |
| `cert_compare` | Compare two certificates |
| `cert_validate_files` | Validate certificate-key pair |
| `cert_validate_fingerprint` | Validate fingerprint format |
| `cert_scan_protocols` | Scan TLS protocols |
| `cert_scan_ciphers` | Scan cipher suites |
| `cert_scan_vulnerabilities` | Scan TLS vulnerabilities (11) |
| `cert_scan_cert_security` | Scan cert security (18) |
| `cert_search_ct` | Search CT logs by domain |
| `cert_search_ct_fingerprint` | Search CT logs by fingerprint |
| `cert_ct_enumerate` | Enumerate subdomains via CT |
| `cert_check_revocation` | Check OCSP/CRL revocation |
| `cert_check_hsts` | Check HSTS status |
| `cert_check_caa` | Check CAA records |
| `cert_check_sct` | Verify SCT compliance |
| `cert_verify_hostname` | Verify hostname matching |
| `cert_verify_chain` | Verify certificate chain |
| `cert_check_wildcard` | Analyze wildcard certificates |
| `cert_get_trusted_domains` | Extract trusted domains |
| `cert_detect_ev` | Detect EV certificates |
| `cert_check_pfs` | Check Perfect Forward Secrecy |
| `cert_check_session_resumption` | Check session resumption |
| `cert_expiry_monitor` | Monitor certificate expiration |
| `cert_jarm` | Generate JARM fingerprint |
| `cert_ja3` | Generate JA3/JA3S fingerprints |
| `cert_check_distrusted_ca` | Detect distrusted CAs |
| `cert_check_ocsp_must_staple` | Check OCSP Must-Staple |
| `cert_check_key_usage` | Validate key usage compliance |
| `cert_check_serial_entropy` | Analyze serial entropy |
| `cert_check_policy` | Analyze policy OIDs |
| `cert_check_name_constraints` | Check name constraints |
| `cert_check_bundle` | Check bundle completeness |

</details>

---

## 🔒 Security Checks

### Certificate Security (18 checks)

| Code | Check | Severity |
|------|-------|----------|
| CERT-001 | Weak Signature Algorithm (MD5, SHA-1) | High |
| CERT-002 | Short RSA Key (<2048 bits) | High |
| CERT-003 | Weak ECDSA Curve (<P-256) | Medium |
| CERT-004 | Missing SAN Extension | High |
| CERT-005 | Hostname Mismatch | Critical |
| CERT-006 | Excessive Validity (>398 days) | Medium |
| CERT-007 | Self-Signed Certificate | Medium |
| CERT-008 | Certificate Expired | Critical |
| CERT-009 | Certificate Expiring Soon (<30 days) | High |
| CERT-010 | CN Not in SANs | Low |
| CERT-011 | Wildcard Certificate Risk | Low |
| CERT-012 | Internal Name (.local, .internal) | High |
| CERT-013 | Untrusted Chain | High |
| CERT-014 | Distrusted CA | Critical |
| CERT-015 | OCSP Must-Staple Violation | High |
| CERT-016 | Key Usage Non-Compliance | High |
| CERT-017 | Low Serial Entropy | Medium |
| CERT-018 | Name Constraint Violation | High |

### TLS Vulnerability Scans (11 checks)

| Vulnerability | CVE | Description |
|---------------|-----|-------------|
| Heartbleed | CVE-2014-0160 | OpenSSL heartbeat information leak |
| POODLE | CVE-2014-3566 | SSLv3 protocol vulnerability |
| ROBOT | CVE-2017-17382 | Bleichenbacher oracle attack |
| CCS Injection | CVE-2014-0224 | Change Cipher Spec injection |
| FREAK | CVE-2015-0204 | Export-grade RSA downgrade |
| Logjam | CVE-2015-4000 | Export-grade DHE downgrade |
| Sweet32 | CVE-2016-2183 | 64-bit block cipher attack |
| BEAST | CVE-2011-3389 | CBC mode IV prediction |
| CRIME | CVE-2012-4929 | DEFLATE compression attack |
| Insecure Renegotiation | CVE-2009-3555 | TLS renegotiation attack |
| DROWN | CVE-2016-0800 | SSLv2 cross-protocol attack |

---

## 🎯 Skills

38 progressive-disclosure skill documents for AI agent guidance. Each skill includes:
- **TL;DR**: One-line summary
- **Capabilities**: What it can do
- **Input/Output**: Parameter and result schemas
- **Workflow**: Step-by-step usage guide
- **Cyberspace Mapping**: Applications for cyberspace mapping
- **Limitations**: Known limitations
- **Related Skills**: Cross-references

See [skills/](skills/) directory for all skill documents.

---

## 🏗️ Architecture

```
certificate-skills/
├── cmd/
│   ├── main.go              # CLI (Cobra, 39 commands)
│   └── mcp/                 # MCP server entry point
├── internal/
│   ├── display/             # Terminal UI (lipgloss)
│   └── mcpserver/           # MCP server (40 tools)
├── pkg/                     # Go SDK (importable package)
│   ├── certificate.go       # Core certificate operations
│   ├── security.go          # Security analysis & scoring
│   ├── offline.go           # Offline/from-cert SDK functions
│   ├── certerrors.go        # Structured error types
│   ├── certvulnscan.go      # 18 cert security checks
│   ├── vulnscanner.go       # 11 TLS vulnerability scans
│   ├── distrustedca.go      # Distrusted CA detection
│   ├── ocspmuststaple.go    # OCSP Must-Staple
│   ├── keyusagecompliance.go # Key usage validation
│   ├── serialentropy.go     # Serial entropy analysis
│   ├── policyanalysis.go    # Policy OID analysis
│   ├── nameconstraints.go   # Name constraint checking
│   ├── bundlecheck.go       # Bundle completeness
│   ├── cipherscanner.go     # Cipher suite scanner
│   ├── tlsscanner.go        # TLS protocol scanner
│   ├── jarm.go / ja3.go     # TLS fingerprinting
│   ├── ctlog.go             # CT log search
│   ├── revocation.go        # OCSP/CRL revocation
│   ├── hsts.go / caa.go     # HSTS & CAA
│   └── ... (30+ source files)
├── skills/                  # 38 skill documents (SKILL.md)
├── .goreleaser.yml          # Cross-platform release config
├── .github/workflows/       # CI/CD pipelines
└── Dockerfile               # Multi-arch Docker build
```

---

## 📊 Project Stats

| Metric | Count |
|--------|-------|
| CLI Commands | 39 |
| MCP Tools | 40 |
| Skills | 38 |
| Cert Security Checks | 18 |
| TLS Vulnerability Scans | 11 |
| Go SDK Functions | 50+ |
| Offline SDK Functions | 7 |
| Supported Platforms | 9 |
| Structured Error Types | 15 |

---

## 🇨🇳 简体中文

### 简介

`cert-skills` 是一个 AI 原生的证书安全工具包和 Go SDK，专为 AI Agent、安全研究员和网络空间测绘设计。支持三种使用方式：CLI 命令行、Go SDK 编程调用、MCP 服务接入 AI。

### 安装

```bash
# Linux x86_64
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_linux_x86_64.tar.gz | tar xz
sudo mv cert-skills /usr/local/bin/

# macOS Apple Silicon
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_darwin_aarch64.tar.gz | tar xz
sudo mv cert-skills /usr/local/bin/

# 从源码编译
git clone https://github.com/cyberspacesec/certificate-skills.git
cd certificate-skills && go build -o cert-skills ./cmd/
```

### CLI 使用

```bash
cert-skills analyze google.com              # 安全评分 (0-100)
cert-skills scan-cert-security example.com  # 18项证书安全检查
cert-skills scan-vulns example.com          # 11项TLS漏洞扫描
cert-skills search-ct example.com           # CT日志搜索
cert-skills jarm suspicious.com             # JARM指纹
```

### Go SDK

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"

result, err := pkg.AnalyzeSecurity("google.com")       // 在线分析
keyUsage := pkg.CheckKeyUsageFromCert(cert)             // 离线分析
distrusted := pkg.CheckDistrustedCAFromCert(chain)      // 离线检查
```

### AI 接入 (MCP)

复制以下配置到 `.claude/settings.json` 即可一键接入：

```json
{
  "mcpServers": {
    "certificate-skills": {
      "command": "cert-skills-mcp",
      "args": []
    }
  }
}
```

接入后，AI Agent 可直接调用 40 个证书安全工具，包括安全评分、漏洞扫描、CT日志搜索、JARM指纹、吊销检查等全部能力。

### 核心能力

| 类别 | 数量 | 说明 |
|------|------|------|
| CLI 命令 | 39 | 全部SDK能力通过CLI暴露 |
| MCP 工具 | 40 | AI Agent 直接调用 |
| 证书安全检查 | 18 | CERT-001 到 CERT-018 |
| TLS 漏洞扫描 | 11 | Heartbleed 到 DROWN |
| Go SDK 函数 | 50+ | 含 7 个离线分析函数 |
| 支持平台 | 9 | Linux/macOS/Windows/FreeBSD |

---

## 📄 License

[MIT License](LICENSE)
