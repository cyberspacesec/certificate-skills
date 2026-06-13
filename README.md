# cert-hacker 🔒

**Certificate Security Toolkit for Cyberspace Mapping**

A comprehensive SSL/TLS certificate security toolkit and SDK for Go — designed for security researchers, system administrators, penetration testers, and cyberspace mapping operations.

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Server-green.svg)](https://modelcontextprotocol.io)

> **🤖 MCP Server**: This project runs as an MCP (Model Context Protocol) server, providing 40 certificate security tools for AI agents like Claude Code.

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [CLI Usage](#-cli-usage)
- [Go SDK](#-go-sdk)
- [MCP Server](#-mcp-server)
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
| Security Scoring | 0-100 security score with Critical/High/Medium/Good levels |
| 18 Cert Security Checks | From weak signatures to name constraints (CERT-001 to CERT-018) |
| 11 TLS Vulnerability Scans | Heartbleed, POODLE, ROBOT, CCS, FREAK, Logjam, Sweet32, BEAST, CRIME, DROWN, Renegotiation |
| Distrusted CA Detection | DigiNotar, WoSign, StartCom, Symantec, CNNIC, TrustCor, DarkMatter |
| OCSP Must-Staple | RFC 7633 compliance — Must-Staple without staple = hard-fail |
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
| CT Log Search | Search Certificate Transparency logs by domain |
| CT Fingerprint Search | Search CT logs by certificate fingerprint |
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

### 🎨 Terminal UI
- Cyberpunk-styled terminal output with lipgloss (neon green + cyan)
- JSON output mode for machine-readable results
- ASCII art banner
- Colored severity badges (💀🚨⚠️✅)
- Visual score bars (████████░░░░ 80/100)

---

## 📦 Installation

### Download Pre-built Binaries (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/cyberspacesec/certificate-skills/releases/latest):

```bash
# Linux x86_64
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_linux_x86_64.tar.gz | tar xz
sudo mv cert-skills /usr/local/bin/

# Linux ARM64 (Apple Silicon Linux, AWS Graviton, etc.)
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_linux_aarch64.tar.gz | tar xz
sudo mv cert-skills /usr/local/bin/

# macOS (Apple Silicon)
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_darwin_aarch64.tar.gz | tar xz
sudo mv cert-skills /usr/local/bin/

# macOS (Intel)
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_darwin_x86_64.tar.gz | tar xz
sudo mv cert-skills /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.0_windows_x86_64.zip" -OutFile "cert-skills.zip"
Expand-Archive cert-skills.zip
```

### Available Platforms

| OS | Architecture | Binary |
|----|-------------|--------|
| Linux | x86_64 / amd64 | `certificate-skills_*_linux_x86_64.tar.gz` |
| Linux | ARM64 / aarch64 | `certificate-skills_*_linux_aarch64.tar.gz` |
| Linux | ARM (v7) | `certificate-skills_*_linux_arm.tar.gz` |
| Linux | i386 | `certificate-skills_*_linux_i386.tar.gz` |
| macOS | Apple Silicon (aarch64) | `certificate-skills_*_darwin_aarch64.tar.gz` |
| macOS | Intel (x86_64) | `certificate-skills_*_darwin_x86_64.tar.gz` |
| Windows | x86_64 | `certificate-skills_*_windows_x86_64.zip` |
| Windows | i386 | `certificate-skills_*_windows_i386.zip` |
| FreeBSD | x86_64 | `certificate-skills_*_freebsd_x86_64.tar.gz` |

Two binaries are provided for each platform:
- **`cert-skills`** — CLI tool (39 commands)
- **`cert-skills-mcp`** — MCP server for AI agents (40 tools)

### Build from Source

```bash
# Requires Go 1.23+
git clone https://github.com/cyberspacesec/certificate-skills.git
cd certificate-skills
go build -trimpath -ldflags "-s -w" -o cert-skills ./cmd/
go build -trimpath -ldflags "-s -w" -o cert-skills-mcp ./cmd/mcp/
```

### Install MCP Server for Claude Code

Add to your `.claude/settings.json`:

```json
{
  "mcpServers": {
    "certificate-skills": {
      "command": "/path/to/cert-skills-mcp"
    }
  }
}
```

Or use with stdio transport (default):
```bash
cert-skills-mcp --transport stdio
```

---

## 🖥️ CLI Usage

```bash
# Certificate information
cert-hacker info google.com
cert-hacker info google.com baidu.com github.com     # Batch
cert-hacker info cert.pem                              # Local file

# Security analysis
cert-hacker analyze google.com                         # Full security scoring
cert-hacker scan-cert-security google.com              # 18 cert security checks
cert-hacker scan-vulns google.com                      # 11 TLS vulnerability scans

# Certificate fingerprinting
cert-hacker fingerprint google.com                     # SHA-256, SHA-1, MD5, SPKI
cert-hacker fingerprint cert.pem                       # From file

# Certificate generation
cert-hacker generate -n test.local -k ecdsa            # ECDSA self-signed
cert-hacker generate -n test.local --is-ca             # CA certificate
cert-hacker generate-csr -n example.com                # CSR for CA submission

# Certificate comparison
cert-hacker compare -1 google.com -2 baidu.com

# CT log searches
cert-hacker search-ct example.com                      # Search by domain
cert-hacker ct-enumerate example.com                   # Enumerate subdomains

# Security checks
cert-hacker check-distrusted-ca example.com            # Distrusted CA detection
cert-hacker check-ocsp-must-staple example.com         # OCSP Must-Staple
cert-hacker check-key-usage example.com                # Key usage compliance
cert-hacker check-serial-entropy example.com           # Serial entropy
cert-hacker check-policy example.com                   # Policy OID analysis
cert-hacker check-name-constraints example.com         # Name constraints
cert-hacker check-bundle example.com                   # Bundle completeness

# TLS scanning
cert-hacker scan-protocols example.com                 # TLS version scan
cert-hacker scan-ciphers example.com                   # Cipher suite scan
cert-hacker jarm example.com                           # JARM fingerprint
cert-hacker ja3 example.com                            # JA3 fingerprint

# Other checks
cert-hacker check-revocation example.com               # OCSP/CRL revocation
cert-hacker check-hsts example.com                     # HSTS status
cert-hacker check-caa example.com                      # CAA records
cert-hacker check-sct example.com                      # SCT compliance
cert-hacker detect-ev example.com                      # EV detection
cert-hacker check-wildcard example.com                 # Wildcard analysis
cert-hacker verify-hostname example.com                # Hostname verification
cert-hacker verify-chain example.com                   # Chain verification
cert-hacker check-pfs example.com                      # Perfect Forward Secrecy
cert-hacker expiry-monitor -t "a.com,b.com"            # Expiry monitoring

# Output formats
cert-hacker info google.com -o json                    # JSON output
cert-hacker analyze google.com -o json                 # Machine-readable
```

---

## 📚 Go SDK

### Online Analysis (requires network)

```go
import pkg "github.com/cyberspacesec/certificate-hacker/pkg"

// Full security analysis with scoring
result, err := pkg.AnalyzeSecurity("google.com")

// Certificate security scan (18 checks)
certResult, err := pkg.ScanCertSecurity("google.com")

// TLS vulnerability scan (11 checks)
vulnResult, err := pkg.ScanVulnerabilities("google.com")

// Check for distrusted CAs
distrustedResult, err := pkg.CheckDistrustedCA("google.com")

// Key usage compliance
keyUsageResult, err := pkg.CheckKeyUsageCompliance("google.com")

// Serial number entropy
entropyResult, err := pkg.CheckSerialEntropy("google.com")
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
        // Handle connection failure
    } else if errors.Is(err, pkg.ErrDNSResolution) {
        // Handle DNS failure
    } else if errors.Is(err, pkg.ErrCertNotFound) {
        // Handle no certificate
    }
}
```

---

## 🤖 MCP Server

Run as an MCP server for AI agents:

```bash
# Build and run
go build -o cert-hacker-mcp ./cmd/mcp/
./cert-hacker-mcp

# Or use with Claude Code
# Add to .claude/settings.json:
{
  "mcpServers": {
    "certificate-hacker": {
      "command": "/path/to/cert-hacker-mcp"
    }
  }
}
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
| `cert_generate_csr` | Generate Certificate Signing Request |
| `cert_analyze_security` | Full security analysis with scoring |
| `cert_batch_analyze` | Batch analyze multiple domains |
| `cert_fingerprint_domain` | Generate fingerprints from domain |
| `cert_fingerprint_file` | Generate fingerprints from file |
| `cert_compare` | Compare two certificates |
| `cert_validate_files` | Validate certificate-key pair |
| `cert_validate_fingerprint` | Validate fingerprint format |
| `cert_scan_protocols` | Scan supported TLS protocols |
| `cert_scan_ciphers` | Scan supported cipher suites |
| `cert_scan_vulnerabilities` | Scan TLS vulnerabilities (11) |
| `cert_scan_cert_security` | Scan certificate security (18) |
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
| CERT-014 | **Distrusted CA** (DigiNotar, WoSign, etc.) | **Critical** |
| CERT-015 | **OCSP Must-Staple Violation** | **High** |
| CERT-016 | **Key Usage Non-Compliance** | **High** |
| CERT-017 | **Low Serial Entropy** | **Medium** |
| CERT-018 | **Name Constraint Violation** | **High** |

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
certificate-hacker/
├── cmd/
│   ├── main.go              # CLI entry point (Cobra-based)
│   └── mcp/                 # MCP server entry point
├── internal/
│   ├── display/             # Terminal UI styling (lipgloss)
│   └── mcpserver/           # MCP server implementation
│       ├── tools.go         # 40 MCP tool definitions
│       └── handlers.go      # MCP request handlers
├── pkg/                     # Public SDK (importable Go package)
│   ├── certificate.go       # Core certificate operations
│   ├── security.go          # Security analysis & scoring
│   ├── certvulnscan.go      # 18 cert security checks
│   ├── vulnscanner.go       # 11 TLS vulnerability scans
│   ├── offline.go           # Offline/from-cert analysis functions
│   ├── certerrors.go        # Structured error types
│   ├── distrustedca.go      # Distrusted CA detection
│   ├── ocspmuststaple.go    # OCSP Must-Staple check
│   ├── keyusagecompliance.go # Key usage validation
│   ├── serialentropy.go     # Serial entropy analysis
│   ├── policyanalysis.go    # Policy OID analysis
│   ├── nameconstraints.go   # Name constraint checking
│   ├── bundlecheck.go       # Bundle completeness
│   ├── cipherscanner.go     # Cipher suite scanner
│   ├── tlsscanner.go        # TLS protocol scanner
│   ├── jarm.go              # JARM fingerprinting
│   ├── ja3.go               # JA3/JA3S fingerprinting
│   ├── ctlog.go             # CT log search
│   ├── revocation.go        # OCSP/CRL revocation
│   ├── hsts.go              # HSTS checking
│   ├── caa.go               # CAA checking
│   ├── sct.go               # SCT verification
│   ├── evcert.go            # EV detection
│   ├── chainverify.go       # Chain verification
│   ├── hostnameverify.go    # Hostname verification
│   ├── pfs.go               # PFS checking
│   ├── sessionresumption.go # Session resumption
│   ├── expirycheck.go       # Expiry monitoring
│   ├── generator.go         # Certificate generation
│   ├── fingerprint.go       # Fingerprint generation
│   ├── comparator.go        # Certificate comparison
│   ├── downloader.go        # Certificate download
│   ├── wildcard.go          # Wildcard analysis
│   └── generator_test.go    # Unit tests
├── skills/                  # 38 skill documents (SKILL.md)
└── go.mod
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
| Go Package Functions | 50+ |
| Offline SDK Functions | 7 |

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
