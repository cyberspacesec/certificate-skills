# Certificate Hacker Claude Code Plugin 转换计划

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将当前 Go CLI 工具仓库改造为 Claude Code Plugin，提供多个 Skills，让其他 AI 安装后获得证书安全分析能力。保留原有 Go 代码作为底层引擎，通过 Skills 指导 Claude 调用 `cert-hacker` CLI 完成证书操作。

**Architecture:** 用户提问证书相关问题 → Claude 识别触发条件 → 加载对应 Skill → Skill 指导 Claude 执行 `cert-hacker` CLI 命令 → Claude 解析输出并回复用户。Plugin 作为分发单元，包含 `.claude-plugin/plugin.json` + 5 个 Skills（证书信息获取、指纹生成、安全分析、证书生成、批量检查），每个 Skill 通过 SKILL.md 定义触发条件和操作流程，底层依赖预编译的 Go 二进制文件。

**Tech Stack:** Go 1.23+ (底层 CLI), Claude Code Plugin 规范 (plugin.json + SKILL.md), Shell 脚本 (构建/安装辅助)

**Risks:**
- Go 二进制需要跨平台编译（Linux/macOS/Windows），用户系统可能不匹配 → 缓解：提供多平台构建脚本，Skill 中包含自动检测逻辑
- 用户未安装 Go 环境无法从源码编译 → 缓解：提供预编译二进制下载 + 源码编译两种方式
- Plugin 结构与现有 Go 代码目录共存，需避免冲突 → 缓解：Plugin 文件放在独立的 `.claude-plugin/` 和 `skills/` 目录，不影响 Go 项目结构

---

### Task 1: 创建 Plugin 骨架和配置文件

**Depends on:** None
**Files:**
- Create: `.claude-plugin/plugin.json`
- Create: `scripts/install.sh`
- Create: `scripts/build-all-platforms.sh`

- [ ] **Step 1: 创建 Plugin manifest — 定义 certificate-hacker 插件元数据**

```json
// .claude-plugin/plugin.json
{
  "name": "certificate-hacker",
  "version": "1.0.0",
  "description": "Certificate security toolkit plugin for Claude Code - provides SSL/TLS certificate analysis, fingerprint generation, security assessment, and certificate generation capabilities",
  "author": {
    "name": "CyberSpaceSec",
    "url": "https://github.com/cyberspacesec"
  },
  "homepage": "https://github.com/cyberspacesec/certificate-hacker",
  "repository": "https://github.com/cyberspacesec/certificate-hacker",
  "license": "MIT",
  "keywords": [
    "certificate",
    "ssl",
    "tls",
    "security",
    "fingerprint",
    "pentesting",
    "x509",
    "openssl"
  ]
}
```

- [ ] **Step 2: 创建安装脚本 — 自动构建和检测 cert-hacker 二进制**

```bash
#!/usr/bin/env bash
# scripts/install.sh
# Build and install cert-hacker binary for the current platform

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_ROOT/bin"
BINARY_NAME="cert-hacker"

echo "=== Certificate Hacker Plugin Installer ==="
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed. Please install Go 1.23+ from https://golang.org/dl/"
    echo "Alternatively, download pre-built binaries from the GitHub releases page."
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "Detected Go version: $GO_VERSION"

# Create bin directory
mkdir -p "$BIN_DIR"

# Build the binary
echo "Building cert-hacker..."
cd "$PROJECT_ROOT"
LDFLAGS="-ldflags \"-X main.version=plugin-1.0.0 -X main.commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)\""
eval "go build $LDFLAGS -o $BIN_DIR/$BINARY_NAME cmd/main.go"

if [ $? -eq 0 ]; then
    echo ""
    echo "SUCCESS: cert-hacker built successfully!"
    echo "Binary location: $BIN_DIR/$BINARY_NAME"
    echo ""
    echo "Verify installation:"
    echo "  $BIN_DIR/$BINARY_NAME --version"
else
    echo "ERROR: Build failed. Please check the error messages above."
    exit 1
fi
```

- [ ] **Step 3: 创建跨平台构建脚本 — 生成多平台二进制文件**

```bash
#!/usr/bin/env bash
# scripts/build-all-platforms.sh
# Cross-platform build for cert-hacker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_ROOT/bin"
BINARY_NAME="cert-hacker"
VERSION="${1:-plugin-1.0.0}"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS="-ldflags \"-X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE\""

mkdir -p "$BIN_DIR"

echo "=== Building cert-hacker for all platforms ==="
echo "Version: $VERSION"
echo ""

PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

for PLATFORM in "${PLATFORMS[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$PLATFORM"
    OUTPUT="$BIN_DIR/${BINARY_NAME}-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi

    echo -n "Building for $GOOS/$GOARCH... "
    cd "$PROJECT_ROOT"
    GOOS=$GOOS GOARCH=$GOARCH eval "go build $LDFLAGS -o $OUTPUT cmd/main.go" && echo "OK" || echo "FAILED"
done

echo ""
echo "Build complete. Binaries in: $BIN_DIR/"
ls -lh "$BIN_DIR/"
```

- [ ] **Step 4: 提交**
Run: `git add .claude-plugin/plugin.json scripts/install.sh scripts/build-all-platforms.sh && git commit -m "feat(plugin): add Claude Code plugin manifest and build scripts"`

---

### Task 2: 创建证书信息获取 Skill

**Depends on:** Task 1
**Files:**
- Create: `skills/certificate-info/SKILL.md`
- Create: `skills/certificate-info/references/cli-reference.md`

- [ ] **Step 1: 创建 certificate-info SKILL.md — 证书信息获取 Skill 定义**

```markdown
---
name: certificate-info
description: This skill should be used when the user asks to "check a certificate", "get certificate info", "view SSL certificate", "show TLS certificate details", "inspect certificate", "read certificate file", "parse certificate", or mentions certificate subject, issuer, validity period, SAN, or DNS names. Provides SSL/TLS certificate retrieval and parsing capabilities.
version: 1.0.0
---

# Certificate Information Skill

Retrieve and display detailed information about SSL/TLS certificates from domains or local files.

## Prerequisites

This skill requires the `cert-hacker` binary. Run the installation script first:

```bash
bash scripts/install.sh
```

Verify the binary is available:

```bash
./bin/cert-hacker --version
```

If the binary is not found, build it:

```bash
cd {{PROJECT_ROOT}} && go build -o bin/cert-hacker cmd/main.go
```

## Core Operations

### Retrieve Certificate from a Domain

Connect to a remote server and retrieve its SSL/TLS certificate information:

```bash
./bin/cert-hacker info <domain>
```

- `<domain>`: Target domain with optional port (default port 443)
- Example: `./bin/cert-hacker info google.com`
- Example: `./bin/cert-hacker info example.com:8443`

### Parse a Local Certificate File

Read and parse a PEM/DER format certificate file:

```bash
./bin/cert-hacker parse <file-path>
```

- Example: `./bin/cert-hacker parse /path/to/certificate.pem`
- Supported formats: `.pem`, `.crt`, `.cer`

### Batch Process Multiple Domains

Check certificates for multiple domains at once:

```bash
./bin/cert-hacker info domain1.com domain2.com domain3.com
```

### JSON Output

Add `--output json` flag for machine-readable output:

```bash
./bin/cert-hacker info google.com --output json
```

## Output Fields

When presenting results to the user, highlight these key fields:

| Field | Description |
|-------|-------------|
| Subject | Certificate subject (CN, O, C) |
| Issuer | Certificate issuer (CA information) |
| Valid From / Valid To | Certificate validity period |
| DNS Names | Subject Alternative Names |
| Key Usage | Digital Signature, Key Encipherment, etc. |
| Public Key Algorithm | RSA, ECDSA, etc. |
| Signature Algorithm | SHA256-RSA, etc. |
| Fingerprints | SHA-256, SHA-1, MD5, Public Key SHA-256 |

## Decision Flow

1. User mentions a domain → use `info` command
2. User provides a file path ending in `.pem`/`.crt`/`.cer` → use `parse` command
3. User provides multiple domains → use batch `info` command
4. User requests structured data → add `--output json` flag

## Additional Resources

### Reference Files

- **`references/cli-reference.md`** - Complete CLI reference for the info and parse commands
```

- [ ] **Step 2: 创建 CLI 参考文档 — 详细命令行参数和输出格式说明**

```markdown
# CLI Reference: Certificate Info Commands

## `cert-hacker info` — Retrieve Certificate Information

### Synopsis

```bash
cert-hacker info [domain:port | file] [domain2] [domain3]... [--output json|text]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| target | Yes | Domain name (with optional `:port`), or certificate file path |
| additional targets | No | Additional domains or files for batch processing |

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output, -o` | `text` | Output format: `text` (human-readable) or `json` (machine-readable) |

### Domain Format

- `google.com` — default port 443
- `google.com:8443` — custom port
- Multiple: `google.com baidu.com github.com`

### File Detection

The command auto-detects file vs domain based on extension:
- `.pem`, `.crt`, `.cer` → treated as certificate file
- Everything else → treated as domain

### JSON Output Format

```json
{
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "handshake_time": "224.944667ms",
  "peer_certificates": {
    "certificates": [
      {
        "subject": "CN=*.google.com",
        "issuer": "CN=WR2,O=Google Trust Services,C=US",
        "serial_number": "...",
        "not_before": "2025-09-08T08:34:53Z",
        "not_after": "2025-12-01T08:34:52Z",
        "dns_names": ["*.google.com", "google.com"],
        "fingerprints": {
          "sha256": "2d:8f:a1:b5:...",
          "public_key_sha256": "f3:89:91:45:..."
        }
      }
    ],
    "chain_length": 3,
    "is_valid": true
  }
}
```

## `cert-hacker parse` — Parse Certificate File

### Synopsis

```bash
cert-hacker parse <certificate-file> [--output json|text]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| file | Yes | Path to certificate file (PEM or DER format) |

### Supported Formats

- PEM (Base64-encoded, wrapped in `-----BEGIN CERTIFICATE-----`)
- DER (binary format, auto-detected)

## Batch Processing

When multiple targets are provided:

```bash
cert-hacker info google.com baidu.com github.com --output json
```

Output is an array of results, each containing:
- `target`: The domain or file path
- `ssl_info` or `cert_info`: Certificate data (if successful)
- `error`: Error message (if failed)
```

- [ ] **Step 3: 提交**
Run: `git add skills/certificate-info/SKILL.md skills/certificate-info/references/cli-reference.md && git commit -m "feat(skills): add certificate-info skill with CLI reference"`

---

### Task 3: 创建证书指纹 Skill

**Depends on:** Task 1
**Files:**
- Create: `skills/certificate-fingerprint/SKILL.md`

- [ ] **Step 1: 创建 certificate-fingerprint SKILL.md — 证书指纹生成 Skill**

```markdown
---
name: certificate-fingerprint
description: This skill should be used when the user asks to "generate certificate fingerprint", "get SSL fingerprint", "show SHA-256 fingerprint", "get public key hash", "compare certificates", "verify certificate identity", or mentions SSL pinning, certificate fingerprint, SHA-1, SHA-256, MD5 hash of a certificate. Provides certificate fingerprint generation and comparison.
version: 1.0.0
---

# Certificate Fingerprint Skill

Generate various types of certificate fingerprints for identity verification and SSL pinning.

## Prerequisites

Requires the `cert-hacker` binary. If not built yet:

```bash
cd {{PROJECT_ROOT}} && go build -o bin/cert-hacker cmd/main.go
```

## Core Operations

### Generate Fingerprints from a Domain

```bash
./bin/cert-hacker fingerprint <domain>
```

- Example: `./bin/cert-hacker fingerprint google.com`
- Connects to the domain and generates fingerprints for the leaf certificate

### Generate Fingerprints from a Certificate File

```bash
./bin/cert-hacker fingerprint <file-path>
```

- Example: `./bin/cert-hacker fingerprint /path/to/cert.pem`
- Parses the local certificate file

### JSON Output

```bash
./bin/cert-hacker fingerprint google.com --output json
```

## Fingerprint Types

| Type | Description | Use Case |
|------|-------------|----------|
| `sha256` | SHA-256 hash of the DER-encoded certificate | Primary identification, most secure |
| `sha1` | SHA-1 hash of the DER-encoded certificate | Legacy systems (deprecated) |
| `md5` | MD5 hash of the DER-encoded certificate | Legacy comparison only (insecure) |
| `public_key_sha256` | SHA-256 hash of the public key (DER) | **SSL Pinning** — survives certificate renewal |

## SSL Pinning Guidance

For SSL/TLS certificate pinning implementations, use the `public_key_sha256` fingerprint:

- It is tied to the **public key**, not the full certificate
- Survives certificate renewal (as long as the same key pair is used)
- Compatible with Android `Network Security Config`, iOS `Info.plist`, and HTTP `Public-Key-Pins` header

### Example: Presenting Fingerprints

When presenting fingerprint results, format as:

```
Certificate Fingerprints:
=========================
SHA-256             : 2d:8f:a1:b5:9a:60:f4:14:ad:1c:29:44:92:c7:8b:af...
PUBLIC_KEY_SHA256   : f3:89:91:45:af:58:8f:aa:e1:99:98:ef:47:6c:76:43...
```

Always highlight the `public_key_sha256` when the user's use case involves SSL pinning.
```

- [ ] **Step 2: 提交**
Run: `git add skills/certificate-fingerprint/SKILL.md && git commit -m "feat(skills): add certificate-fingerprint skill"`

---

### Task 4: 创建安全分析 Skill

**Depends on:** Task 1
**Files:**
- Create: `skills/certificate-analysis/SKILL.md`
- Create: `skills/certificate-analysis/references/scoring-system.md`

- [ ] **Step 1: 创建 certificate-analysis SKILL.md — SSL/TLS 安全分析 Skill**

```markdown
---
name: certificate-analysis
description: This skill should be used when the user asks to "analyze SSL security", "check TLS security", "assess certificate security", "security score", "find SSL vulnerabilities", "check certificate expiry", "audit TLS configuration", "is this certificate secure", or mentions certificate security analysis, TLS hardening, cipher suite security. Provides comprehensive SSL/TLS security analysis with scoring.
version: 1.0.0
---

# Certificate Security Analysis Skill

Perform comprehensive security analysis of SSL/TLS connections with scoring and recommendations.

## Prerequisites

Requires the `cert-hacker` binary. If not built yet:

```bash
cd {{PROJECT_ROOT}} && go build -o bin/cert-hacker cmd/main.go
```

## Core Operation

### Analyze a Domain's SSL/TLS Security

```bash
./bin/cert-hacker analyze <domain>
```

- Example: `./bin/cert-hacker analyze google.com`
- Example: `./bin/cert-hacker analyze example.com:8443`
- Connects to the target and performs full security assessment

### JSON Output

```bash
./bin/cert-hacker analyze google.com --output json
```

## Analysis Categories

The analysis covers three areas, each contributing to the overall security score:

### 1. Certificate Check

| Check | Severity | Description |
|-------|----------|-------------|
| Certificate Expired | Critical | Certificate past its validity period |
| Certificate Expiring Soon | High | Expiring within 30 days |
| Weak Signature Algorithm | High | MD5 or SHA-1 signature |
| Self-Signed Certificate | Medium | Not issued by a trusted CA |
| Missing SAN | Medium | No Subject Alternative Names |

### 2. TLS Connection Check

| Check | Severity | Description |
|-------|----------|-------------|
| Insecure TLS Version | High | TLS 1.0 or TLS 1.1 in use |
| Weak Cipher Suite | High | RC4, DES, 3DES, NULL, or EXPORT ciphers |

### 3. Expiration Check

| Status | Condition |
|--------|-----------|
| Expired | Past NotAfter date |
| Critical | ≤ 7 days until expiry |
| Warning | ≤ 30 days until expiry |
| Good | > 30 days until expiry |

## Security Scoring

The overall score ranges from 0 to 100:

| Score | Level | Interpretation |
|-------|-------|----------------|
| 90-100 | Good | No major issues |
| 70-89 | Medium | Minor improvements recommended |
| 50-69 | High | Significant security concerns |
| 0-49 | Critical | Immediate action required |

Deductions per issue severity:
- Critical: -30 points
- High: -20 points
- Medium: -10 points
- Low: -5 points

## Presenting Results

When presenting analysis results to the user:

1. **Start with the overall score and level** — give the big picture first
2. **List issues by severity** — Critical first, then High, Medium, Low
3. **For each issue**, explain: what was found, why it matters, and the recommended fix
4. **End with actionable recommendations** — prioritize by impact

### Example Output Format

```
Security Analysis: google.com
Score: 85/100 (Good)

Issues Found:
  1. ⚠️ Self-Signed Certificate [Medium]
     This certificate is not signed by a trusted CA.

Recommendations:
  1. Replace with a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.)
```

## Additional Resources

### Reference Files

- **`references/scoring-system.md`** - Detailed scoring methodology and all check criteria
```

- [ ] **Step 2: 创建评分系统参考文档 — 详细评分标准和方法论**

```markdown
# Security Scoring System Reference

## Scoring Methodology

### Base Score

All analyses start at 100 points. Points are deducted based on discovered issues.

### Issue Severity and Point Deductions

| Severity | Deduction | Color Code | Icon |
|----------|-----------|------------|------|
| Critical | -30 | Red | 💀 |
| High | -20 | Orange | 🚨 |
| Medium | -10 | Yellow | ⚠️ |
| Low | -5 | Blue | 🔸 |

### Score to Level Mapping

| Score Range | Level | Meaning |
|-------------|-------|---------|
| 90 - 100 | Good | Configuration follows best practices |
| 70 - 89 | Medium | Minor issues that should be addressed |
| 50 - 69 | High | Significant security concerns |
| 0 - 49 | Critical | Immediate remediation required |

## Certificate Checks (Detailed)

### Expiration Analysis

| Status | Days Until Expiry | Score Impact |
|--------|-------------------|--------------|
| Expired | < 0 | Critical (-30) |
| Critical | 0 - 7 | High (-20) |
| Warning | 8 - 30 | High (-20) |
| Good | > 30 | No deduction |

### Signature Algorithm Assessment

| Algorithm | Security | Score Impact |
|-----------|----------|--------------|
| SHA-256 with RSA | Secure | No deduction |
| SHA-384 with RSA | Secure | No deduction |
| ECDSA with SHA-256 | Secure | No deduction |
| SHA-1 with RSA | Weak | High (-20) |
| MD5 with RSA | Broken | High (-20) |

### Self-Signed Detection

A certificate is considered self-signed when `Subject == Issuer`.

- Impact: Medium (-10) — browsers show warnings
- Recommendation: Use Let's Encrypt or a commercial CA

## TLS Checks (Detailed)

### TLS Version Assessment

| Version | Security | Score Impact |
|---------|----------|--------------|
| TLS 1.3 | Best | No deduction |
| TLS 1.2 | Secure | No deduction |
| TLS 1.1 | Insecure | High (-20) |
| TLS 1.0 | Insecure | High (-20) |
| SSL 3.0 | Broken | Critical (-30) |

### Cipher Suite Assessment

#### Secure Cipher Suites (No Deduction)

- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256
- ECDHE-RSA-AES128-GCM-SHA256
- ECDHE-RSA-AES256-GCM-SHA384

#### Weak Cipher Suites (High Deduction)

- Any cipher containing: RC4, DES, 3DES, NULL, EXPORT
- Non-AEAD ciphers in TLS 1.2+

## Recommendations Logic

The system generates recommendations based on detected issues:

1. **Expired/Expiring** → "Renew the certificate immediately"
2. **Weak Signature** → "Upgrade to SHA-256 or higher"
3. **Self-Signed** → "Use a certificate from a trusted CA"
4. **Old TLS** → "Upgrade to TLS 1.2 or 1.3, disable older versions"
5. **Weak Cipher** → "Configure AES-GCM or ChaCha20-Poly1305"
6. **No Issues** → "Continue monitoring expiration dates"
```

- [ ] **Step 3: 提交**
Run: `git add skills/certificate-analysis/SKILL.md skills/certificate-analysis/references/scoring-system.md && git commit -m "feat(skills): add certificate-analysis skill with scoring reference"`

---

### Task 5: 创建证书生成 Skill

**Depends on:** Task 1
**Files:**
- Create: `skills/certificate-generator/SKILL.md`
- Create: `skills/certificate-generator/references/generation-options.md`

- [ ] **Step 1: 创建 certificate-generator SKILL.md — 自签名证书生成 Skill**

```markdown
---
name: certificate-generator
description: This skill should be used when the user asks to "generate a certificate", "create self-signed certificate", "make SSL certificate", "generate CA certificate", "create root CA", "generate test certificate", or mentions creating certificates for development, testing, or local HTTPS. Provides self-signed and CA certificate generation.
version: 1.0.0
---

# Certificate Generator Skill

Generate self-signed SSL/TLS certificates for development, testing, and internal use.

## Prerequisites

Requires the `cert-hacker` binary. If not built yet:

```bash
cd {{PROJECT_ROOT}} && go build -o bin/cert-hacker cmd/main.go
```

## Core Operation

### Generate a Self-Signed Certificate

```bash
./bin/cert-hacker generate --common-name <name> [options]
```

### Required Parameter

| Parameter | Description |
|-----------|-------------|
| `--common-name, -n` | Common Name (CN) for the certificate |

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--organization` | (empty) | Organization name (O) |
| `--country` | (empty) | Country code, 2 letters (C) |
| `--province` | (empty) | Province or state (ST) |
| `--locality` | (empty) | City or locality (L) |
| `--dns-names` | (empty) | Comma-separated DNS names for SAN |
| `--validity-days` | 365 | Certificate validity in days |
| `--key-size` | 2048 | RSA key size: 2048 or 4096 |
| `--is-ca` | false | Generate as CA certificate |
| `--output-cert` | `<cn>.pem` | Output certificate file path |
| `--output-key` | `<cn>-key.pem` | Output private key file path |

## Common Usage Patterns

### Local Development Certificate

```bash
./bin/cert-hacker generate --common-name localhost
```

Generates `localhost.pem` and `localhost-key.pem` in the current directory.

### Multi-Domain Certificate

```bash
./bin/cert-hacker generate \
  --common-name example.com \
  --dns-names "www.example.com,api.example.com,admin.example.com"
```

### CA Root Certificate

```bash
./bin/cert-hacker generate \
  --common-name "My Root CA" \
  --is-ca \
  --validity-days 3650 \
  --key-size 4096
```

### Custom Output Paths

```bash
./bin/cert-hacker generate \
  --common-name myserver \
  --output-cert /etc/ssl/myserver.crt \
  --output-key /etc/ssl/myserver.key
```

## Post-Generation Steps

After generating a certificate, always:

1. **Verify the generated files exist and are readable**
2. **Check fingerprints**: `./bin/cert-hacker fingerprint <cert-file>`
3. **Parse and verify**: `./bin/cert-hacker parse <cert-file>`
4. **Remind the user** this is a self-signed certificate — browsers will show warnings unless the CA cert is imported to the trust store

## Security Warning

Always include this warning when presenting generation results:

> ⚠️ **Note**: Self-signed certificates are for testing and development purposes only. They are not trusted by browsers or operating systems by default. For production use, obtain certificates from a trusted Certificate Authority (e.g., Let's Encrypt, DigiCert, Cloudflare).

## Additional Resources

### Reference Files

- **`references/generation-options.md`** - Complete parameter reference and advanced usage
```

- [ ] **Step 2: 创建生成选项参考文档 — 详细参数说明和高级用法**

```markdown
# Certificate Generation Options Reference

## All Parameters

| Parameter | Short | Type | Default | Description |
|-----------|-------|------|---------|-------------|
| `--common-name` | `-n` | string | (required) | Common Name (CN) field |
| `--organization` | | string | "" | Organization (O) field |
| `--country` | | string | "" | Country code (C), 2 letters |
| `--province` | | string | "" | State/Province (ST) |
| `--locality` | | string | "" | City/Locality (L) |
| `--dns-names` | | string | "" | Comma-separated SAN DNS names |
| `--validity-days` | | int | 365 | Certificate validity period in days |
| `--key-size` | | int | 2048 | RSA key size in bits (2048 or 4096) |
| `--is-ca` | | bool | false | Generate as Certificate Authority |
| `--output-cert` | | string | `<cn>.pem` | Certificate output file path |
| `--output-key` | | string | `<cn>-key.pem` | Private key output file path |

## Key Size Selection

| Key Size | Security Level | Performance | Recommended Use |
|----------|---------------|-------------|-----------------|
| 2048-bit | Standard | Fast | General purpose, most web servers |
| 4096-bit | High | Slower | CA certificates, high-security needs |

## Validity Period Recommendations

| Use Case | Recommended Period |
|----------|--------------------|
| Local development | 365 days |
| Internal services | 365-730 days |
| CA root certificate | 3650 days (10 years) |
| Short-lived testing | 30-90 days |

## Output Files

### Certificate File Format

PEM format with header:
```
-----BEGIN CERTIFICATE-----
<Base64-encoded DER>
-----END CERTIFICATE-----
```

### Private Key File Format

PKCS#8 PEM format with header:
```
-----BEGIN PRIVATE KEY-----
<Base64-encoded DER>
-----END PRIVATE KEY-----
```

## Certificate Extensions

Generated certificates include these extensions:

- **Basic Constraints**: `CA:TRUE` (if `--is-ca`) or `CA:FALSE`
- **Key Usage**: `Digital Signature, Key Encipherment` (leaf) or adds `Certificate Sign` (CA)
- **Extended Key Usage**: `Server Authentication`
- **Subject Alternative Names**: All DNS names specified, plus the CN if no DNS names given
```

- [ ] **Step 3: 提交**
Run: `git add skills/certificate-generator/SKILL.md skills/certificate-generator/references/generation-options.md && git commit -m "feat(skills): add certificate-generator skill with options reference"`

---

### Task 6: 创建 Plugin README 和安装说明

**Depends on:** Task 1, Task 2, Task 3, Task 4, Task 5
**Files:**
- Create: `PLUGIN_README.md`
- Modify: `README.md:1-10` (添加 Plugin 安装说明入口)

- [ ] **Step 1: 创建 PLUGIN_README.md — Plugin 安装和使用说明**

```markdown
# Certificate Hacker — Claude Code Plugin

🔒 A Claude Code plugin providing SSL/TLS certificate security analysis capabilities.

## What This Plugin Provides

This plugin adds 5 specialized skills to Claude Code:

| Skill | Description | Trigger Examples |
|-------|-------------|------------------|
| `certificate-info` | Retrieve and display certificate information | "check SSL cert for google.com" |
| `certificate-fingerprint` | Generate certificate fingerprints for SSL pinning | "get SHA-256 fingerprint" |
| `certificate-analysis` | Comprehensive security analysis with scoring | "analyze TLS security of example.com" |
| `certificate-generator` | Generate self-signed and CA certificates | "create a test certificate for localhost" |

## Installation

### Option 1: Install from Marketplace

```bash
# Add this plugin's marketplace
/plugin marketplace add cyberspacesec/certificate-hacker

# Install the plugin
/plugin install certificate-hacker@certificate-hacker

# Enable the plugin
/plugin enable certificate-hacker@certificate-hacker
```

### Option 2: Install from Local Directory

```bash
# Clone the repository
git clone https://github.com/cyberspacesec/certificate-hacker.git
cd certificate-hacker

# Build the cert-hacker binary
bash scripts/install.sh

# Test with Claude Code
claude --plugin-dir .
```

### Option 3: Add to Project Settings

Add to your project's `.claude/settings.json`:

```json
{
  "enabledPlugins": {
    "certificate-hacker@certificate-hacker": true
  },
  "extraKnownMarketplaces": {
    "certificate-hacker": {
      "source": {
        "source": "git",
        "url": "https://github.com/cyberspacesec/certificate-hacker.git"
      }
    }
  }
}
```

## Prerequisites

- **Go 1.23+** (for building the binary from source)
- **OR** download pre-built binaries from [GitHub Releases](https://github.com/cyberspacesec/certificate-hacker/releases)

## Usage Examples

After installation, simply ask Claude in natural language:

```
# Check a website's certificate
"Check the SSL certificate for google.com"

# Security analysis
"Analyze the TLS security of my-website.com"

# Generate a test certificate
"Generate a self-signed certificate for localhost"

# Get fingerprints for SSL pinning
"Get the public key fingerprint of api.example.com for SSL pinning"
```

## Plugin Structure

```
certificate-hacker/
├── .claude-plugin/
│   └── plugin.json          # Plugin manifest
├── skills/
│   ├── certificate-info/    # Certificate retrieval and parsing
│   ├── certificate-fingerprint/  # Fingerprint generation
│   ├── certificate-analysis/     # Security analysis and scoring
│   └── certificate-generator/    # Certificate generation
├── cmd/                     # Go CLI source code
├── pkg/                     # Go library packages
├── scripts/                 # Build and install scripts
└── bin/                     # Compiled binary (after build)
```

## Security Disclaimer

⚠️ This tool is intended for **legitimate security research and testing** only. Users are responsible for ensuring compliance with applicable laws and regulations.

## License

MIT License — see [LICENSE](LICENSE) for details.
```

- [ ] **Step 2: 修改 README.md 添加 Plugin 说明入口 — 在文件开头添加 Plugin 安装引导**
文件: `README.md:1-10`（在标题之后添加 Plugin 说明区块）

```markdown
# 证书安全工具 (Certificate Hacker)

🔒 一个功能完整的证书安全工具包，支持证书获取、分析、生成和安全测试功能。

> **🤖 Claude Code Plugin**: 本项目同时可作为 Claude Code 插件使用，为 AI 提供证书安全分析能力。
> 详见 [PLUGIN_README.md](PLUGIN_README.md) 了解如何安装为 Claude Code 技能插件。
```

- [ ] **Step 3: 提交**
Run: `git add PLUGIN_README.md README.md && git commit -m "docs: add plugin README and update main README with plugin section"`

---

### Task 7: 更新 .gitignore 并验证整体结构

**Depends on:** Task 6
**Files:**
- Modify: `.gitignore` (添加 Plugin 相关忽略规则)
- Test: 验证目录结构完整性

- [ ] **Step 1: 更新 .gitignore — 添加 Plugin 构建产物忽略规则**
文件: `.gitignore`

在现有 `.gitignore` 末尾追加以下内容：

```text

# Plugin build artifacts
bin/
*.exe

# OS files
.DS_Store
Thumbs.db
```

- [ ] **Step 2: 验证 Plugin 目录结构完整性**
Run: `find . -not -path './.git/*' -not -path './.git' | sort`
Expected:
  - Output contains: `.claude-plugin/plugin.json`
  - Output contains: `skills/certificate-info/SKILL.md`
  - Output contains: `skills/certificate-fingerprint/SKILL.md`
  - Output contains: `skills/certificate-analysis/SKILL.md`
  - Output contains: `skills/certificate-generator/SKILL.md`
  - Output contains: `scripts/install.sh`
  - Output contains: `scripts/build-all-platforms.sh`
  - Output contains: `PLUGIN_README.md`
  - Output contains: `cmd/main.go`
  - Output contains: `pkg/certificate.go`

- [ ] **Step 3: 验证 Go 项目仍然可以编译**
Run: `cd /home/cc11001100/github/cyberspacesec/certificate-hacker && go build -o /tmp/cert-hacker-test cmd/main.go && echo "BUILD OK"`
Expected:
  - Exit code: 0
  - Output contains: "BUILD OK"

- [ ] **Step 4: 清理测试产物并提交**
Run: `rm -f /tmp/cert-hacker-test && git add .gitignore && git commit -m "chore: update .gitignore for plugin build artifacts"`

---

## 最终项目结构

```
certificate-hacker/
├── .claude-plugin/
│   └── plugin.json                              # Plugin manifest
├── .gitignore
├── Makefile
├── PLUGIN_README.md                             # Plugin 安装说明
├── README.md                                    # 项目说明 (含 Plugin 入口)
├── cmd/
│   └── main.go                                  # Go CLI 入口
├── docs/
│   └── todo.md
├── go.mod
├── go.sum
├── pkg/
│   ├── certificate.go                           # 证书获取和解析
│   ├── fingerprint.go                           # 指纹生成
│   ├── generator.go                             # 证书生成
│   └── security.go                              # 安全分析
├── scripts/
│   ├── install.sh                               # 构建安装脚本
│   └── build-all-platforms.sh                   # 跨平台构建
└── skills/
    ├── certificate-analysis/
    │   ├── SKILL.md                             # 安全分析 Skill
    │   └── references/
    │       └── scoring-system.md                # 评分系统参考
    ├── certificate-fingerprint/
    │   └── SKILL.md                             # 指纹生成 Skill
    ├── certificate-generator/
    │   ├── SKILL.md                             # 证书生成 Skill
    │   └── references/
    │       └── generation-options.md            # 生成参数参考
    └── certificate-info/
        ├── SKILL.md                             # 证书信息 Skill
        └── references/
            └── cli-reference.md                 # CLI 参考文档
```
