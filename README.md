# cert-skills 🔒

**AI-Native Certificate Security Toolkit — Skills · CLI · MCP · Go SDK**

A comprehensive SSL/TLS certificate security toolkit designed for AI agents, security researchers, and cyberspace mapping. Four integration modes: **Skills** (45 executable prompts), **CLI** (51 commands), **MCP Server** (54 tools), **Go SDK** (50+ functions).

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Server-green.svg)](https://modelcontextprotocol.io)
[![Release](https://img.shields.io/github/v/release/cyberspacesec/certificate-skills?include_prereleases)](https://github.com/cyberspacesec/certificate-skills/releases/latest)

**English** | [简体中文](#-简体中文)

---

## 🤖 AI Integration — One-Click Setup

### Skills Integration (Recommended for AI Agents)

**45 executable prompt skills** — copy them into your project and your AI agent automatically knows when and how to use each tool.

```bash
# One-click install — copy all 45 skills into your project
git clone https://github.com/cyberspacesec/certificate-skills.git
cp -r certificate-skills/.claude/skills/ /your/project/.claude/skills/
```

Each skill is an **executable prompt** (not just documentation) that tells your AI agent:
- **When to Use** — trigger phrases that activate the skill
- **When NOT to Use** — boundaries to avoid wrong tool selection
- **Instructions** — step-by-step workflow with CLI and MCP tool calls
- **Anti-Patterns** — common mistakes to avoid

> 📋 **45 Skills** in [.claude/skills/](.claude/skills/) — ready for Claude Code, Cursor, and other AI agents. See [CLAUDE.md](CLAUDE.md) for the full index.

### MCP Server (For Claude Code)

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

**Best experience: Skills + MCP together.** Skills provide the prompt intelligence; MCP provides the tool execution.

### CLI (For Humans & AI Agents)

```bash
# Install binary first
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.1_linux_x86_64.tar.gz | tar xz && sudo mv cert-skills /usr/local/bin/

cert-skills analyze google.com                         # Security score (0-100)
cert-skills scan-cert-security google.com              # 18 cert checks
cert-skills scan-vulns google.com                      # 11 TLS vulnerability scans
cert-skills search-ct example.com                      # CT log search
cert-skills jarm suspicious.com -o json                # JARM fingerprint (JSON)
cert-skills detect-change google.com --save            # Certificate change detection
cert-skills map-scan --hosts example.com -o json       # Batch mapping scan
```

### Go SDK (For Programmatic Use)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"

result, err := pkg.AnalyzeSecurity("google.com")          // Online
keyUsage := pkg.CheckKeyUsageFromCert(cert)                // Offline (no network)
distrusted := pkg.CheckDistrustedCAFromCert(chain)         // Offline
```

---

## ✨ Features

### 🔍 Certificate Intelligence
Certificate info, parse, download, compare, fingerprints (SHA-256/SHA-1/MD5/SPKI), batch analysis

### 🛡️ Security Analysis
| Check | Count | Details |
|-------|-------|---------|
| Cert Security Checks | 18 | Weak signatures, short keys, hostname mismatch, distrusted CA, OCSP Must-Staple, key usage, serial entropy, name constraints... |
| TLS Vulnerability Scans | 11 | Heartbleed, POODLE, ROBOT, CCS, FREAK, Logjam, Sweet32, BEAST, CRIME, DROWN, Renegotiation |
| Security Scoring | 1 | 0-100 score with Critical/High/Medium/Good levels |

### 🔐 PKI Operations
Certificate generation (RSA/ECDSA/Ed25519), CSR generation, cert-key validation, chain verification

### 🌐 Cyberspace Mapping
CT log search, subdomain enumeration, JARM/JA3 fingerprinting, EV detection, HSTS, CAA, SCT, wildcard analysis, trusted domain extraction, PFS, session resumption, expiry monitoring, revocation check
Batch certificate collection, offline certificate parsing, de-duplication, clustering, topology, and lifecycle timeline generation

---

## 📦 Installation

### Pre-built Binaries (Recommended)

Download from [GitHub Releases](https://github.com/cyberspacesec/certificate-skills/releases/latest):

```bash
# Linux x86_64
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.1_linux_x86_64.tar.gz | tar xz && sudo mv cert-skills /usr/local/bin/

# Linux ARM64 (AWS Graviton, Raspberry Pi 5)
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.1_linux_aarch64.tar.gz | tar xz && sudo mv cert-skills /usr/local/bin/

# macOS Apple Silicon
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.1_darwin_aarch64.tar.gz | tar xz && sudo mv cert-skills /usr/local/bin/

# macOS Intel
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.1_darwin_x86_64.tar.gz | tar xz && sudo mv cert-skills /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.1_windows_x86_64.zip" -OutFile "cert-skills.zip"; Expand-Archive cert-skills.zip
```

**9 platforms available:** Linux (x86_64, ARM64, ARM v7, i386), macOS (Apple Silicon, Intel), Windows (x86_64, i386), FreeBSD (x86_64)

Two binaries per platform: **`cert-skills`** (CLI) and **`cert-skills-mcp`** (MCP server).

### Build from Source

```bash
git clone https://github.com/cyberspacesec/certificate-skills.git
cd certificate-skills
go build -trimpath -ldflags "-s -w" -o cert-skills ./cmd/       # CLI
go build -trimpath -ldflags "-s -w" -o cert-skills-mcp ./cmd/mcp/ # MCP Server
```

### Go Module

```bash
go get github.com/cyberspacesec/certificate-skills/pkg
```

---

## 🖥️ CLI Reference

```bash
# Security analysis
cert-skills analyze <domain>                    # Full security scoring (0-100)
cert-skills scan-cert-security <domain>         # 18 cert security checks
cert-skills scan-vulns <domain>                 # 11 TLS vulnerability scans
cert-skills scan-protocols <domain>             # TLS version scan
cert-skills scan-ciphers <domain>               # Cipher suite scan

# Certificate operations
cert-skills info <domain>                       # Certificate information
cert-skills info <domain1> <domain2>            # Batch info
cert-skills fingerprint <domain>                # SHA-256/SHA-1/MD5/SPKI
cert-skills compare -1 <domain1> -2 <domain2>   # Compare certificates
cert-skills download <domain>                   # Download cert chain
cert-skills parse <file.pem>                    # Parse local file
cert-skills validate -c <cert.pem> -k <key.pem> # Validate cert-key pair

# PKI operations
cert-skills generate -n test.local -k ecdsa     # Generate self-signed cert
cert-skills generate-csr -n example.com          # Generate CSR

# Security checks
cert-skills check-distrusted-ca <domain>        # Distrusted CA detection
cert-skills check-ocsp-must-staple <domain>     # OCSP Must-Staple
cert-skills check-key-usage <domain>            # Key usage compliance
cert-skills check-serial-entropy <domain>       # Serial entropy
cert-skills check-policy <domain>               # Policy OID analysis
cert-skills check-name-constraints <domain>     # Name constraints
cert-skills check-bundle <domain>               # Bundle completeness
cert-skills check-revocation <domain>           # OCSP/CRL revocation
cert-skills check-hsts <domain>                 # HSTS status
cert-skills check-caa <domain>                  # CAA records
cert-skills check-sct <domain>                  # SCT compliance

# Cyberspace mapping
cert-skills search-ct <domain>                  # Search CT logs
cert-skills ct-enumerate <domain>               # Enumerate subdomains
cert-skills map-scan --hosts a.com,b.com        # Batch collect certs
cert-skills map-parse certs/*.pem               # Offline mapping analysis
cert-skills map-timeline snapshots/*.json       # Lifecycle timeline
cert-skills jarm <domain>                       # JARM fingerprint
cert-skills ja3 <domain>                        # JA3 fingerprint
cert-skills match-fp <domain>                   # Match known fingerprints
cert-skills detect-change <domain> --save        # Certificate change detection
cert-skills detect-ev <domain>                  # EV detection
cert-skills check-wildcard <domain>             # Wildcard analysis
cert-skills get-trusted-domains <domain>        # Extract domains
cert-skills verify-hostname <domain>            # Hostname verification
cert-skills verify-chain <domain>               # Chain verification
cert-skills check-pfs <domain>                  # PFS support
cert-skills expiry-monitor -t "a.com,b.com"     # Expiry monitoring

# JSON output (for AI agents and automation)
cert-skills <command> <domain> -o json
```

---

## 📚 Go SDK

### Online Analysis (requires network)

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"

result, err := pkg.AnalyzeSecurity("google.com")           // Security score
certResult, err := pkg.ScanCertSecurity("google.com")       // 18 cert checks
vulnResult, err := pkg.VulnerabilityScan("google.com")      // 11 vuln scans
distrusted, err := pkg.CheckDistrustedCA("google.com")      // Distrusted CA
keyUsage, err := pkg.CheckKeyUsageCompliance("google.com")  // Key usage
entropy, err := pkg.CheckSerialEntropy("google.com")        // Serial entropy
jarmResult, err := pkg.JARMScan("google.com")               // JARM
ja3Result, err := pkg.JA3Scan("google.com")                 // JA3
ctResult, err := pkg.CTSearch("example.com")                // CT search
changeResult, err := pkg.DetectChange("example.com", prev)  // Change detection
hstsResult, err := pkg.CheckHSTS("example.com")             // HSTS
revResult, err := pkg.CheckRevocation("example.com")        // Revocation
```

### Offline Analysis (no network required)

```go
cert, _ := pkg.GetCertFromFile("cert.pem")

keyUsage := pkg.CheckKeyUsageFromCert(cert)                  // Key usage
policy := pkg.CheckPolicyFromCert(cert)                      // Policy OIDs
serial := pkg.AnalyzeSerialNumberFromCert(cert)               // Serial entropy
security, _ := pkg.ScanCertSecurityFromChain(cert, host, nil) // Cert security
distrusted := pkg.CheckDistrustedCAFromCert(chain)            // Distrusted CA
constraints := pkg.CheckNameConstraintsFromCert(chain)         // Name constraints
```

### Structured Error Handling

```go
import "errors"

result, err := pkg.AnalyzeSecurity("unreachable.example.com")
if errors.Is(err, pkg.ErrConnectionFailed) { /* connection failure */ }
if errors.Is(err, pkg.ErrDNSResolution) { /* DNS failure */ }
if errors.Is(err, pkg.ErrCertParseFailed) { /* parse error */ }
```

---

## 🔒 Security Checks

### Certificate Security (CERT-001 to CERT-018)

| Code | Check | Severity |
|------|-------|----------|
| CERT-001 | Weak Signature Algorithm | High |
| CERT-002 | Short RSA Key (<2048) | High |
| CERT-003 | Weak ECDSA Curve | Medium |
| CERT-004 | Missing SAN Extension | High |
| CERT-005 | Hostname Mismatch | Critical |
| CERT-006 | Excessive Validity | Medium |
| CERT-007 | Self-Signed Certificate | Medium |
| CERT-008 | Certificate Expired | Critical |
| CERT-009 | Certificate Expiring Soon | High |
| CERT-010 | CN Not in SANs | Low |
| CERT-011 | Wildcard Certificate Risk | Low |
| CERT-012 | Internal Name | High |
| CERT-013 | Untrusted Chain | High |
| CERT-014 | **Distrusted CA** | **Critical** |
| CERT-015 | **OCSP Must-Staple Violation** | **High** |
| CERT-016 | **Key Usage Non-Compliance** | **High** |
| CERT-017 | **Low Serial Entropy** | **Medium** |
| CERT-018 | **Name Constraint Violation** | **High** |

### TLS Vulnerability Scans

| Vulnerability | CVE |
|---------------|-----|
| Heartbleed | CVE-2014-0160 |
| POODLE | CVE-2014-3566 |
| ROBOT | CVE-2017-17382 |
| CCS Injection | CVE-2014-0224 |
| FREAK | CVE-2015-0204 |
| Logjam | CVE-2015-4000 |
| Sweet32 | CVE-2016-2183 |
| BEAST | CVE-2011-3389 |
| CRIME | CVE-2012-4929 |
| Insecure Renegotiation | CVE-2009-3555 |
| DROWN | CVE-2016-0800 |

---

## 🎯 Skills (45 Executable Prompts)

Each Skill is an **executable prompt** that tells your AI agent when to trigger, how to use the tool, and what to avoid:

```
Frontmatter (name + trigger description + tools/allowed-tools)
→ When to Use → When NOT to Use → Instructions → Anti-Patterns
```

Repository layout:
- [`skills/`](skills/) contains portable Anthropic-style skill packages (`SKILL.md` plus optional `references/`, `scripts/`, and `assets/`).
- Each `SKILL.md` contains Markdown instructions after frontmatter, with exactly one H1 outside fenced code blocks and at least one H2 section.
- Frontmatter uses only the supported `name`, `description`, tool metadata, and optional `compatibility` fields.
- Frontmatter keys are unique within each `SKILL.md`.
- Tool metadata fields are non-empty YAML lists using the expected portable or Claude Code tool-name format.
- Declared skill tools are referenced from the skill Markdown instructions.
- Claude Code skill prompts include required executable sections outside fenced code blocks.
- Frontmatter descriptions stay concise (100 words or fewer) and carry trigger guidance.
- Portable skills keep trigger guidance in the frontmatter description, not `When to Use` body sections.
- Portable skill reference links include a `Read when` cue so detailed material is loaded only when relevant.
- Reference files over 300 lines must include a `Contents` or `Table of Contents` heading.
- Bundled `scripts/` and `assets/` files are linked from `SKILL.md`; bundled scripts must be executable.
- Skill packages reject generated cache or backup artifacts that should not be distributed.
- Skill package content rejects high-risk shell patterns that could compromise the user's system.
- Each portable skill includes `evals/evals.json` with 2-3 test prompts using only the skill-creator eval schema fields and consecutive case ids.
- Skill eval prompts are realistic user requests, not evaluator control instructions.
- Skill `evals/` directories contain only `evals.json` and optional `files/` fixtures.
- Skill eval file fixtures, when used, live under `evals/files/`.
- Every `evals/files/` fixture is referenced by at least one eval case.
- [`.claude/skills/`](.claude/skills/) contains Claude Code-ready executable prompts with MCP `allowed-tools` metadata.
- [`evals/evals.json`](evals/evals.json) contains repository-level skill-selection smoke evals.
- [`evals/skills-structure.json`](evals/skills-structure.json) contains repository structure checks used by `make validate-skills`.
- `make validate-skills` uses [`scripts/skill_validation.py`](scripts/skill_validation.py) to enforce Anthropic-style metadata, eval, link, layout, and tool-parity constraints.
- [`scripts/package-skills.py`](scripts/package-skills.py) reuses the same validator before writing `.skill` archives.
- Generated `.skill` archives, skill eval workspaces, skill benchmark outputs, `dist/` outputs, Go test binaries, `bin/` outputs, and coverage reports are ignored and must not be tracked as source files.
- When local skill eval, benchmark, blind-comparison, or description-optimization outputs are present, validation also checks official generated-output placement and field shapes such as `eval_metadata.json`, `grading.json`, `metrics.json`, `timing.json`, `history.json`, workspace and benchmark-mode `benchmark.json`, `feedback.json`, `comparison-N.json` naming, `analysis.json`, and trigger eval sets, including nested grading, benchmark expectations, benchmark result, benchmark notes, benchmark summary stat, comparison, analysis, and A/B blind-comparison label fields.

Build portable `.skill` archives:

```bash
make package-skills
```

**Categories:** Security Analysis (6) · Certificate Operations (7) · PKI (5) · CRL (2) · Cyberspace Mapping (10) · Protocol Analysis (4) · Compliance Checks (8) · Revocation & HSTS (2) · Chain Verification (1)

See [.claude/skills/](.claude/skills/) for all skills and [CLAUDE.md](CLAUDE.md) for the full index.

---

## 📊 Project Stats

| Metric | Count |
|--------|-------|
| Skills | 45 |
| CLI Commands | 51 |
| MCP Tools | 54 |
| Cert Security Checks | 18 |
| TLS Vulnerability Scans | 11 |
| Go SDK Functions | 50+ |
| Offline SDK Functions | 7 |
| Supported Platforms | 9 |
| Structured Error Types | 15 |

---

## 🇨🇳 简体中文

### 简介

`cert-skills` 是一个 AI 原生的证书安全工具包，支持四种接入方式：**Skills**（45个可执行提示词）、**CLI**（51个命令）、**MCP 服务器**（54个工具）、**Go SDK**（50+函数）。

### 🤖 AI 一键接入

**Skills 接入（推荐）：** 45个可执行提示词技能，复制到项目即可自动识别：

```bash
# 一键安装 — 复制全部 45 个技能到你的项目
git clone https://github.com/cyberspacesec/certificate-skills.git
cp -r certificate-skills/.claude/skills/ /your/project/.claude/skills/
```

每个 Skill 是一个**可执行提示词**（不是文档），告诉 AI Agent：
- **何时使用** — 触发短语自动激活技能
- **何时不使用** — 避免选错工具的边界
- **操作指令** — 包含 CLI 和 MCP 工具调用的分步工作流
- **反模式** — 常见错误和需避免的做法

仓库结构：
- [`skills/`](skills/) 保存可移植的 Anthropic-style skill packages（`SKILL.md` 和可选 `references/`、`scripts/`、`assets/`）。
- 每个 `SKILL.md` 在 frontmatter 后包含 Markdown instructions，fenced code block 外只包含一个 H1，并至少包含一个 H2 小节。
- frontmatter 只使用受支持的 `name`、`description`、工具元数据和可选 `compatibility` 字段。
- 每个 `SKILL.md` 内的 frontmatter key 不能重复。
- 工具元数据字段必须是非空 YAML list，并使用对应的 portable 或 Claude Code 工具名格式。
- skill 声明的工具必须在该 skill 的 Markdown instructions 中被引用。
- Claude Code skill prompts 必须在 fenced code block 外包含必需的 executable sections。
- frontmatter description 保持简洁（不超过 100 words），并承载触发说明。
- 可移植 skill 将触发说明保留在 frontmatter description 中，而不是 `When to Use` 正文段落。
- 可移植 skill 的 reference 链接包含 `Read when` 提示，用于说明何时读取详细材料。
- 超过 300 行的 reference 文件必须包含 `Contents` 或 `Table of Contents` 标题。
- 打包的 `scripts/` 和 `assets/` 文件必须从 `SKILL.md` 链接；打包脚本必须可执行。
- skill package 会拒绝不应分发的生成缓存或备份产物。
- skill package 内容会拒绝可能破坏用户系统的高风险 shell 模式。
- 每个可移植 skill 都包含 `evals/evals.json`，内含 2-3 个测试提示词，只使用 skill-creator eval schema 字段，并使用连续 case id。
- skill eval prompt 使用真实用户请求风格，而不是评测器控制指令。
- skill `evals/` 目录只包含 `evals.json` 和可选的 `files/` fixture。
- skill eval 文件测试 fixture 如有使用，放在 `evals/files/` 下。
- 每个 `evals/files/` fixture 至少被一个 eval case 引用。
- [`.claude/skills/`](.claude/skills/) 保存 Claude Code 可直接复制使用的版本，包含 MCP `allowed-tools` 元数据。
- [`evals/evals.json`](evals/evals.json) 保存仓库级技能选择 smoke eval。
- [`evals/skills-structure.json`](evals/skills-structure.json) 保存仓库结构检查，由 `make validate-skills` 校验。
- `make validate-skills` 使用 [`scripts/skill_validation.py`](scripts/skill_validation.py) 校验 Anthropic-style 元数据、eval、链接、目录布局和工具元数据一致性。
- [`scripts/package-skills.py`](scripts/package-skills.py) 在写入 `.skill` archives 前复用同一套校验器。
- 生成的 `.skill` archives、skill eval workspaces、skill benchmark outputs、`dist/` 输出、Go test binaries、`bin/` 输出和 coverage reports 会被忽略，不能作为源码跟踪。
- 如果本地存在 skill eval、benchmark、blind-comparison 或 description-optimization 输出，校验还会检查官方 generated-output 位置和字段结构，例如 `eval_metadata.json`、`grading.json`、`metrics.json`、`timing.json`、`history.json`、workspace 和 benchmark-mode `benchmark.json`、`feedback.json`、`comparison-N.json` 命名、`analysis.json` 和 trigger eval sets，包括 grading、benchmark expectations、benchmark result、benchmark notes、benchmark summary stat、comparison、analysis 与 A/B blind-comparison 标签字段。

打包 portable `.skill` archives：

```bash
make package-skills
```

**MCP 接入（Claude Code）：**

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

**最佳体验：Skills + MCP 配合使用。** Skills 提供提示词智能，MCP 提供工具执行。

**Go SDK 接入：**

```go
import pkg "github.com/cyberspacesec/certificate-skills/pkg"
result, err := pkg.AnalyzeSecurity("example.com")         // 在线
keyUsage := pkg.CheckKeyUsageFromCert(cert)                // 离线
```

### 安装

```bash
# 下载预编译二进制
curl -sL https://github.com/cyberspacesec/certificate-skills/releases/latest/download/certificate-skills_0.1.1_linux_x86_64.tar.gz | tar xz && sudo mv cert-skills /usr/local/bin/

# 从源码编译
git clone https://github.com/cyberspacesec/certificate-skills.git
cd certificate-skills && go build -o cert-skills ./cmd/
```

### 核心能力

| 类别 | 数量 | 说明 |
|------|------|------|
| Skills | 45 | AI Agent 可执行提示词 |
| CLI 命令 | 51 | 全部能力通过命令行暴露 |
| MCP 工具 | 54 | AI Agent 直接调用 |
| 证书安全检查 | 18 | CERT-001 到 CERT-018 |
| TLS 漏洞扫描 | 11 | Heartbleed 到 DROWN |
| Go SDK | 50+ | 含 7 个离线分析函数 |
| 支持平台 | 9 | Linux/macOS/Windows/FreeBSD |

详见 [CLAUDE.md](CLAUDE.md) 获取完整的 Skills 索引和接入指南。

---

## 📄 License

[MIT License](LICENSE)
