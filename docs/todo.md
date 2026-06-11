# 证书安全工具开发清单

## 🎯 开发目标
构建一个功能完整的证书安全工具，支持证书获取、分析、生成和安全测试功能。

## 📋 开发任务清单

### 阶段一：基础架构 (优先级: 🔴 高) ✅

- [x] **1.1 项目结构完善**
  - [x] 创建 `cmd/` 目录和主程序入口
  - [x] 设计命令行接口结构 (使用cobra库)
  - [ ] 添加配置文件支持
  - [ ] 创建基础的日志系统

- [x] **1.2 依赖管理**
  - [x] 添加必要的Go依赖包
  - [x] 创建Makefile构建脚本
  - [x] 添加版本信息管理

### 阶段二：核心证书功能 (优先级: 🔴 高) ✅

- [x] **2.1 证书获取模块**
  - [x] 实现从URL获取证书
  - [x] 支持从文件读取证书
  - [x] 支持证书链获取
  - [x] 添加超时和重试机制

- [x] **2.2 证书解析模块**
  - [x] 证书基本信息解析 (主题、颁发者、有效期等)
  - [x] 证书扩展信息解析 (SAN、密钥用途等)
  - [x] 证书链验证 (x509.Verify 真实验证)
  - [x] 支持多种证书格式 (PEM、DER，自动检测)

- [x] **2.3 证书信息输出**
  - [x] 格式化文本输出
  - [x] JSON格式输出
  - [ ] CSV格式输出 (批量处理)

### 阶段三：证书分析功能 (优先级: 🟡 中)

- [x] **3.1 SSL/TLS连接分析**
  - [x] SSL握手过程分析
  - [x] 支持的TLS协议版本检测 (scan-protocols 命令)
  - [x] 加密套件枚举和分析 (scan-ciphers 命令)
  - [x] 证书链完整性检查 (x509.Verify)

- [x] **3.2 证书安全检查**
  - [x] 证书过期时间检查
  - [x] 弱密钥检测 (RSA密钥长度、椭圆曲线参数)
  - [x] 签名算法安全性检查
  - [x] OCSP Stapling 检测
  - [x] HSTS 头检测
  - [ ] 证书透明度日志查询

- [x] **3.3 证书指纹生成** ✅
  - [x] SHA-1指纹生成
  - [x] SHA-256指纹生成
  - [x] MD5指纹生成
  - [x] 公钥指纹生成 (用于SSL Pinning)

### 阶段四：证书生成功能 (优先级: 🟡 中)

- [x] **4.1 自签名证书生成**
  - [x] RSA密钥对生成 (2048/4096)
  - [x] ECDSA密钥对生成 (P-256/P-384/P-521)
  - [x] Ed25519密钥对生成
  - [x] 自定义证书主题信息
  - [x] 添加证书扩展 (SAN、密钥用途等)
  - [x] CSR生成 (generate-csr 命令)

- [ ] **4.2 CA证书管理**
  - [x] 根CA证书生成 (--is-ca)
  - [ ] 中间CA证书生成
  - [ ] 使用CA签发终端证书
  - [ ] CRL (证书吊销列表) 生成

### 阶段五：安全测试工具 (优先级: 🟢 低)

⚠️ **注意**: 以下功能仅用于合法的安全测试和研究，使用前请确保合规性

- [ ] **5.1 证书克隆功能**
  - [ ] 复制目标证书的主题信息
  - [ ] 生成相似但不同的证书
  - [ ] 支持域名变种生成

- [ ] **5.2 SSL漏洞检测**
  - [ ] Heartbleed漏洞检测
  - [ ] POODLE攻击检测
  - [ ] BEAST攻击检测
  - [ ] CRIME/BREACH攻击检测

- [ ] **5.3 降级攻击工具**
  - [ ] SSL Strip攻击模拟
  - [x] TLS版本降级测试 (scan-protocols)
  - [x] 加密套件降级测试 (scan-ciphers)

### 阶段六：系统集成 (优先级: 🟡 中)

- [ ] **6.1 系统证书存储**
  - [ ] Windows证书存储读取
  - [ ] macOS钥匙串访问
  - [ ] Linux系统证书目录扫描
  - [ ] 可疑根证书检测

- [x] **6.2 批量处理功能**
  - [x] 批量域名证书检查 (batch-analyze 命令)
  - [x] 证书过期批量监控
  - [ ] 结果导出和报告生成

### 阶段七：完善和优化 (优先级: 🟢 低)

- [x] **7.1 测试和文档**
  - [x] 单元测试覆盖 (24 tests)
  - [ ] 集成测试
  - [ ] 性能基准测试
  - [x] MCP工具文档
  - [x] 使用示例和教程

- [ ] **7.2 发布准备**
  - [ ] 交叉编译支持
  - [ ] Docker容器化
  - [ ] GitHub Actions CI/CD
  - [ ] 版本发布自动化

## 🛠️ 技术栈

- **语言**: Go 1.23+
- **CLI框架**: cobra
- **加密库**: crypto/x509, crypto/tls
- **MCP**: mark3labs/mcp-go
- **网络库**: net/http
- **测试框架**: testing
- **构建工具**: Make

## 🚀 CLI 命令一览

| 命令 | 描述 | 示例 |
|------|------|------|
| `info` | 获取证书信息 | `cert-hacker info google.com` |
| `download` | 下载证书链 | `cert-hacker download google.com` |
| `parse` | 解析证书文件 | `cert-hacker parse cert.pem` |
| `generate` | 生成自签名证书 | `cert-hacker generate --common-name localhost --key-type ecdsa` |
| `generate-csr` | 生成CSR | `cert-hacker generate-csr --common-name example.com` |
| `analyze` | 安全分析 | `cert-hacker analyze google.com` |
| `batch-analyze` | 批量安全分析 | `cert-hacker batch-analyze --targets google.com,github.com` |
| `fingerprint` | 生成指纹 | `cert-hacker fingerprint google.com` |
| `compare` | 比较两个证书 | `cert-hacker compare --target1 google.com --target2 github.com` |
| `validate` | 验证证书和密钥 | `cert-hacker validate --cert cert.pem --key key.pem` |
| `validate-fingerprint` | 验证指纹格式 | `cert-hacker validate-fingerprint --fingerprint ... --hash-type sha256` |
| `scan-protocols` | 扫描TLS版本 | `cert-hacker scan-protocols google.com` |
| `scan-ciphers` | 扫描密码套件 | `cert-hacker scan-ciphers google.com` |

## 🔌 MCP 工具一览 (15 tools)

| 工具 | 描述 |
|------|------|
| `cert_info` | 获取域名证书信息 |
| `cert_parse` | 解析本地证书文件 |
| `cert_analyze_security` | 综合安全分析 |
| `cert_download` | 下载证书链 |
| `cert_fingerprint_domain` | 域名证书指纹 |
| `cert_fingerprint_file` | 文件证书指纹 |
| `cert_generate` | 生成自签名证书 |
| `cert_generate_csr` | 生成CSR |
| `cert_validate_files` | 验证证书和密钥匹配 |
| `cert_validate_fingerprint` | 验证指纹格式 |
| `cert_compare` | 比较两个证书 |
| `cert_batch_analyze` | 批量安全分析 |
| `cert_scan_protocols` | TLS协议版本扫描 |
| `cert_scan_ciphers` | 密码套件扫描 |
| `cert_check_hsts` | HSTS检测 |

---

## 📊 项目当前状态 (更新时间: 2026-06-11)

### ✅ 已完成功能
1. **基础架构**: 完整的Go项目结构，CLI界面，MCP服务器 (stdio/SSE/Streamable HTTP)
2. **证书获取**: 从域名和文件获取证书，支持证书链，DER自动检测
3. **证书解析**: 完整的证书信息解析 + KeySize + HTTP/2检测 + OCSP Stapling
4. **证书指纹**: SHA1/SHA256/MD5/PublicKey SHA256 指纹生成
5. **证书生成**: RSA/ECDSA/Ed25519 自签名证书 + CSR生成
6. **证书验证**: 证书+密钥匹配验证，指纹格式验证
7. **安全分析**: 综合安全评分(0-100)，证书/TLS/过期检查，OCSP/HSTS检测
8. **TLS扫描**: 协议版本探测(TLS 1.0-1.3)，密码套件枚举(安全/弱)
9. **批量处理**: 批量安全分析，证书比较(域名/文件)
10. **输出格式**: 文本和JSON两种输出格式
11. **13个CLI命令**: info/download/parse/generate/generate-csr/analyze/batch-analyze/fingerprint/compare/validate/validate-fingerprint/scan-protocols/scan-ciphers
12. **15个MCP工具**: 完整的MCP工具集，支持Claude Code等AI客户端

### 🎯 下一阶段重点
1. **CA证书管理**: 中间CA生成，CA签发终端证书
2. **证书透明度日志**: CT log查询
3. **CSV输出**: 批量结果CSV导出
4. **配置文件**: viper配置支持
5. **SSL漏洞检测**: Heartbleed/POODLE/BEAST检测
6. **集成测试**: 端到端测试覆盖
7. **交叉编译 + CI/CD**: 多平台构建

### 📈 完成度评估
- **基础框架**: 100% ✅
- **核心功能**: 95% ✅
- **分析功能**: 85% ✅
- **生成功能**: 80% ✅
- **安全功能**: 40% 🚧
- **文档测试**: 50% 🚧

**总体完成度: 约 75%**

---

> **提示**: 每完成一个功能模块，记得在此文件中标记 ✅ 完成状态
