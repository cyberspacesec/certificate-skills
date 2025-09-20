# 证书安全工具 (Certificate Hacker)

🔒 一个功能完整的证书安全工具包，支持证书获取、分析、生成和安全测试功能。

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# 一、简介

`cert-hacker` 是一个专为安全研究人员、系统管理员和渗透测试人员设计的证书安全工具包。它提供了全面的SSL/TLS证书操作功能，包括证书获取、解析、分析、生成和安全测试等。

# 二、功能特性

## ✅ 已实现功能

### 🔍 证书信息获取和解析
- ✅ 从远程域名获取SSL/TLS证书
- ✅ 从本地文件解析证书 (PEM/DER格式)
- ✅ 完整的证书信息解析 (主题、颁发者、有效期等)
- ✅ 证书链解析和显示
- ✅ 支持Subject Alternative Names (SAN)
- ✅ 密钥用途和扩展密钥用途解析

### 🔐 证书指纹生成
- ✅ MD5、SHA-1、SHA-256指纹生成
- ✅ 公钥指纹生成 (用于SSL Pinning)
- ✅ 多种输出格式 (文本和JSON)

### 🌐 SSL/TLS连接分析
- ✅ TLS版本检测
- ✅ 加密套件识别
- ✅ 握手时间测量
- ✅ 证书链验证

## 🚧 开发中功能
- 🔄 SSL/TLS安全分析 (协议支持、加密套件评估)
- 🔄 证书生成功能 (自签名证书、CA证书)
- 🔄 证书过期监控
- 🔄 批量处理和报告生成

## 📋 计划功能
- 📅 证书透明度日志查询
- 📅 SSL漏洞检测
- 📅 系统证书存储管理
- 📅 证书伪造和克隆 (安全测试用途)

# 三、安装和使用

## 安装

### 源码编译
```bash
git clone https://github.com/cyberspacesec/certificate-hacker.git
cd certificate-hacker
make install   # 安装依赖
make build      # 构建程序
```

### 使用方法

#### 获取域名证书信息
```bash
# 获取Google的证书信息
./bin/cert-hacker info google.com

# 指定端口
./bin/cert-hacker info example.com:8443

# JSON格式输出
./bin/cert-hacker info google.com --output json
```

#### 解析本地证书文件
```bash
./bin/cert-hacker parse certificate.pem
./bin/cert-hacker parse certificate.crt --output json
```

#### 生成证书指纹
```bash
# 从域名生成指纹
./bin/cert-hacker fingerprint google.com

# 从证书文件生成指纹
./bin/cert-hacker fingerprint certificate.pem

# JSON格式输出
./bin/cert-hacker fingerprint google.com --output json
```

#### 下载证书到文件 (开发中)
```bash
./bin/cert-hacker download google.com
./bin/cert-hacker download google.com --output google.pem
```

### 输出示例

#### 文本格式
```
SSL/TLS Connection Information:
===============================
TLS Version: TLS 1.3
Cipher Suite: TLS_AES_128_GCM_SHA256
Handshake Time: 224.944667ms

Certificate Information:
========================
Subject: CN=*.google.com
Issuer: CN=WR2,O=Google Trust Services,C=US
Valid From: 2025-09-08 08:34:53 UTC
Valid To: 2025-12-01 08:34:52 UTC
DNS Names: *.google.com, *.youtube.com, google.com, youtube.com

Fingerprints:
=============
SHA256              : 2d:8f:a1:b5:9a:60:f4:14:ad:1c:29:44:92:c7:8b:af...
PUBLIC_KEY_SHA256   : f3:89:91:45:af:58:8f:aa:e1:99:98:ef:47:6c:76:43...
```

#### JSON格式
```json
{
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "peer_certificates": {
    "certificates": [{
      "subject": "CN=*.google.com",
      "issuer": "CN=WR2,O=Google Trust Services,C=US",
      "fingerprints": {
        "sha256": "2d:8f:a1:b5:9a:60:f4:14:ad:1c:29:44:92:c7:8b:af...",
        "public_key_sha256": "f3:89:91:45:af:58:8f:aa:e1:99:98:ef:47:6c:76:43..."
      }
    }]
  }
}
```

# 四、开发路线图

详细的开发任务和进度请查看 [docs/todo.md](docs/todo.md)

## 当前状态
- ✅ **基础框架**: 100% 完成
- ✅ **核心功能**: 80% 完成  
- 🚧 **分析功能**: 20% 完成
- 📋 **生成功能**: 计划中
- 🚧 **安全功能**: 15% 完成

**总体完成度: 约 40%**

# 五、许可证和安全声明

⚠️ **重要提醒**: 本工具仅用于合法的安全研究和测试目的。使用本工具进行任何非法活动的后果由用户自行承担。

# 六、相关资料

- [SSL/TLS 最佳实践](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [证书透明度项目](https://certificate.transparency.dev/)
- [OWASP SSL/TLS 指南](https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
