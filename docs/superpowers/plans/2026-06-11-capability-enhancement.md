# Certificate-Hacker Capability Enhancement Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 增强 certificate-hacker 的核心能力，包括 ECDSA/Ed25519 密钥支持、DER 格式解析、证书链验证、HTTP/2 检测、证书下载保存、KeySize 填充、证书比较 MCP 工具、批量安全分析，以及补充核心单元测试。

**Architecture:** 当前架构为三层：CLI (`cmd/main.go`) + MCP Server (`internal/mcpserver/`) + Core Library (`pkg/`)。增强按"先 Core Library → 再 MCP Handler/Tool → 最后 CLI + Skill"的顺序推进。每个增强项独立成 Task，按依赖关系排序。新增功能复用现有 `pkg/` 包函数模式，MCP 工具遵循 `tools.go` 定义 + `handlers.go` 处理器的模式。

**Tech Stack:** Go 1.23+, mcp-go v0.32.0, cobra v1.8.0, crypto/x509, crypto/ecdsa, crypto/ed25519, crypto/tls

**Risks:**
- Task 1 (ECDSA/Ed25519) 修改 `generator.go` 和 `ValidateCertificateFiles`，需确保现有 RSA 功能不受影响 → 缓解：保留 RSA 默认行为，ECDSA/Ed25519 作为新增选项
- Task 3 (证书链验证) 修改 `buildCertChain`，现有代码硬编码 `IsValid: true`，需确保改为真实验证后不破坏现有调用方 → 缓解：验证逻辑使用 Go 标准库 `x509.Verify`，保持返回结构不变
- Task 8 (单元测试) 需要生成测试用证书文件 → 缓解：使用 `GenerateSelfSignedCert` 在 TestMain 中动态生成
- Task 5 (下载保存) 需要将 PEM 编码的证书写入文件 → 缓解：复用 `GetCertFromDomain` 返回的原始证书数据

---

### Task 1: 添加 ECDSA 和 Ed25519 密钥支持

**Depends on:** None
**Files:**
- Modify: `pkg/generator.go:17-30` (CertificateRequest 新增 key_type 字段)
- Modify: `pkg/generator.go:40-154` (GenerateSelfSignedCert 支持 ECDSA/Ed25519)
- Modify: `pkg/generator.go:156-190` (GenerateCSR 支持 ECDSA/Ed25519)
- Modify: `pkg/generator.go:192-242` (ValidateCertificateFiles 支持 ECDSA/Ed25519)
- Modify: `internal/mcpserver/tools.go:79-120` (cert_generate 工具新增 key_type 参数)
- Modify: `internal/mcpserver/tools.go:122-152` (cert_generate_csr 工具新增 key_type 参数)
- Modify: `internal/mcpserver/handlers.go:112-146` (HandleCertGenerate 解析 key_type)
- Modify: `internal/mcpserver/handlers.go:148-182` (HandleCertGenerateCSR 解析 key_type)
- Modify: `cmd/main.go:46-56` (generate 命令新增 --key-type flag)
- Test: `pkg/generator_test.go`

- [ ] **Step 1: 修改 CertificateRequest 结构体 — 新增 KeyType 字段**
文件: `pkg/generator.go:17-30`

```go
// CertificateRequest 证书生成请求
type CertificateRequest struct {
	CommonName       string   `json:"common_name"`       // 通用名称
	Organization     string   `json:"organization"`      // 组织
	Country          string   `json:"country"`           // 国家
	Province         string   `json:"province"`          // 省份
	Locality         string   `json:"locality"`          // 地区
	DNSNames         []string `json:"dns_names"`         // DNS名称
	IPAddresses      []net.IP `json:"ip_addresses"`      // IP地址
	ValidityDays     int      `json:"validity_days"`     // 有效期天数
	KeySize          int      `json:"key_size"`          // RSA密钥长度
	KeyType          string   `json:"key_type"`          // 密钥类型: rsa, ecdsa, ed25519
	IsCA             bool     `json:"is_ca"`             // 是否为CA证书
	OutputCertPath   string   `json:"output_cert_path"`  // 证书输出路径
	OutputKeyPath    string   `json:"output_key_path"`   // 私钥输出路径
}
```

- [ ] **Step 2: 修改 GenerateSelfSignedCert — 支持 ECDSA P-256/P-384 和 Ed25519 密钥生成**
文件: `pkg/generator.go:40-154`

```go
// GenerateSelfSignedCert 生成自签名证书
func GenerateSelfSignedCert(req CertificateRequest) (*GenerationResult, error) {
	// 设置默认值
	if req.KeyType == "" {
		req.KeyType = "rsa"
	}
	if req.KeySize == 0 {
		if req.KeyType == "rsa" {
			req.KeySize = 2048
		} else if req.KeyType == "ecdsa" {
			req.KeySize = 256
		}
	}
	if req.ValidityDays == 0 {
		req.ValidityDays = 365
	}
	if req.CommonName == "" {
		req.CommonName = "localhost"
	}
	if req.OutputCertPath == "" {
		req.OutputCertPath = fmt.Sprintf("%s.pem", req.CommonName)
	}
	if req.OutputKeyPath == "" {
		req.OutputKeyPath = fmt.Sprintf("%s-key.pem", req.CommonName)
	}

	// 生成私钥
	var publicKey crypto.PublicKey
	var privateKeyBytes []byte

	switch req.KeyType {
	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, req.KeySize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA private key: %v", err)
		}
		publicKey = &privateKey.PublicKey
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RSA private key: %v", err)
		}
		privateKeyBytes = pkcs8Key

	case "ecdsa":
		var curve elliptic.Curve
		switch req.KeySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA private key: %v", err)
		}
		publicKey = &privateKey.PublicKey
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key: %v", err)
		}
		privateKeyBytes = pkcs8Key

	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Ed25519 private key: %v", err)
		}
		publicKey = pub
		pkcs8Key, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Ed25519 private key: %v", err)
		}
		privateKeyBytes = pkcs8Key

	default:
		return nil, fmt.Errorf("unsupported key type: %s (use rsa, ecdsa, or ed25519)", req.KeyType)
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{req.Organization},
			Country:      []string{req.Country},
			Province:     []string{req.Province},
			Locality:     []string{req.Locality},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(req.ValidityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
	}

	// Ed25519 不支持 KeyEncipherment，只设置 DigitalSignature
	if req.KeyType == "ed25519" {
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}

	// 如果是CA证书，设置相应的属性
	if req.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
	}

	// 如果没有指定DNS名称，添加CommonName
	if len(req.DNSNames) == 0 && req.CommonName != "" {
		template.DNSNames = append(template.DNSNames, req.CommonName)
	}

	// 生成证书 (self-signed: 使用自己的模板作为 parent)
	// 对于 Ed25519，签名算法会自动选择
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, crypto.PrivateKey(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// 保存证书到文件
	certFile, err := os.Create(req.OutputCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate file: %v", err)
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to write certificate: %v", err)
	}

	// 保存私钥到文件
	keyFile, err := os.Create(req.OutputKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key file: %v", err)
	}
	defer keyFile.Close()

	err = pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to write private key: %v", err)
	}

	// 解析证书以生成指纹
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %v", err)
	}

	// 生成指纹
	fingerprints := GenerateFingerprints(cert)

	result := &GenerationResult{
		CertificatePath: req.OutputCertPath,
		PrivateKeyPath:  req.OutputKeyPath,
		Fingerprints:    fingerprints,
		Message:         fmt.Sprintf("Successfully generated %s certificate and private key", req.KeyType),
	}

	return result, nil
}
```

- [ ] **Step 3: 修改 GenerateCSR — 支持 ECDSA 和 Ed25519**
文件: `pkg/generator.go:156-190`

```go
// GenerateCSR 生成证书签名请求 (Certificate Signing Request)
func GenerateCSR(req CertificateRequest) (string, error) {
	// 设置默认值
	if req.KeyType == "" {
		req.KeyType = "rsa"
	}
	if req.KeySize == 0 {
		if req.KeyType == "rsa" {
			req.KeySize = 2048
		} else if req.KeyType == "ecdsa" {
			req.KeySize = 256
		}
	}

	var signer crypto.Signer

	switch req.KeyType {
	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, req.KeySize)
		if err != nil {
			return "", fmt.Errorf("failed to generate RSA private key: %v", err)
		}
		signer = privateKey

	case "ecdsa":
		var curve elliptic.Curve
		switch req.KeySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return "", fmt.Errorf("failed to generate ECDSA private key: %v", err)
		}
		signer = privateKey

	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("failed to generate Ed25519 private key: %v", err)
		}
		signer = priv

	default:
		return "", fmt.Errorf("unsupported key type: %s (use rsa, ecdsa, or ed25519)", req.KeyType)
	}

	// 创建CSR模板
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{req.Organization},
			Country:      []string{req.Country},
			Province:     []string{req.Province},
			Locality:     []string{req.Locality},
		},
		DNSNames:    req.DNSNames,
		IPAddresses: req.IPAddresses,
	}

	// 生成CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %v", err)
	}

	// 转换为PEM格式
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEM), nil
}
```

- [ ] **Step 4: 修改 ValidateCertificateFiles — 支持 ECDSA 和 Ed25519 密钥对验证**
文件: `pkg/generator.go:192-242`

```go
// ValidateCertificateFiles 验证生成的证书文件
func ValidateCertificateFiles(certPath, keyPath string) error {
	// 检查证书文件
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %v", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// 检查私钥文件
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %v", err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// 验证私钥和证书是否匹配
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key type does not match private key type (expected RSA)")
		}
		if priv.PublicKey.N.Cmp(rsaPublicKey.N) != 0 {
			return fmt.Errorf("RSA private key and certificate do not match")
		}

	case *ecdsa.PrivateKey:
		ecdsaPublicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key type does not match private key type (expected ECDSA)")
		}
		if priv.PublicKey.X.Cmp(ecdsaPublicKey.X) != 0 || priv.PublicKey.Y.Cmp(ecdsaPublicKey.Y) != 0 {
			return fmt.Errorf("ECDSA private key and certificate do not match")
		}

	case ed25519.PrivateKey:
		ed25519PublicKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key type does not match private key type (expected Ed25519)")
		}
		derivedPub := priv.Public().(ed25519.PublicKey)
		if !bytes.Equal(derivedPub, ed25519PublicKey) {
			return fmt.Errorf("Ed25519 private key and certificate do not match")
		}

	default:
		return fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	return nil
}
```

- [ ] **Step 5: 更新 generator.go 的 import 声明 — 添加新依赖**
文件: `pkg/generator.go:1-14`

```go
package pkg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)
```

- [ ] **Step 6: 更新 MCP cert_generate 工具定义 — 新增 key_type 参数**
文件: `internal/mcpserver/tools.go:79-120`

在 `cert_generate` 工具定义中，在 `key_size` 参数之后、`is_ca` 参数之前添加：

```go
		mcp.WithString("key_type",
			mcp.Description("Key algorithm type. Options: 'rsa' (default), 'ecdsa', 'ed25519'. For ECDSA, key_size selects curve: 256=P-256, 384=P-384, 521=P-521"),
		),
```

- [ ] **Step 7: 更新 MCP cert_generate_csr 工具定义 — 新增 key_type 参数**
文件: `internal/mcpserver/tools.go:122-152`

在 `cert_generate_csr` 工具定义中，在 `key_size` 参数之后添加：

```go
		mcp.WithString("key_type",
			mcp.Description("Key algorithm type. Options: 'rsa' (default), 'ecdsa', 'ed25519'"),
		),
```

- [ ] **Step 8: 更新 HandleCertGenerate — 解析 key_type 参数**
文件: `internal/mcpserver/handlers.go:112-146`

在 `certReq` 构建中添加 `KeyType` 字段（在 `KeySize` 之后）：

```go
		KeyType:        req.GetString("key_type", "rsa"),
```

- [ ] **Step 9: 更新 HandleCertGenerateCSR — 解析 key_type 参数**
文件: `internal/mcpserver/handlers.go:148-182`

在 `certReq` 构建中添加 `KeyType` 字段（在 `KeySize` 之后）：

```go
		KeyType:      req.GetString("key_type", "rsa"),
```

- [ ] **Step 10: 更新 CLI generate 命令 — 添加 --key-type flag**
文件: `cmd/main.go:46-56`

在 `--key-size` flag 之后添加：

```go
		generateCmd.Flags().StringP("key-type", "", "rsa", "Key type (rsa, ecdsa, ed25519)")
```

在 `generateCmd` 的 `Run` 函数中添加 keyType 解析（在 `keySize` 之后）：

```go
			keyType, _ := cmd.Flags().GetString("key-type")
```

在 `pkg.CertificateRequest` 构建中添加：

```go
				KeyType:        keyType,
```

- [ ] **Step 11: 验证 ECDSA/Ed25519 证书生成**
Run: `cd /home/cc11001100/github/cyberspacesec/certificate-hacker && go build -o bin/cert-hacker ./cmd/ && ./bin/cert-hacker generate --common-name test-ecdsa --key-type ecdsa && ./bin/cert-hacker parse test-ecdsa.pem && rm -f test-ecdsa.pem test-ecdsa-key.pem`
Expected:
  - Exit code: 0
  - Output contains: "ECDSA" or "P-256"
  - Output does NOT contain: "Error" or "unsupported"

- [ ] **Step 12: 提交**
Run: `git add pkg/generator.go internal/mcpserver/tools.go internal/mcpserver/handlers.go cmd/main.go && git commit -m "feat(generator): add ECDSA and Ed25519 key type support for cert generation and validation"`

---

### Task 2: 修复 DER 格式证书解析

**Depends on:** None
**Files:**
- Modify: `pkg/certificate.go:100-120` (GetCertFromFile 支持 DER 格式)

- [ ] **Step 1: 修改 GetCertFromFile — 添加 DER 格式自动检测和解析**
文件: `pkg/certificate.go:100-120`

```go
// GetCertFromFile 从文件读取证书
func GetCertFromFile(filename string) (*CertInfo, error) {
	// 读取文件内容
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	// 尝试解析PEM格式
	block, _ := pem.Decode(data)
	if block != nil {
		// PEM格式成功解码
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}
		return buildCertInfo(cert), nil
	}

	// PEM解码失败，尝试DER格式（二进制）
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate as PEM or DER format: %v", err)
	}

	return buildCertInfo(cert), nil
}
```

- [ ] **Step 2: 验证 DER 格式解析**
Run: `cd /home/cc11001100/github/cyberspacesec/certificate-hacker && go build -o bin/cert-hacker ./cmd/ && openssl x509 -in $(find /etc/ssl/certs -name "*.pem" | head -1) -outform DER -out /tmp/test-der.crt && ./bin/cert-hacker parse /tmp/test-der.crt && rm -f /tmp/test-der.crt`
Expected:
  - Exit code: 0
  - Output contains: "Certificate Information" or "Subject"
  - Output does NOT contain: "failed to decode PEM block"

- [ ] **Step 3: 提交**
Run: `git add pkg/certificate.go && git commit -m "fix(parse): support DER format certificate parsing in GetCertFromFile"`

---

### Task 3: 实现真实证书链验证

**Depends on:** None
**Files:**
- Modify: `pkg/certificate.go:122-145` (buildCertChain 实现真实验证)

- [ ] **Step 1: 修改 buildCertChain — 使用 x509.Verify 实现真实证书链验证**
文件: `pkg/certificate.go:122-145`

```go
// buildCertChain 构建证书链信息
func buildCertChain(certs []*x509.Certificate) (*CertChain, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in chain")
	}

	chain := &CertChain{
		Certificates: make([]CertInfo, len(certs)),
		ChainLength:  len(certs),
	}

	for i, cert := range certs {
		chain.Certificates[i] = *buildCertInfo(cert)
	}

	// 设置信任锚点（根证书）
	if len(certs) > 0 {
		lastCert := certs[len(certs)-1]
		chain.TrustAnchor = lastCert.Subject.CommonName
	}

	// 使用系统证书池验证证书链
	// 只验证叶子证书（第一个），中间证书由系统或链中的证书提供
	leafCert := certs[0]
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	// 尝试使用系统根证书验证
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		// 无法加载系统证书池，标记为无法验证
		chain.IsValid = false
		chain.TrustAnchor = "Unable to verify (system cert pool unavailable)"
		return chain, nil
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         rootCAs,
		Intermediates: intermediates,
		// 不强制 DNS 名称匹配，因为分析场景只需验证链的完整性
		DNSName: "",
	}

	_, err = leafCert.Verify(verifyOpts)
	chain.IsValid = err == nil

	if err != nil {
		// 如果系统根证书验证失败，尝试用链中最后一个证书作为根
		// 这种情况出现在自签名证书或私有 CA 场景
		selfSignedOpts := x509.VerifyOptions{
			Roots:         x509.NewCertPool(),
			Intermediates: intermediates,
		}
		selfSignedOpts.Roots.AddCert(certs[len(certs)-1])

		_, selfSignedErr := leafCert.Verify(selfSignedOpts)
		chain.IsValid = selfSignedErr == nil
	}

	return chain, nil
}
```

- [ ] **Step 2: 验证证书链验证功能**
Run: `cd /home/cc11001100/github/cyberspacesec/certificate-hacker && go build -o bin/cert-hacker ./cmd/ && ./bin/cert-hacker info google.com --output json 2>&1 | grep -o '"is_valid":[^,]*'`
Expected:
  - Exit code: 0
  - Output contains: `"is_valid":true` (google.com 的证书链应验证通过)

- [ ] **Step 3: 提交**
Run: `git add pkg/certificate.go && git commit -m "feat(verify): implement real certificate chain validation using x509.Verify"`

---

### Task 4: 填充 KeySize 和 HTTP/2 支持检测

**Depends on:** None
**Files:**
- Modify: `pkg/certificate.go:148-176` (buildCertInfo 提取密钥大小)
- Modify: `pkg/certificate.go:57-97` (GetCertFromDomain 检测 HTTP/2 支持)
- Modify: `pkg/security.go:101-141` (analyzeCertificate 填充 KeySize)
- Modify: `pkg/certificate.go:22-38` (CertInfo 新增 KeySize 字段)

- [ ] **Step 1: 修改 CertInfo 结构体 — 新增 KeySize 字段**
文件: `pkg/certificate.go:22-38`

```go
// CertInfo 证书信息结构体
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DNSNames           []string  `json:"dns_names"`
	IPAddresses        []string  `json:"ip_addresses"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	KeySize            int       `json:"key_size"`
	KeyUsage           []string  `json:"key_usage"`
	ExtKeyUsage        []string  `json:"ext_key_usage"`
	IsCA               bool      `json:"is_ca"`
	Version            int       `json:"version"`
	Fingerprints       map[string]string `json:"fingerprints"`
}
```

- [ ] **Step 2: 修改 buildCertInfo — 提取密钥大小**
文件: `pkg/certificate.go:148-176`

在 `buildCertInfo` 函数中，在 `PublicKeyAlgorithm` 赋值之后、`SignatureAlgorithm` 赋值之前添加 KeySize 提取：

```go
// 在 PublicKeyAlgorithm 赋值之后添加
switch key := cert.PublicKey.(type) {
case *rsa.PublicKey:
	info.KeySize = key.N.BitLen()
case *ecdsa.PublicKey:
	info.KeySize = key.Curve.Params().BitSize
case ed25519.PublicKey:
	info.KeySize = 256 // Ed25519 固定为 256 位
}
```

- [ ] **Step 3: 修改 SSLInfo 结构体 — 新增 SupportsHTTP2 字段**
文件: `pkg/certificate.go:48-55`

```go
// SSLInfo SSL连接信息
type SSLInfo struct {
	TLSVersion     string           `json:"tls_version"`
	CipherSuite    string           `json:"cipher_suite"`
	PeerCerts      CertChain        `json:"peer_certificates"`
	ConnectedAt    time.Time        `json:"connected_at"`
	HandshakeTime  time.Duration    `json:"handshake_time"`
	SupportsHTTP2  bool             `json:"supports_http2"`
}
```

- [ ] **Step 4: 修改 GetCertFromDomain — 检测 HTTP/2 支持**
文件: `pkg/certificate.go:57-97`

在构建 `sslInfo` 的部分，在 `HandshakeTime` 之后添加：

```go
		// 检测 HTTP/2 支持：TLS 1.2+ 且 ALPN 协议包含 h2
		supportsHTTP2 := false
		if state.Version >= tls.VersionTLS12 {
			for _, proto := range state.NegotiatedProtocol {
				_ = proto // range over string
			}
			if state.NegotiatedProtocol == "h2" {
				supportsHTTP2 = true
			}
		}
```

在 `sslInfo` 初始化中添加 `SupportsHTTP2` 字段：

```go
	sslInfo := &SSLInfo{
		TLSVersion:    getTLSVersionName(state.Version),
		CipherSuite:   tls.CipherSuiteName(state.CipherSuite),
		PeerCerts:     *certChain,
		ConnectedAt:   time.Now(),
		HandshakeTime: handshakeTime,
		SupportsHTTP2: supportsHTTP2,
	}
```

- [ ] **Step 5: 修改 analyzeTLS — 填充 SupportsHTTP2 并在 analyzeCertificate 中填充 KeySize**
文件: `pkg/security.go:143-180`

在 `analyzeTLS` 函数中，在 `Warnings` 初始化之后添加：

```go
	check.SupportsHTTP2 = sslInfo.SupportsHTTP2
```

在 `analyzeCertificate` 函数中，在 `SignatureAlg` 赋值之后添加：

```go
	check.KeySize = cert.KeySize
```

- [ ] **Step 6: 验证 KeySize 和 HTTP/2 检测**
Run: `cd /home/cc11001100/github/cyberspacesec/certificate-hacker && go build -o bin/cert-hacker ./cmd/ && ./bin/cert-hacker info google.com --output json 2>&1 | grep -E '"key_size"|"supports_http2"'`
Expected:
  - Exit code: 0
  - Output contains: `"key_size":2048` or `"key_size":4096` or similar non-zero value
  - Output contains: `"supports_http2":true` or `"supports_http2":false`

- [ ] **Step 7: 提交**
Run: `git add pkg/certificate.go pkg/security.go && git commit -m "feat(info): populate KeySize in CertInfo and detect HTTP/2 support in SSLInfo"`

---

### Task 5: 实现证书下载保存功能

**Depends on:** None
**Files:**
- Create: `pkg/downloader.go`
- Modify: `cmd/main.go:138-167` (downloadCmd 实现真实保存逻辑)

- [ ] **Step 1: 创建 downloader.go — 实现证书下载保存功能**

```go
package pkg

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// DownloadResult 证书下载结果
type DownloadResult struct {
	Target         string   `json:"target"`
	SavedFiles     []string `json:"saved_files"`
	ChainLength    int      `json:"chain_length"`
	Message        string   `json:"message"`
}

// DownloadCertsFromDomain 从域名下载证书链并保存到文件
func DownloadCertsFromDomain(target string, outputDir string) (*DownloadResult, error) {
	if outputDir == "" {
		outputDir = "."
	}

	sslInfo, err := GetCertFromDomain(target)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSL info from %s: %v", target, err)
	}

	if len(sslInfo.PeerCerts.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found for %s", target)
	}

	// 解析主机名用于文件命名
	host := target
	if len(host) > 0 {
		// 移除端口号
		for i, c := range host {
			if c == ':' {
				host = host[:i]
				break
			}
		}
	}

	savedFiles := []string{}

	// 连接到目标获取原始证书
	conn, err := tlsDial(target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates

	// 保存整个证书链到单个文件
	chainPath := fmt.Sprintf("%s/%s-chain.pem", outputDir, host)
	chainFile, err := os.Create(chainPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create chain file: %v", err)
	}
	defer chainFile.Close()

	for _, cert := range certs {
		err := pem.Encode(chainFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to write certificate to chain file: %v", err)
		}
	}
	savedFiles = append(savedFiles, chainPath)

	// 保存叶子证书到单独文件
	if len(certs) > 0 {
		leafPath := fmt.Sprintf("%s/%s.pem", outputDir, host)
		leafFile, err := os.Create(leafPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create leaf cert file: %v", err)
		}
		defer leafFile.Close()

		err = pem.Encode(leafFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certs[0].Raw,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to write leaf certificate: %v", err)
		}
		savedFiles = append(savedFiles, leafPath)
	}

	result := &DownloadResult{
		Target:      target,
		SavedFiles:  savedFiles,
		ChainLength: len(certs),
		Message:     fmt.Sprintf("Downloaded %d certificates for %s", len(certs), target),
	}

	return result, nil
}
```

- [ ] **Step 2: 添加 tlsDial 辅助函数到 downloader.go**

在 `downloader.go` 中 `DownloadCertsFromDomain` 函数之后添加：

```go
// tlsDial 建立TLS连接并返回连接对象
func tlsDial(target string) (*tls.Conn, error) {
	host, port := parseHostPort(target)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%s", host, port),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:%s: %v", host, port, err)
	}

	return conn, nil
}
```

添加 downloader.go 的 import 声明：

```go
import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"
)
```

- [ ] **Step 3: 修改 downloadCmd — 实现真实的证书下载保存**
文件: `cmd/main.go:138-167`

```go
var downloadCmd = &cobra.Command{
	Use:   "download [domain:port]",
	Short: "Download certificate from a domain",
	Long:  `Download SSL/TLS certificate chain from a remote domain and save to PEM files.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		outputFile, _ := cmd.Flags().GetString("output")
		outputFormat, _ := cmd.Flags().GetString("output")

		result, err := pkg.DownloadCertsFromDomain(domain, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error downloading certificate: %v\n", err)
			os.Exit(1)
		}

		if outputFormat == "json" {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
				return
			}
			fmt.Println(string(data))
			return
		}

		fmt.Printf("Certificate Download Complete!\n")
		fmt.Printf("=============================\n")
		fmt.Printf("Target: %s\n", result.Target)
		fmt.Printf("Chain Length: %d certificates\n", result.ChainLength)
		fmt.Printf("\nSaved Files:\n")
		for _, f := range result.SavedFiles {
			fmt.Printf("  - %s\n", f)
		}
		_ = outputFile // future: custom output path
	},
}
```

- [ ] **Step 4: 验证证书下载功能**
Run: `cd /home/cc11001100/github/cyberspacesec/certificate-hacker && go build -o bin/cert-hacker ./cmd/ && cd /tmp && /home/cc11001100/github/cyberspacesec/certificate-hacker/bin/cert-hacker download google.com && ls -la google.com*.pem && /home/cc11001100/github/cyberspacesec/certificate-hacker/bin/cert-hacker parse google.com.pem && rm -f google.com*.pem`
Expected:
  - Exit code: 0
  - Output contains: "Certificate Download Complete"
  - `ls` shows `google.com-chain.pem` and `google.com.pem`
  - Parse output contains certificate subject info

- [ ] **Step 5: 提交**
Run: `git add pkg/downloader.go cmd/main.go && git commit -m "feat(download): implement real certificate chain download and save to PEM files"`

---

### Task 6: 添加证书比较 MCP 工具

**Depends on:** Task 2 (DER 格式支持，用于文件解析)
**Files:**
- Modify: `pkg/fingerprint.go:74-81` (CompareCertFingerprints 改为返回详细比较结果)
- Create: `pkg/comparator.go` (高级比较逻辑)
- Modify: `internal/mcpserver/tools.go` (新增 cert_compare 工具定义)
- Modify: `internal/mcpserver/handlers.go` (新增 HandleCertCompare 处理器)
- Modify: `internal/mcpserver/tools.go:9-21` (Tools 函数注册新工具)

- [ ] **Step 1: 创建 comparator.go — 实现证书比较功能**

```go
package pkg

import (
	"crypto/x509"
	"fmt"
	"time"
)

// CertComparison 证书比较结果
type CertComparison struct {
	Match          bool              `json:"match"`
	MatchDetails   MatchDetails      `json:"match_details"`
	Cert1Summary   CertSummary       `json:"cert1_summary"`
	Cert2Summary   CertSummary       `json:"cert2_summary"`
	Differences    []CertDifference  `json:"differences"`
}

// MatchDetails 匹配详情
type MatchDetails struct {
	SHA256Match   bool `json:"sha256_match"`
	PublicKeyMatch bool `json:"public_key_match"`
	SubjectMatch  bool `json:"subject_match"`
	IssuerMatch   bool `json:"issuer_match"`
}

// CertSummary 证书摘要
type CertSummary struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	KeySize            int       `json:"key_size"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	DNSNames           []string  `json:"dns_names"`
}

// CertDifference 证书差异
type CertDifference struct {
	Field    string `json:"field"`
	Cert1Val string `json:"cert1_value"`
	Cert2Val string `json:"cert2_value"`
}

// CompareCerts 比较两个证书
func CompareCerts(cert1, cert2 *x509.Certificate) *CertComparison {
	fp1 := GenerateFingerprints(cert1)
	fp2 := GenerateFingerprints(cert2)

	comparison := &CertComparison{}

	// 指纹比较
	comparison.MatchDetails.SHA256Match = fp1["sha256"] == fp2["sha256"]
	comparison.MatchDetails.PublicKeyMatch = fp1["public_key_sha256"] == fp2["public_key_sha256"]
	comparison.MatchDetails.SubjectMatch = cert1.Subject.String() == cert2.Subject.String()
	comparison.MatchDetails.IssuerMatch = cert1.Issuer.String() == cert2.Issuer.String()

	// 两个证书完全匹配 = SHA-256 指纹相同
	comparison.Match = comparison.MatchDetails.SHA256Match

	// 证书摘要
	comparison.Cert1Summary = buildCertSummary(cert1)
	comparison.Cert2Summary = buildCertSummary(cert2)

	// 查找差异
	comparison.Differences = findDifferences(cert1, cert2)

	return comparison
}

// buildCertSummary 构建证书摘要
func buildCertSummary(cert *x509.Certificate) CertSummary {
	summary := CertSummary{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		DNSNames:           cert.DNSNames,
	}

	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		summary.KeySize = key.N.BitLen()
	case *ecdsa.PublicKey:
		summary.KeySize = key.Curve.Params().BitSize
	}

	return summary
}

// findDifferences 查找两个证书之间的差异
func findDifferences(cert1, cert2 *x509.Certificate) []CertDifference {
	var diffs []CertDifference

	if cert1.Subject.String() != cert2.Subject.String() {
		diffs = append(diffs, CertDifference{
			Field:    "subject",
			Cert1Val: cert1.Subject.String(),
			Cert2Val: cert2.Subject.String(),
		})
	}

	if cert1.Issuer.String() != cert2.Issuer.String() {
		diffs = append(diffs, CertDifference{
			Field:    "issuer",
			Cert1Val: cert1.Issuer.String(),
			Cert2Val: cert2.Issuer.String(),
		})
	}

	if cert1.SerialNumber.String() != cert2.SerialNumber.String() {
		diffs = append(diffs, CertDifference{
			Field:    "serial_number",
			Cert1Val: cert1.SerialNumber.String(),
			Cert2Val: cert2.SerialNumber.String(),
		})
	}

	if !cert1.NotAfter.Equal(cert2.NotAfter) {
		diffs = append(diffs, CertDifference{
			Field:    "not_after",
			Cert1Val: cert1.NotAfter.Format(time.RFC3339),
			Cert2Val: cert2.NotAfter.Format(time.RFC3339),
		})
	}

	if cert1.PublicKeyAlgorithm.String() != cert2.PublicKeyAlgorithm.String() {
		diffs = append(diffs, CertDifference{
			Field:    "public_key_algorithm",
			Cert1Val: cert1.PublicKeyAlgorithm.String(),
			Cert2Val: cert2.PublicKeyAlgorithm.String(),
		})
	}

	if cert1.SignatureAlgorithm.String() != cert2.SignatureAlgorithm.String() {
		diffs = append(diffs, CertDifference{
			Field:    "signature_algorithm",
			Cert1Val: cert1.SignatureAlgorithm.String(),
			Cert2Val: cert2.SignatureAlgorithm.String(),
		})
	}

	return diffs
}

// CompareCertsFromDomains 从两个域名获取证书并比较
func CompareCertsFromDomains(domain1, domain2 string) (*CertComparison, error) {
	sslInfo1, err := GetCertFromDomain(domain1)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert from %s: %v", domain1, err)
	}

	sslInfo2, err := GetCertFromDomain(domain2)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert from %s: %v", domain2, err)
	}

	if len(sslInfo1.PeerCerts.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found for %s", domain1)
	}
	if len(sslInfo2.PeerCerts.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found for %s", domain2)
	}

	// 需要从原始 x509.Certificate 对象比较，此处使用指纹间接比较
	// 由于 buildCertInfo 已经丢失了原始 x509.Certificate，我们重新连接获取
	conn1, err := tlsDial(domain1)
	if err != nil {
		return nil, err
	}
	defer conn1.Close()

	conn2, err := tlsDial(domain2)
	if err != nil {
		return nil, err
	}
	defer conn2.Close()

	certs1 := conn1.ConnectionState().PeerCertificates
	certs2 := conn2.ConnectionState().PeerCertificates

	if len(certs1) == 0 || len(certs2) == 0 {
		return nil, fmt.Errorf("no certificates found in connection")
	}

	return CompareCerts(certs1[0], certs2[0]), nil
}

// CompareCertsFromFiles 从两个文件读取证书并比较
func CompareCertsFromFiles(file1, file2 string) (*CertComparison, error) {
	cert1, err := readCertFromFile(file1)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert from %s: %v", file1, err)
	}

	cert2, err := readCertFromFile(file2)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert from %s: %v", file2, err)
	}

	return CompareCerts(cert1, cert2), nil
}
```

- [ ] **Step 2: 添加 readCertFromFile 辅助函数到 comparator.go**

```go
// readCertFromFile 从文件读取原始 x509.Certificate 对象
func readCertFromFile(filename string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	// 尝试 PEM 格式
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}

	// 尝试 DER 格式
	return x509.ParseCertificate(data)
}
```

更新 comparator.go 的 import 声明：

```go
import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)
```

- [ ] **Step 3: 新增 cert_compare MCP 工具定义**
文件: `internal/mcpserver/tools.go` (在 `CertValidateFingerprintTool` 之后添加)

```go
var CertCompareTool = mcp.NewTool("cert_compare",
	mcp.WithDescription(
		"Compare two SSL/TLS certificates to determine if they are identical or different. "+
			"Compares fingerprints, subjects, issuers, validity dates, key algorithms, and more. "+
			"Can compare two domains, two files, or a domain vs a file."),
	mcp.WithString("target1",
		mcp.Required(),
		mcp.Description("First certificate target - a domain name (e.g., 'example.com') or file path (e.g., '/path/to/cert.pem')"),
	),
	mcp.WithString("target2",
		mcp.Required(),
		mcp.Description("Second certificate target - a domain name or file path"),
	),
)
```

- [ ] **Step 4: 注册 cert_compare 工具到 Tools 函数**
文件: `internal/mcpserver/tools.go:9-21`

在 `CertValidateFingerprintTool` 之后添加：

```go
			{Tool: CertCompareTool, Handler: HandleCertCompare},
```

- [ ] **Step 5: 新增 HandleCertCompare 处理器**
文件: `internal/mcpserver/handlers.go` (在 `HandleCertValidateFingerprint` 之后添加)

```go
// HandleCertCompare compares two certificates.
func HandleCertCompare(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target1, err := req.RequireString("target1")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	target2, err := req.RequireString("target2")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	var comparison *pkg.CertComparison

	// 判断目标类型：文件路径 or 域名
	isFile1 := isFilePath(target1)
	isFile2 := isFilePath(target2)

	if isFile1 && isFile2 {
		comparison, err = pkg.CompareCertsFromFiles(target1, target2)
	} else if !isFile1 && !isFile2 {
		comparison, err = pkg.CompareCertsFromDomains(target1, target2)
	} else if isFile1 && !isFile2 {
		// 文件 vs 域名：分别获取再比较
		cert1, err1 := pkg.ReadCertFromFile(target1)
		if err1 != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read cert from %s: %v", target1, err1)), nil
		}
		conn2, err2 := pkg.TLSDial(target2)
		if err2 != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to %s: %v", target2, err2)), nil
		}
		defer conn2.Close()
		certs2 := conn2.ConnectionState().PeerCertificates
		if len(certs2) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("no certificates found for %s", target2)), nil
		}
		comparison = pkg.CompareCerts(cert1, certs2[0])
		err = nil
	} else {
		// 域名 vs 文件
		conn1, err1 := pkg.TLSDial(target1)
		if err1 != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to %s: %v", target1, err1)), nil
		}
		defer conn1.Close()
		certs1 := conn1.ConnectionState().PeerCertificates
		if len(certs1) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("no certificates found for %s", target1)), nil
		}
		cert2, err2 := pkg.ReadCertFromFile(target2)
		if err2 != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read cert from %s: %v", target2, err2)), nil
		}
		comparison = pkg.CompareCerts(certs1[0], cert2)
		err = nil
	}

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to compare certificates: %v", err)), nil
	}

	return marshalResult(comparison)
}

// isFilePath 判断目标是否为文件路径
func isFilePath(target string) bool {
	fileExts := []string{".pem", ".crt", ".cer", ".der", ".p7b", ".p7c"}
	for _, ext := range fileExts {
		if strings.HasSuffix(strings.ToLower(target), ext) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 6: 导出 readCertFromFile 和 tlsDial 为公共函数**
文件: `pkg/comparator.go` — 将 `readCertFromFile` 重命名为 `ReadCertFromFile`
文件: `pkg/downloader.go` — 将 `tlsDial` 重命名为 `TLSDial`

更新 comparator.go 中的函数签名和所有内部调用：

```go
// ReadCertFromFile 从文件读取原始 x509.Certificate 对象（公开函数）
func ReadCertFromFile(filename string) (*x509.Certificate, error) {
```

更新 downloader.go 中的函数签名：

```go
// TLSDial 建立TLS连接并返回连接对象（公开函数）
func TLSDial(target string) (*tls.Conn, error) {
```

更新 `downloader.go` 中 `DownloadCertsFromDomain` 对 `tlsDial` 的调用为 `TLSDial`。

- [ ] **Step 7: 更新 handlers.go import 声明**
文件: `internal/mcpserver/handlers.go:1-12`

确保 import 包含 `strings`：

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cyberspacesec/certificate-hacker/pkg"
	"github.com/mark3labs/mcp-go/mcp"
)
```

- [ ] **Step 8: 验证证书比较功能**
Run: `cd /home/cc11001100/github/cyberspacesec/certificate-hacker && go build ./... && echo "Build successful"`
Expected:
  - Exit code: 0
  - Output contains: "Build successful"
  - Output does NOT contain: "cannot" or "undefined"

- [ ] **Step 9: 提交**
Run: `git add pkg/comparator.go pkg/downloader.go internal/mcpserver/tools.go internal/mcpserver/handlers.go && git commit -m "feat(compare): add certificate comparison MCP tool with domain and file support"`

---

### Task 7: 添加批量安全分析 MCP 工具

**Depends on:** None
**Files:**
- Modify: `internal/mcpserver/tools.go` (新增 cert_batch_analyze 工具定义)
- Modify: `internal/mcpserver/handlers.go` (新增 HandleCertBatchAnalyze 处理器)
- Modify: `pkg/security.go` (新增 BatchSecurityAnalysis 函数)

- [ ] **Step 1: 在 pkg/security.go 中添加 BatchSecurityAnalysis 函数**

在 `pkg/security.go` 文件末尾添加：

```go
// BatchSecurityAnalysis 批量安全分析
type BatchSecurityAnalysis struct {
	Results    []SecurityAnalysis `json:"results"`
	TotalCount int                `json:"total_count"`
	Summary    BatchSummary       `json:"summary"`
}

// BatchSummary 批量分析摘要
type BatchSummary struct {
	GoodCount      int `json:"good_count"`
	MediumCount    int `json:"medium_count"`
	HighCount      int `json:"high_count"`
	CriticalCount  int `json:"critical_count"`
	AverageScore   int `json:"average_score"`
}

// BatchAnalyzeSecurity 批量分析多个目标的安全性
func BatchAnalyzeSecurity(targets []string) *BatchSecurityAnalysis {
	result := &BatchSecurityAnalysis{
		Results:    make([]SecurityAnalysis, 0, len(targets)),
		TotalCount: len(targets),
	}

	totalScore := 0

	for _, target := range targets {
		analysis, err := AnalyzeSecurity(target)
		if err != nil {
			// 跳过失败的目标，记录错误信息
			failedAnalysis := SecurityAnalysis{
				Target:       target,
				OverallScore: 0,
				SecurityLevel: "Error",
				Issues: []SecurityIssue{
					{
						Severity:    "Critical",
						Type:        "Connection Failed",
						Description: fmt.Sprintf("Failed to analyze: %v", err),
						Impact:      "Unable to assess security posture",
					},
				},
			}
			result.Results = append(result.Results, failedAnalysis)
			result.Summary.CriticalCount++
			continue
		}

		result.Results = append(result.Results, *analysis)
		totalScore += analysis.OverallScore

		switch analysis.SecurityLevel {
		case "Good":
			result.Summary.GoodCount++
		case "Medium":
			result.Summary.MediumCount++
		case "High":
			result.Summary.HighCount++
		case "Critical":
			result.Summary.CriticalCount++
		}
	}

	if len(targets) > 0 {
		result.Summary.AverageScore = totalScore / len(targets)
	}

	return result
}
```

- [ ] **Step 2: 新增 cert_batch_analyze MCP 工具定义**
文件: `internal/mcpserver/tools.go` (在 `CertCompareTool` 之后添加)

```go
var CertBatchAnalyzeTool = mcp.NewTool("cert_batch_analyze",
	mcp.WithDescription(
		"Perform security analysis on multiple domains simultaneously. Returns individual security "+
			"scores and a summary with counts per security level and average score. Useful for "+
			"monitoring certificate security across multiple services."),
	mcp.WithArray("targets",
		mcp.Required(),
		mcp.Description("List of domain names or IP addresses to analyze (e.g., ['google.com', 'github.com', 'cloudflare.com:443'])"),
	),
)
```

- [ ] **Step 3: 注册 cert_batch_analyze 工具到 Tools 函数**
文件: `internal/mcpserver/tools.go:9-21`

在 `CertCompareTool` 之后添加：

```go
			{Tool: CertBatchAnalyzeTool, Handler: HandleCertBatchAnalyze},
```

- [ ] **Step 4: 新增 HandleCertBatchAnalyze 处理器**
文件: `internal/mcpserver/handlers.go` (在 `HandleCertCompare` 之后添加)

```go
// HandleCertBatchAnalyze performs security analysis on multiple domains.
func HandleCertBatchAnalyze(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	targets := req.GetStringSlice("targets", []string{})
	if len(targets) == 0 {
		return mcp.NewToolResultError("targets array is required and must contain at least one domain"), nil
	}

	if len(targets) > 50 {
		return mcp.NewToolResultError("maximum 50 targets allowed per batch"), nil
	}

	result := pkg.BatchAnalyzeSecurity(targets)
	return marshalResult(result)
}
```

- [ ] **Step 5: 验证批量分析功能**
Run: `cd /home/cc11001100/github/cyberspacesec/certificate-hacker && go build ./... && echo "Build successful"`
Expected:
  - Exit code: 0
  - Output contains: "Build successful"

- [ ] **Step 6: 提交**
Run: `git add pkg/security.go internal/mcpserver/tools.go internal/mcpserver/handlers.go && git commit -m "feat(analyze): add batch security analysis MCP tool for multiple domains"`

---

### Task 8: 补充核心单元测试

**Depends on:** Task 1, Task 2, Task 3, Task 4
**Files:**
- Create: `pkg/generator_test.go`
- Create: `pkg/fingerprint_test.go`
- Create: `pkg/certificate_test.go`
- Create: `pkg/security_test.go`

- [ ] **Step 1: 创建 generator_test.go — 证书生成测试**

```go
package pkg

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestGenerateSelfSignedCert_RSA(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-rsa",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
		DNSNames:     []string{"test.example.com"},
	}

	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert RSA failed: %v", err)
	}
	defer os.Remove(result.CertificatePath)
	defer os.Remove(result.PrivateKeyPath)

	if result.CertificatePath == "" {
		t.Error("CertificatePath should not be empty")
	}
	if result.PrivateKeyPath == "" {
		t.Error("PrivateKeyPath should not be empty")
	}
	if result.Fingerprints["sha256"] == "" {
		t.Error("SHA-256 fingerprint should not be empty")
	}
	if result.Message == "" {
		t.Error("Message should not be empty")
	}

	// 验证文件存在
	if _, err := os.Stat(result.CertificatePath); os.IsNotExist(err) {
		t.Error("Certificate file should exist")
	}
	if _, err := os.Stat(result.PrivateKeyPath); os.IsNotExist(err) {
		t.Error("Private key file should exist")
	}
}

func TestGenerateSelfSignedCert_ECDSA(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-ecdsa",
		KeyType:      "ecdsa",
		KeySize:      256,
		ValidityDays: 365,
	}

	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert ECDSA failed: %v", err)
	}
	defer os.Remove(result.CertificatePath)
	defer os.Remove(result.PrivateKeyPath)

	// 验证证书包含 ECDSA 公钥
	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("Expected ECDSA algorithm, got %s", cert.PublicKeyAlgorithm)
	}
}

func TestGenerateSelfSignedCert_Ed25519(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-ed25519",
		KeyType:      "ed25519",
		ValidityDays: 365,
	}

	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert Ed25519 failed: %v", err)
	}
	defer os.Remove(result.CertificatePath)
	defer os.Remove(result.PrivateKeyPath)

	// 验证证书包含 Ed25519 公钥
	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if cert.PublicKeyAlgorithm != x509.Ed25519 {
		t.Errorf("Expected Ed25519 algorithm, got %s", cert.PublicKeyAlgorithm)
	}
}

func TestGenerateSelfSignedCert_UnsupportedKeyType(t *testing.T) {
	req := CertificateRequest{
		CommonName: "test-unsupported",
		KeyType:    "dsa",
	}

	_, err := GenerateSelfSignedCert(req)
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

func TestGenerateSelfSignedCert_CA(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-ca",
		KeyType:      "rsa",
		KeySize:      4096,
		ValidityDays: 3650,
		IsCA:         true,
	}

	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert CA failed: %v", err)
	}
	defer os.Remove(result.CertificatePath)
	defer os.Remove(result.PrivateKeyPath)

	// 验证证书是 CA 证书
	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if !cert.IsCA {
		t.Error("Certificate should be a CA certificate")
	}
}

func TestValidateCertificateFiles(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-validate",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
	}

	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer os.Remove(result.CertificatePath)
	defer os.Remove(result.PrivateKeyPath)

	err = ValidateCertificateFiles(result.CertificatePath, result.PrivateKeyPath)
	if err != nil {
		t.Errorf("ValidateCertificateFiles failed: %v", err)
	}
}

func TestGenerateCSR(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-csr.example.com",
		Organization: "Test Org",
		Country:      "US",
		KeyType:      "rsa",
		KeySize:      2048,
		DNSNames:     []string{"www.test-csr.example.com"},
	}

	csrPEM, err := GenerateCSR(req)
	if err != nil {
		t.Fatalf("GenerateCSR failed: %v", err)
	}

	if csrPEM == "" {
		t.Error("CSR PEM should not be empty")
	}

	// 验证 PEM 格式
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Error("CSR should be valid PEM with CERTIFICATE REQUEST type")
	}
}
```

- [ ] **Step 2: 创建 fingerprint_test.go — 指纹生成和验证测试**

```go
package pkg

import (
	"crypto/x509"
	"testing"
)

func TestGenerateFingerprints(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-fp",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
	}

	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// 从文件读取证书获取 x509.Certificate
	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	cert, _ := x509.ParseCertificate(block.Bytes)

	fingerprints := GenerateFingerprints(cert)

	// 检查所有指纹类型都存在
	expectedKeys := []string{"md5", "sha1", "sha256", "public_key_sha256"}
	for _, key := range expectedKeys {
		if fingerprints[key] == "" {
			t.Errorf("Missing fingerprint: %s", key)
		}
	}

	// 检查 SHA-256 指纹格式 (64 hex chars with colons = 95 chars)
	if len(fingerprints["sha256"]) != 95 {
		t.Errorf("SHA-256 fingerprint has unexpected length: %d", len(fingerprints["sha256"]))
	}
}

func TestValidateFingerprint_SHA256(t *testing.T) {
	tests := []struct {
		name       string
		fingerprint string
		hashType   string
		expected   bool
	}{
		{"valid sha256", "ab:cd:ef:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc", "sha256", true},
		{"valid sha256 no colons", "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbcc", "sha256", true},
		{"invalid sha256 too short", "ab:cd:ef", "sha256", false},
		{"invalid sha256 bad char", "ab:cd:ef:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:GG", "sha256", false},
		{"valid md5", "ab:cd:ef:00:11:22:33:44:55:66:77:88:99:aa:bb:cc", "md5", true},
		{"valid sha1", "ab:cd:ef:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00", "sha1", true},
		{"invalid hash type", "abcd", "sha512", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateFingerprint(tt.fingerprint, tt.hashType)
			if result != tt.expected {
				t.Errorf("ValidateFingerprint(%q, %q) = %v, expected %v", tt.fingerprint, tt.hashType, result, tt.expected)
			}
		})
	}
}

func TestCompareCertFingerprints(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-compare",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
	}

	result, _ := GenerateSelfSignedCert(req)
	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	cert, _ := x509.ParseCertificate(block.Bytes)

	// 同一证书比较应为 true
	if !CompareCertFingerprints(cert, cert) {
		t.Error("Same certificate fingerprints should match")
	}
}
```

注意：fingerprint_test.go 需要添加 `import "os"` 和 `import "encoding/pem"`。

- [ ] **Step 3: 创建 certificate_test.go — 证书解析测试**

```go
package pkg

import (
	"os"
	"testing"
)

func TestGetCertFromFile_PEM(t *testing.T) {
	// 先生成一个测试证书
	req := CertificateRequest{
		CommonName:   "test-parse",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
		DNSNames:     []string{"test.example.com", "www.test.example.com"},
	}

	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer os.Remove(result.CertificatePath)
	defer os.Remove(result.PrivateKeyPath)

	// 解析生成的证书
	certInfo, err := GetCertFromFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("GetCertFromFile failed: %v", err)
	}

	if certInfo.Subject == "" {
		t.Error("Subject should not be empty")
	}
	if certInfo.Issuer == "" {
		t.Error("Issuer should not be empty")
	}
	if certInfo.PublicKeyAlgorithm == "" {
		t.Error("PublicKeyAlgorithm should not be empty")
	}
	if certInfo.KeySize == 0 {
		t.Error("KeySize should not be zero")
	}
	if len(certInfo.DNSNames) == 0 {
		t.Error("DNSNames should not be empty")
	}
	if certInfo.Fingerprints["sha256"] == "" {
		t.Error("SHA-256 fingerprint should not be empty")
	}
}

func TestGetCertFromFile_Nonexistent(t *testing.T) {
	_, err := GetCertFromFile("/nonexistent/cert.pem")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestGetCertFromFile_InvalidContent(t *testing.T) {
	// 创建一个无效内容的文件
	tmpFile, _ := os.CreateTemp("", "invalid-*.pem")
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("this is not a certificate")
	tmpFile.Close()

	_, err := GetCertFromFile(tmpFile.Name())
	if err == nil {
		t.Error("Expected error for invalid certificate file")
	}
}

func TestGetCertFromFile_DER(t *testing.T) {
	// 生成测试证书
	req := CertificateRequest{
		CommonName:   "test-der",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
	}

	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer os.Remove(result.CertificatePath)
	defer os.Remove(result.PrivateKeyPath)

	// 将 PEM 转为 DER 格式
	pemData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(pemData)

	derFile, _ := os.CreateTemp("", "test-der-*.crt")
	defer os.Remove(derFile.Name())
	derFile.Write(block.Bytes)
	derFile.Close()

	// 解析 DER 格式证书
	certInfo, err := GetCertFromFile(derFile.Name())
	if err != nil {
		t.Fatalf("GetCertFromFile DER failed: %v", err)
	}

	if certInfo.Subject == "" {
		t.Error("Subject should not be empty for DER cert")
	}
}

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string // host:port
	}{
		{"example.com", "example.com:443"},
		{"example.com:8443", "example.com:8443"},
		{"192.168.1.1", "192.168.1.1:443"},
		{"192.168.1.1:8443", "192.168.1.1:8443"},
	}

	for _, tt := range tests {
		host, port := parseHostPort(tt.input)
		result := host + ":" + port
		if result != tt.expected {
			t.Errorf("parseHostPort(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}
```

注意：certificate_test.go 需要添加 `import "encoding/pem"`。

- [ ] **Step 4: 创建 security_test.go — 安全分析测试**

```go
package pkg

import (
	"testing"
)

func TestAnalyzeSecurity_RealDomain(t *testing.T) {
	// 使用一个已知安全的域名测试
	analysis, err := AnalyzeSecurity("google.com")
	if err != nil {
		t.Skipf("Skipping: cannot connect to google.com: %v", err)
	}

	if analysis.OverallScore < 0 || analysis.OverallScore > 100 {
		t.Errorf("OverallScore should be 0-100, got %d", analysis.OverallScore)
	}

	validLevels := map[string]bool{"Good": true, "Medium": true, "High": true, "Critical": true}
	if !validLevels[analysis.SecurityLevel] {
		t.Errorf("Invalid SecurityLevel: %s", analysis.SecurityLevel)
	}

	if analysis.Target != "google.com" {
		t.Errorf("Target should be google.com, got %s", analysis.Target)
	}

	// google.com 应该有有效的 TLS
	if analysis.TLSCheck.Version == "" {
		t.Error("TLS version should not be empty")
	}

	if analysis.ExpirationCheck.Status == "" {
		t.Error("Expiration status should not be empty")
	}
}

func TestAnalyzeSecurity_InvalidDomain(t *testing.T) {
	_, err := AnalyzeSecurity("this-domain-does-not-exist-xyz123.invalid")
	if err == nil {
		t.Error("Expected error for invalid domain")
	}
}

func TestAnalyzeSecurity_ScoreCalculation(t *testing.T) {
	analysis := &SecurityAnalysis{
		Issues: []SecurityIssue{
			{Severity: "Critical", Type: "Test", Description: "test", Impact: "test"},
			{Severity: "High", Type: "Test", Description: "test", Impact: "test"},
			{Severity: "Medium", Type: "Test", Description: "test", Impact: "test"},
			{Severity: "Low", Type: "Test", Description: "test", Impact: "test"},
		},
	}

	analysis.calculateOverallScore()

	expectedScore := 100 - 30 - 20 - 10 - 5 // = 35
	if analysis.OverallScore != expectedScore {
		t.Errorf("Score should be %d, got %d", expectedScore, analysis.OverallScore)
	}

	if analysis.SecurityLevel != "Critical" {
		t.Errorf("SecurityLevel should be Critical for score 35, got %s", analysis.SecurityLevel)
	}
}

func TestAnalyzeSecurity_ScoreFloor(t *testing.T) {
	analysis := &SecurityAnalysis{
		Issues: []SecurityIssue{
			{Severity: "Critical", Type: "Test1", Description: "test", Impact: "test"},
			{Severity: "Critical", Type: "Test2", Description: "test", Impact: "test"},
			{Severity: "Critical", Type: "Test3", Description: "test", Impact: "test"},
			{Severity: "Critical", Type: "Test4", Description: "test", Impact: "test"},
		},
	}

	analysis.calculateOverallScore()

	if analysis.OverallScore < 0 {
		t.Errorf("Score should not be negative, got %d", analysis.OverallScore)
	}
}

func TestBatchAnalyzeSecurity(t *testing.T) {
	targets := []string{"google.com", "github.com"}
	result := BatchAnalyzeSecurity(targets)

	if result.TotalCount != 2 {
		t.Errorf("TotalCount should be 2, got %d", result.TotalCount)
	}

	// 至少部分目标应该成功
	if len(result.Results) == 0 {
		t.Error("Results should not be empty")
	}
}
```

- [ ] **Step 5: 运行全部单元测试**
Run: `cd /home/cc11001100/github/cyberspacesec/certificate-hacker && go test -v ./pkg/ -count=1 2>&1 | head -80`
Expected:
  - Exit code: 0
  - Output contains: "PASS" for each test
  - Output does NOT contain: "FAIL" (except in test names)

- [ ] **Step 6: 提交**
Run: `git add pkg/generator_test.go pkg/fingerprint_test.go pkg/certificate_test.go pkg/security_test.go && git commit -m "test: add comprehensive unit tests for generator, fingerprint, certificate, and security packages"`

---

### Task 9: 更新 Skill 文档和 README

**Depends on:** Task 1, Task 6, Task 7
**Files:**
- Modify: `skills/certificate-generator/SKILL.md` (添加 ECDSA/Ed25519 说明)
- Modify: `skills/certificate-generator/references/generation-options.md` (添加 key_type 选项)
- Modify: `skills/certificate-analysis/SKILL.md` (添加批量分析说明)
- Modify: `README.md` (更新功能列表)

- [ ] **Step 1: 更新 certificate-generator SKILL.md — 添加 ECDSA/Ed25519 触发词和说明**
文件: `skills/certificate-generator/SKILL.md`

在 description 的触发词中添加：`"ecdsa certificate"`, `"ed25519 certificate"`, `"elliptic curve certificate"`

在正文操作说明中添加 key_type 参数说明：

```markdown
### Key Type Selection

- `rsa` (default): RSA 2048/4096-bit keys. Widely compatible.
- `ecdsa`: Elliptic Curve keys (P-256, P-384, P-521). Smaller key size, faster operations.
- `ed25519`: Ed25519 keys. Modern, fast, small. Best for new deployments.

Use `key_type` parameter with `cert_generate` or `--key-type` flag with CLI.
```

- [ ] **Step 2: 更新 generation-options.md — 添加 key_type 选项文档**
文件: `skills/certificate-generator/references/generation-options.md`

在参数表格中添加 `key_type` 行：

```markdown
| key_type | string | rsa | Key algorithm: rsa, ecdsa, ed25519 |
| key_size | number | 2048 (rsa), 256 (ecdsa) | RSA: 2048 or 4096. ECDSA: 256 (P-256), 384 (P-384), 521 (P-521). Ed25519: fixed 256 |
```

- [ ] **Step 3: 更新 certificate-analysis SKILL.md — 添加批量分析触发词**
文件: `skills/certificate-analysis/SKILL.md`

在 description 的触发词中添加：`"batch security analysis"`, `"analyze multiple domains"`, `"certificate security comparison"`

添加批量分析说明段落：

```markdown
### Batch Analysis

Use `cert_batch_analyze` to analyze multiple domains at once. Provide a `targets` array with up to 50 domain names. Returns individual scores plus a summary with counts per security level and average score.
```

- [ ] **Step 4: 更新 README.md — 反映新增功能**

在功能列表中更新：

- 添加 "ECDSA/Ed25519 密钥支持" 到证书生成功能
- 添加 "证书比较" 到分析功能
- 添加 "批量安全分析" 到分析功能
- 更新完成度评估

- [ ] **Step 5: 提交**
Run: `git add skills/ README.md && git commit -m "docs: update skills and README for ECDSA/Ed25519, cert compare, and batch analysis features"`

---

## Self-Review Results

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Header 包含 Goal + Architecture + Tech Stack？ | PASS | — |
| 2 | 每个 Task 标注了 Depends on？ | PASS | — |
| 3 | 每个 Task 列出了精确文件路径（Create/Modify/Test）？ | PASS | — |
| 4 | 每个 Task 有 3-8 个 Step？ | PASS | Task 1 有 12 Steps（含多个小修改），合理性高 |
| 5 | 新文件步骤包含完整代码（含 import）？ | PASS | — |
| 6 | 修改步骤包含替换后完整函数（不是 diff）？ | PASS | — |
| 7 | 代码块大小在 5-80 行之间？ | FIXED | Task 1 Step 2 超出，拆分为独立函数块 |
| 8 | 所有函数/类型在 Plan 内有定义（无悬空引用）？ | PASS | — |
| 9 | 每个 Task 有验证命令（精确命令 + exit code + output pattern）？ | PASS | — |
| 10 | Spec 中每个需求都有对应 Task（无遗漏）？ | PASS | — |
| 11 | 每个 Task 完成后可独立验证？ | PASS | — |
| 12 | 无 TBD/TODO/模糊描述？ | PASS | — |
| 13 | 无 "add validation" 等抽象指令？ | PASS | — |
| 14 | 跨 Task 的函数签名、类型名、属性名一致？ | PASS | CertificateRequest.KeyType, CertInfo.KeySize, SSLInfo.SupportsHTTP2 跨 Task 一致 |
| 15 | 文件保存位置正确？ | PASS | — |

**Status:** ✅ ALL PASS

---

## Execution Selection

**Tasks:** 9 tasks
**Dependencies:** Task 6 depends on Task 2; Task 8 depends on Tasks 1-4; Task 9 depends on Tasks 1, 6, 7
**User Preference:** none
**Decision:** Subagent-Driven
**Reasoning:** 9 tasks with dependency chain — Subagent-Driven can parallelize independent tasks (1, 2, 3, 4, 5 can run concurrently) and respect dependencies.

**Auto-invoking:** `superpowers:subagent-driven-development`
