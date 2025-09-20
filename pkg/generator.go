package pkg

import (
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
	KeySize          int      `json:"key_size"`          // 密钥长度
	IsCA             bool     `json:"is_ca"`             // 是否为CA证书
	OutputCertPath   string   `json:"output_cert_path"`  // 证书输出路径
	OutputKeyPath    string   `json:"output_key_path"`   // 私钥输出路径
}

// GenerationResult 证书生成结果
type GenerationResult struct {
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
	Fingerprints    map[string]string `json:"fingerprints"`
	Message         string `json:"message"`
}

// GenerateSelfSignedCert 生成自签名证书
func GenerateSelfSignedCert(req CertificateRequest) (*GenerationResult, error) {
	// 设置默认值
	if req.KeySize == 0 {
		req.KeySize = 2048
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
	privateKey, err := rsa.GenerateKey(rand.Reader, req.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
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

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
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

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	err = pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
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
		Message:         fmt.Sprintf("Successfully generated certificate and private key"),
	}

	return result, nil
}

// GenerateCSR 生成证书签名请求 (Certificate Signing Request)
func GenerateCSR(req CertificateRequest) (string, error) {
	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, req.KeySize)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %v", err)
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
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
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
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not RSA")
	}

	rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not RSA")
	}

	if rsaPrivateKey.PublicKey.N.Cmp(rsaPublicKey.N) != 0 {
		return fmt.Errorf("private key and certificate do not match")
	}

	return nil
}
