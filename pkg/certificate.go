package pkg

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// BatchResult 批量处理结果
type BatchResult struct {
	Target   string    `json:"target"`
	SSLInfo  *SSLInfo  `json:"ssl_info,omitempty"`
	CertInfo *CertInfo `json:"cert_info,omitempty"`
	Error    error     `json:"error,omitempty"`
}

// CertInfo 证书信息结构体
type CertInfo struct {
	Subject            string            `json:"subject"`
	Issuer             string            `json:"issuer"`
	SerialNumber       string            `json:"serial_number"`
	NotBefore          time.Time         `json:"not_before"`
	NotAfter           time.Time         `json:"not_after"`
	DNSNames           []string          `json:"dns_names"`
	IPAddresses        []string          `json:"ip_addresses"`
	PublicKeyAlgorithm string            `json:"public_key_algorithm"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	KeySize            int               `json:"key_size"`
	KeyUsage           []string          `json:"key_usage"`
	ExtKeyUsage        []string          `json:"ext_key_usage"`
	IsCA               bool              `json:"is_ca"`
	Version            int               `json:"version"`
	Fingerprints       map[string]string `json:"fingerprints"`
}

// CertChain 证书链信息
type CertChain struct {
	Certificates []CertInfo `json:"certificates"`
	ChainLength  int        `json:"chain_length"`
	IsValid      bool       `json:"is_valid"`
	TrustAnchor  string     `json:"trust_anchor"`
}

// SSLInfo SSL连接信息
type SSLInfo struct {
	TLSVersion    string        `json:"tls_version"`
	CipherSuite   string        `json:"cipher_suite"`
	PeerCerts     CertChain     `json:"peer_certificates"`
	ConnectedAt   time.Time     `json:"connected_at"`
	HandshakeTime time.Duration `json:"handshake_time"`
	SupportsHTTP2 bool          `json:"supports_http2"`
	HasOCSPStaple bool          `json:"has_ocsp_staple"`
	OCSPResponse  []byte        `json:"ocsp_response,omitempty"`
}

// GetCertFromDomain 从域名获取证书
func GetCertFromDomain(domain string) (*SSLInfo, error) {
	// 解析域名和端口
	host, port := parseHostPort(domain)

	start := time.Now()

	// 建立TLS连接
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%s", host, port),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:%s: %v", host, port, err)
	}
	defer conn.Close()

	handshakeTime := time.Since(start)

	// 获取连接状态
	state := conn.ConnectionState()

	// 构建证书链信息
	certChain, err := buildCertChain(state.PeerCertificates)
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate chain: %v", err)
	}

	// 检测 HTTP/2 支持：ALPN 协议协商结果包含 h2
	supportsHTTP2 := state.NegotiatedProtocol == "h2"
	hasOCSPStaple := len(state.OCSPResponse) > 0

	// 构建SSL信息
	sslInfo := &SSLInfo{
		TLSVersion:    getTLSVersionName(state.Version),
		CipherSuite:   tls.CipherSuiteName(state.CipherSuite),
		PeerCerts:     *certChain,
		ConnectedAt:   time.Now(),
		HandshakeTime: handshakeTime,
		SupportsHTTP2: supportsHTTP2,
		HasOCSPStaple: hasOCSPStaple,
		OCSPResponse:  state.OCSPResponse,
	}

	return sslInfo, nil
}

// GetCertFromFile 从文件读取证书（支持 PEM 和 DER 格式）
func GetCertFromFile(filename string) (*CertInfo, error) {
	// 读取文件内容
	data, err := os.ReadFile(filename)
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

// buildCertChain 构建证书链信息（包含真实证书链验证）
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

// buildCertInfo 构建证书信息
func buildCertInfo(cert *x509.Certificate) *CertInfo {
	info := &CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DNSNames:           cert.DNSNames,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
		Version:            cert.Version,
		Fingerprints:       make(map[string]string),
	}

	// 提取密钥大小
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeySize = key.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeySize = key.Curve.Params().BitSize
	case ed25519.PublicKey:
		info.KeySize = 256 // Ed25519 固定为 256 位
	}

	// 转换IP地址为字符串
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	// 解析密钥用途
	info.KeyUsage = parseKeyUsage(cert.KeyUsage)
	info.ExtKeyUsage = parseExtKeyUsage(cert.ExtKeyUsage)

	// 生成指纹
	info.Fingerprints = GenerateFingerprints(cert)

	return info
}

// parseHostPort 解析主机名和端口 (支持 IPv6 地址如 [::1]:443)
func parseHostPort(addr string) (host, port string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// No port specified, use default 443
		return addr, "443"
	}
	return host, port
}

// IsFileTarget checks if a target string looks like a file path.
func IsFileTarget(target string) bool {
	fileExts := []string{".pem", ".crt", ".cer", ".der", ".p7b", ".p7c"}
	for _, ext := range fileExts {
		if strings.HasSuffix(strings.ToLower(target), ext) {
			return true
		}
	}
	return false
}

// getTLSVersionName 获取TLS版本名称
func getTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// parseKeyUsage 解析密钥用途
func parseKeyUsage(usage x509.KeyUsage) []string {
	var usages []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}

	return usages
}

// parseExtKeyUsage 解析扩展密钥用途
func parseExtKeyUsage(usage []x509.ExtKeyUsage) []string {
	var usages []string

	for _, u := range usage {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		}
	}

	return usages
}
