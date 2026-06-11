package pkg

import (
	"fmt"
	"strings"
	"time"
)

// SecurityAnalysis 安全分析结果
type SecurityAnalysis struct {
	Target           string           `json:"target"`
	OverallScore     int              `json:"overall_score"`     // 总体安全评分 (0-100)
	SecurityLevel    string           `json:"security_level"`    // 安全等级: Critical, High, Medium, Low, Good
	Issues           []SecurityIssue  `json:"issues"`            // 发现的安全问题
	Recommendations  []string         `json:"recommendations"`   // 安全建议
	CertificateCheck CertificateCheck `json:"certificate_check"` // 证书检查结果
	TLSCheck         TLSCheck         `json:"tls_check"`         // TLS检查结果
	ExpirationCheck  ExpirationCheck  `json:"expiration_check"`  // 过期检查
}

// SecurityIssue 安全问题
type SecurityIssue struct {
	Severity    string `json:"severity"`    // Critical, High, Medium, Low
	Type        string `json:"type"`        // 问题类型
	Description string `json:"description"` // 问题描述
	Impact      string `json:"impact"`      // 影响描述
}

// CertificateCheck 证书检查结果
type CertificateCheck struct {
	IsValid          bool     `json:"is_valid"`
	IsSelfSigned     bool     `json:"is_self_signed"`
	IsExpired        bool     `json:"is_expired"`
	IsExpiringSoon   bool     `json:"is_expiring_soon"`
	DaysUntilExpiry  int      `json:"days_until_expiry"`
	KeySize          int      `json:"key_size"`
	SignatureAlg     string   `json:"signature_algorithm"`
	WeakSignature    bool     `json:"weak_signature"`
	HasSAN           bool     `json:"has_san"`
	SANCount         int      `json:"san_count"`
	WildcardCert     bool     `json:"wildcard_cert"`
	Warnings         []string `json:"warnings"`
}

// TLSCheck TLS连接检查结果
type TLSCheck struct {
	Version             string   `json:"version"`
	CipherSuite         string   `json:"cipher_suite"`
	IsSecureVersion     bool     `json:"is_secure_version"`
	IsSecureCipherSuite bool     `json:"is_secure_cipher_suite"`
	SupportsHTTP2       bool     `json:"supports_http2"`
	Warnings            []string `json:"warnings"`
}

// ExpirationCheck 过期检查
type ExpirationCheck struct {
	DaysUntilExpiry int    `json:"days_until_expiry"`
	ExpirationDate  string `json:"expiration_date"`
	Status          string `json:"status"` // Expired, Critical, Warning, Good
	Message         string `json:"message"`
}

// BatchSecurityAnalysis 批量安全分析
type BatchSecurityAnalysis struct {
	Results    []SecurityAnalysis `json:"results"`
	TotalCount int                `json:"total_count"`
	Summary    BatchSummary       `json:"summary"`
}

// BatchSummary 批量分析摘要
type BatchSummary struct {
	GoodCount     int `json:"good_count"`
	MediumCount   int `json:"medium_count"`
	HighCount     int `json:"high_count"`
	CriticalCount int `json:"critical_count"`
	AverageScore  int `json:"average_score"`
}

// AnalyzeSecurity 执行安全分析
func AnalyzeSecurity(target string) (*SecurityAnalysis, error) {
	analysis := &SecurityAnalysis{
		Target:          target,
		Issues:          []SecurityIssue{},
		Recommendations: []string{},
	}

	// 获取SSL信息
	sslInfo, err := GetCertFromDomain(target)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSL info: %v", err)
	}

	if len(sslInfo.PeerCerts.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := sslInfo.PeerCerts.Certificates[0]

	// 执行各项检查
	analysis.CertificateCheck = analyzeCertificate(&cert)
	analysis.TLSCheck = analyzeTLS(sslInfo)
	analysis.ExpirationCheck = analyzeExpiration(&cert)

	// 收集安全问题
	analysis.collectSecurityIssues()

	// 计算总体评分
	analysis.calculateOverallScore()

	// 生成安全建议
	analysis.generateRecommendations()

	return analysis, nil
}

// analyzeCertificate 分析证书安全性
func analyzeCertificate(cert *CertInfo) CertificateCheck {
	check := CertificateCheck{
		IsValid:      true,
		SignatureAlg: cert.SignatureAlgorithm,
		KeySize:      cert.KeySize,
		HasSAN:       len(cert.DNSNames) > 0,
		SANCount:     len(cert.DNSNames),
		Warnings:     []string{},
	}

	// 检查是否过期
	now := time.Now()
	check.IsExpired = now.After(cert.NotAfter)
	check.DaysUntilExpiry = int(cert.NotAfter.Sub(now).Hours() / 24)
	check.IsExpiringSoon = check.DaysUntilExpiry <= 30 && check.DaysUntilExpiry > 0

	// 检查签名算法安全性
	weakSignatures := []string{"MD5", "SHA1"}
	for _, weak := range weakSignatures {
		if strings.Contains(strings.ToUpper(cert.SignatureAlgorithm), weak) {
			check.WeakSignature = true
			check.Warnings = append(check.Warnings, fmt.Sprintf("Weak signature algorithm: %s", cert.SignatureAlgorithm))
			break
		}
	}

	// 检查是否为通配符证书
	for _, dnsName := range cert.DNSNames {
		if strings.HasPrefix(dnsName, "*.") {
			check.WildcardCert = true
			break
		}
	}

	// 检查是否自签名
	if cert.Subject == cert.Issuer {
		check.IsSelfSigned = true
		check.Warnings = append(check.Warnings, "Self-signed certificate detected")
	}

	return check
}

// analyzeTLS 分析TLS连接安全性
func analyzeTLS(sslInfo *SSLInfo) TLSCheck {
	check := TLSCheck{
		Version:        sslInfo.TLSVersion,
		CipherSuite:   sslInfo.CipherSuite,
		SupportsHTTP2:  sslInfo.SupportsHTTP2,
		Warnings:      []string{},
	}

	// 检查TLS版本安全性
	secureVersions := []string{"TLS 1.2", "TLS 1.3"}
	check.IsSecureVersion = false
	for _, version := range secureVersions {
		if sslInfo.TLSVersion == version {
			check.IsSecureVersion = true
			break
		}
	}

	if !check.IsSecureVersion {
		check.Warnings = append(check.Warnings, fmt.Sprintf("Insecure TLS version: %s", sslInfo.TLSVersion))
	}

	// 检查加密套件安全性（简化检查）
	cipherSuite := strings.ToUpper(sslInfo.CipherSuite)
	check.IsSecureCipherSuite = true

	// 检查弱加密套件
	weakCiphers := []string{"RC4", "DES", "3DES", "NULL", "EXPORT"}
	for _, weak := range weakCiphers {
		if strings.Contains(cipherSuite, weak) {
			check.IsSecureCipherSuite = false
			check.Warnings = append(check.Warnings, fmt.Sprintf("Weak cipher suite: %s", sslInfo.CipherSuite))
			break
		}
	}

	return check
}

// analyzeExpiration 分析证书过期情况
func analyzeExpiration(cert *CertInfo) ExpirationCheck {
	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	check := ExpirationCheck{
		DaysUntilExpiry: daysUntilExpiry,
		ExpirationDate:  cert.NotAfter.Format("2006-01-02 15:04:05 UTC"),
	}

	if daysUntilExpiry < 0 {
		check.Status = "Expired"
		check.Message = fmt.Sprintf("Certificate expired %d days ago", -daysUntilExpiry)
	} else if daysUntilExpiry <= 7 {
		check.Status = "Critical"
		check.Message = fmt.Sprintf("Certificate expires in %d days - URGENT renewal required", daysUntilExpiry)
	} else if daysUntilExpiry <= 30 {
		check.Status = "Warning"
		check.Message = fmt.Sprintf("Certificate expires in %d days - renewal recommended", daysUntilExpiry)
	} else {
		check.Status = "Good"
		check.Message = fmt.Sprintf("Certificate expires in %d days", daysUntilExpiry)
	}

	return check
}

// collectSecurityIssues 收集安全问题
func (analysis *SecurityAnalysis) collectSecurityIssues() {
	// 证书相关问题
	if analysis.CertificateCheck.IsExpired {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "Critical",
			Type:        "Certificate Expired",
			Description: "The certificate has expired",
			Impact:      "Users will see security warnings and may not be able to connect",
		})
	}

	if analysis.CertificateCheck.IsExpiringSoon {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "High",
			Type:        "Certificate Expiring Soon",
			Description: fmt.Sprintf("Certificate expires in %d days", analysis.CertificateCheck.DaysUntilExpiry),
			Impact:      "Certificate will expire soon, causing service disruption",
		})
	}

	if analysis.CertificateCheck.WeakSignature {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "High",
			Type:        "Weak Signature Algorithm",
			Description: fmt.Sprintf("Using weak signature algorithm: %s", analysis.CertificateCheck.SignatureAlg),
			Impact:      "Certificate may be vulnerable to cryptographic attacks",
		})
	}

	if analysis.CertificateCheck.IsSelfSigned {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "Medium",
			Type:        "Self-Signed Certificate",
			Description: "Certificate is self-signed",
			Impact:      "Users will see security warnings and trust may be compromised",
		})
	}

	// TLS相关问题
	if !analysis.TLSCheck.IsSecureVersion {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "High",
			Type:        "Insecure TLS Version",
			Description: fmt.Sprintf("Using insecure TLS version: %s", analysis.TLSCheck.Version),
			Impact:      "Connection may be vulnerable to protocol downgrade attacks",
		})
	}

	if !analysis.TLSCheck.IsSecureCipherSuite {
		analysis.Issues = append(analysis.Issues, SecurityIssue{
			Severity:    "High",
			Type:        "Weak Cipher Suite",
			Description: fmt.Sprintf("Using weak cipher suite: %s", analysis.TLSCheck.CipherSuite),
			Impact:      "Encrypted data may be vulnerable to cryptographic attacks",
		})
	}
}

// calculateOverallScore 计算总体安全评分
func (analysis *SecurityAnalysis) calculateOverallScore() {
	score := 100

	for _, issue := range analysis.Issues {
		switch issue.Severity {
		case "Critical":
			score -= 30
		case "High":
			score -= 20
		case "Medium":
			score -= 10
		case "Low":
			score -= 5
		}
	}

	if score < 0 {
		score = 0
	}

	analysis.OverallScore = score

	// 确定安全等级
	if score >= 90 {
		analysis.SecurityLevel = "Good"
	} else if score >= 70 {
		analysis.SecurityLevel = "Medium"
	} else if score >= 50 {
		analysis.SecurityLevel = "High"
	} else {
		analysis.SecurityLevel = "Critical"
	}
}

// generateRecommendations 生成安全建议
func (analysis *SecurityAnalysis) generateRecommendations() {
	recommendations := []string{}

	if analysis.CertificateCheck.IsExpired || analysis.CertificateCheck.IsExpiringSoon {
		recommendations = append(recommendations, "Renew the certificate immediately to avoid service disruption")
	}

	if analysis.CertificateCheck.WeakSignature {
		recommendations = append(recommendations, "Upgrade to a certificate with SHA-256 or higher signature algorithm")
	}

	if analysis.CertificateCheck.IsSelfSigned {
		recommendations = append(recommendations, "Replace self-signed certificate with one from a trusted CA")
	}

	if !analysis.TLSCheck.IsSecureVersion {
		recommendations = append(recommendations, "Upgrade to TLS 1.2 or TLS 1.3")
		recommendations = append(recommendations, "Disable support for older TLS versions (TLS 1.0, TLS 1.1)")
	}

	if !analysis.TLSCheck.IsSecureCipherSuite {
		recommendations = append(recommendations, "Configure secure cipher suites (AES-GCM, ChaCha20-Poly1305)")
		recommendations = append(recommendations, "Disable weak cipher suites (RC4, 3DES, NULL ciphers)")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Certificate and TLS configuration appear to be secure")
		recommendations = append(recommendations, "Continue monitoring certificate expiration dates")
		recommendations = append(recommendations, "Regularly review and update TLS configuration")
	}

	analysis.Recommendations = recommendations
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
				Target:        target,
				OverallScore:  0,
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
