package pkg

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// CertComparison 证书比较结果
type CertComparison struct {
	Match        bool             `json:"match"`
	MatchDetails MatchDetails     `json:"match_details"`
	Cert1Summary CertSummary      `json:"cert1_summary"`
	Cert2Summary CertSummary      `json:"cert2_summary"`
	Differences  []CertDifference `json:"differences"`
}

// MatchDetails 匹配详情
type MatchDetails struct {
	SHA256Match    bool `json:"sha256_match"`
	PublicKeyMatch bool `json:"public_key_match"`
	SubjectMatch   bool `json:"subject_match"`
	IssuerMatch    bool `json:"issuer_match"`
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

// CompareCerts 比较两个 x509.Certificate 对象
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
	conn1, err := TLSDial(domain1)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", domain1, err)
	}
	defer conn1.Close()

	conn2, err := TLSDial(domain2)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", domain2, err)
	}
	defer conn2.Close()

	certs1 := conn1.ConnectionState().PeerCertificates
	certs2 := conn2.ConnectionState().PeerCertificates

	if len(certs1) == 0 {
		return nil, fmt.Errorf("no certificates found for %s", domain1)
	}
	if len(certs2) == 0 {
		return nil, fmt.Errorf("no certificates found for %s", domain2)
	}

	return CompareCerts(certs1[0], certs2[0]), nil
}

// CompareCertsFromFiles 从两个文件读取证书并比较
func CompareCertsFromFiles(file1, file2 string) (*CertComparison, error) {
	cert1, err := ReadCertFromFile(file1)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert from %s: %v", file1, err)
	}

	cert2, err := ReadCertFromFile(file2)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert from %s: %v", file2, err)
	}

	return CompareCerts(cert1, cert2), nil
}

// ReadCertFromFile 从文件读取原始 x509.Certificate 对象（公开函数，供 MCP handler 等模块复用）
func ReadCertFromFile(filename string) (*x509.Certificate, error) {
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
