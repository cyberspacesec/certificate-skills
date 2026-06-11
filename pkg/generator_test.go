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

func TestValidateCertificateFiles_RSA(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-validate-rsa",
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
		t.Errorf("ValidateCertificateFiles RSA failed: %v", err)
	}
}

func TestValidateCertificateFiles_ECDSA(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-validate-ecdsa",
		KeyType:      "ecdsa",
		KeySize:      256,
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
		t.Errorf("ValidateCertificateFiles ECDSA failed: %v", err)
	}
}

func TestValidateCertificateFiles_Ed25519(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-validate-ed25519",
		KeyType:      "ed25519",
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
		t.Errorf("ValidateCertificateFiles Ed25519 failed: %v", err)
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

func TestGenerateCSR_ECDSA(t *testing.T) {
	req := CertificateRequest{
		CommonName: "test-csr-ecdsa.example.com",
		KeyType:    "ecdsa",
		KeySize:    256,
	}

	csrPEM, err := GenerateCSR(req)
	if err != nil {
		t.Fatalf("GenerateCSR ECDSA failed: %v", err)
	}

	if csrPEM == "" {
		t.Error("CSR PEM should not be empty")
	}
}
