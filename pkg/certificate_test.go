package pkg

import (
	"encoding/pem"
	"os"
	"testing"
)

func TestGetCertFromFile_PEM(t *testing.T) {
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
	tmpFile, err := os.CreateTemp("", "invalid-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("this is not a certificate")
	tmpFile.Close()

	_, err = GetCertFromFile(tmpFile.Name())
	if err == nil {
		t.Error("Expected error for invalid certificate file")
	}
}

func TestGetCertFromFile_DER(t *testing.T) {
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
	pemData, err := os.ReadFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("Failed to read PEM file: %v", err)
	}
	block, _ := pem.Decode(pemData)

	derFile, err := os.CreateTemp("", "test-der-*.crt")
	if err != nil {
		t.Fatalf("Failed to create temp DER file: %v", err)
	}
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
	if certInfo.KeySize == 0 {
		t.Error("KeySize should not be zero for DER cert")
	}
}

func TestGetCertFromFile_ECDSA_DER(t *testing.T) {
	req := CertificateRequest{
		CommonName:   "test-ecdsa-der",
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

	// 将 PEM 转为 DER
	pemData, err := os.ReadFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("Failed to read PEM file: %v", err)
	}
	block, _ := pem.Decode(pemData)

	derFile, err := os.CreateTemp("", "test-ecdsa-der-*.crt")
	if err != nil {
		t.Fatalf("Failed to create temp DER file: %v", err)
	}
	defer os.Remove(derFile.Name())
	derFile.Write(block.Bytes)
	derFile.Close()

	certInfo, err := GetCertFromFile(derFile.Name())
	if err != nil {
		t.Fatalf("GetCertFromFile ECDSA DER failed: %v", err)
	}

	if certInfo.KeySize != 256 {
		t.Errorf("Expected KeySize 256 for ECDSA P-256, got %d", certInfo.KeySize)
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
		t.Run(tt.input, func(t *testing.T) {
			host, port := parseHostPort(tt.input)
			result := host + ":" + port
			if result != tt.expected {
				t.Errorf("parseHostPort(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}