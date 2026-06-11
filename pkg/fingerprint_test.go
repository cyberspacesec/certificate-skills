package pkg

import (
	"crypto/x509"
	"encoding/pem"
	"os"
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
	defer os.Remove(result.CertificatePath)
	defer os.Remove(result.PrivateKeyPath)

	// 从文件读取证书获取 x509.Certificate
	certData, err := os.ReadFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
	}
	block, _ := pem.Decode(certData)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

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
		name        string
		fingerprint string
		hashType    string
		expected    bool
	}{
		{"valid sha256 with colons", "ab:cd:ef:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc", "sha256", true},
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

	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer os.Remove(result.CertificatePath)
	defer os.Remove(result.PrivateKeyPath)

	certData, err := os.ReadFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
	}
	block, _ := pem.Decode(certData)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// 同一证书比较应为 true
	if !CompareCertFingerprints(cert, cert) {
		t.Error("Same certificate fingerprints should match")
	}
}