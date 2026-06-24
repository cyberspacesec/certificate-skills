package pkg

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCRL(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA
	caReq := CertificateRequest{
		CommonName:     "CRL Test CA",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   3650,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "ca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
	}
	GenerateSelfSignedCert(caReq)

	// Generate CRL
	crlReq := CRLGenerateRequest{
		CACertPath: filepath.Join(tmpDir, "ca.pem"),
		CAKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
		RevokedCerts: []RevokedEntry{
			{SerialNumber: "12345", Reason: "key-compromise"},
			{SerialNumber: "67890"},
		},
		NextUpdate: 30,
		Number:     1,
		OutputPath: filepath.Join(tmpDir, "test.crl"),
	}

	result, err := GenerateCRL(crlReq)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v", err)
	}

	if result.RevokedCount != 2 {
		t.Errorf("Expected 2 revoked certs, got %d", result.RevokedCount)
	}

	if result.CRLNumber != 1 {
		t.Errorf("Expected CRL number 1, got %d", result.CRLNumber)
	}

	// Verify CRL file exists
	if _, err := os.Stat(result.CRLPath); os.IsNotExist(err) {
		t.Error("CRL file was not created")
	}
}

func TestParseCRL(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA
	caReq := CertificateRequest{
		CommonName:     "Parse CRL Test CA",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   3650,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "ca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
	}
	GenerateSelfSignedCert(caReq)

	// Generate CRL
	crlReq := CRLGenerateRequest{
		CACertPath: filepath.Join(tmpDir, "ca.pem"),
		CAKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
		RevokedCerts: []RevokedEntry{
			{SerialNumber: "99999", Reason: "superseded"},
		},
		NextUpdate: 30,
		Number:     1,
		OutputPath: filepath.Join(tmpDir, "test.crl"),
	}
	GenerateCRL(crlReq)

	// Parse the CRL
	crlInfo, err := ParseCRL(filepath.Join(tmpDir, "test.crl"))
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	if crlInfo.RevokedCount != 1 {
		t.Errorf("Expected 1 revoked cert, got %d", crlInfo.RevokedCount)
	}

	if len(crlInfo.RevokedCerts) != 1 {
		t.Fatalf("Expected 1 revoked cert entry, got %d", len(crlInfo.RevokedCerts))
	}

	if crlInfo.RevokedCerts[0].SerialNumber != "99999" {
		t.Errorf("Expected serial 99999, got %s", crlInfo.RevokedCerts[0].SerialNumber)
	}

	if crlInfo.RevokedCerts[0].Reason != "superseded" {
		t.Errorf("Expected reason 'superseded', got %s", crlInfo.RevokedCerts[0].Reason)
	}
}

func TestVerifyCRLSignature(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA
	caReq := CertificateRequest{
		CommonName:     "Verify CRL Test CA",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   3650,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "ca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
	}
	GenerateSelfSignedCert(caReq)

	// Generate CRL
	crlReq := CRLGenerateRequest{
		CACertPath: filepath.Join(tmpDir, "ca.pem"),
		CAKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
		NextUpdate: 30,
		Number:     1,
		OutputPath: filepath.Join(tmpDir, "test.crl"),
	}
	GenerateCRL(crlReq)

	// Verify with correct CA
	result, err := VerifyCRLSignature(filepath.Join(tmpDir, "test.crl"), filepath.Join(tmpDir, "ca.pem"))
	if err != nil {
		t.Fatalf("Failed to verify CRL signature: %v", err)
	}

	if !result.IsValid {
		t.Error("CRL signature should be valid for the issuing CA")
	}
}

func TestCheckCertRevokedByCRL(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA
	caReq := CertificateRequest{
		CommonName:     "Revocation Test CA",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   3650,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "ca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
	}
	GenerateSelfSignedCert(caReq)

	// Sign a cert to be revoked
	signReq := SignCertRequest{
		CACertPath:     filepath.Join(tmpDir, "ca.pem"),
		CAKeyPath:      filepath.Join(tmpDir, "ca-key.pem"),
		CommonName:     "revoked.example.com",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		OutputCertPath: filepath.Join(tmpDir, "revoked.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "revoked-key.pem"),
	}
	SignCertificate(signReq)

	// Read the cert to get its serial
	certData, _ := os.ReadFile(filepath.Join(tmpDir, "revoked.pem"))
	block, _ := pem.Decode(certData)
	cert, _ := x509.ParseCertificate(block.Bytes)
	serial := cert.SerialNumber.String()

	// Generate CRL with that serial revoked
	crlReq := CRLGenerateRequest{
		CACertPath: filepath.Join(tmpDir, "ca.pem"),
		CAKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
		RevokedCerts: []RevokedEntry{
			{SerialNumber: serial, Reason: "key-compromise"},
		},
		NextUpdate: 30,
		Number:     1,
		OutputPath: filepath.Join(tmpDir, "test.crl"),
	}
	GenerateCRL(crlReq)

	// Check if the cert is revoked
	result, err := CheckCertRevokedByCRL(filepath.Join(tmpDir, "revoked.pem"), filepath.Join(tmpDir, "test.crl"))
	if err != nil {
		t.Fatalf("Failed to check revocation: %v", err)
	}

	if !result.IsRevoked {
		t.Error("Certificate should be marked as revoked")
	}

	if result.Reason != "key-compromise" {
		t.Errorf("Expected reason 'key-compromise', got '%s'", result.Reason)
	}
}

func TestReasonCodeToString(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{0, "unspecified"},
		{1, "key-compromise"},
		{2, "ca-compromise"},
		{4, "superseded"},
		{10, "aa-compromise"},
		{99, "unknown (99)"},
	}

	for _, tc := range tests {
		result := reasonCodeToString(tc.code)
		if result != tc.expected {
			t.Errorf("reasonCodeToString(%d) = %q, want %q", tc.code, result, tc.expected)
		}
	}
}

func TestGenerateEmptyCRL(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA
	caReq := CertificateRequest{
		CommonName:     "Empty CRL Test CA",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   3650,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "ca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
	}
	GenerateSelfSignedCert(caReq)

	// Generate empty CRL (no revoked certs)
	crlReq := CRLGenerateRequest{
		CACertPath: filepath.Join(tmpDir, "ca.pem"),
		CAKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
		NextUpdate: 30,
		Number:     1,
		OutputPath: filepath.Join(tmpDir, "empty.crl"),
	}

	result, err := GenerateCRL(crlReq)
	if err != nil {
		t.Fatalf("Failed to generate empty CRL: %v", err)
	}

	if result.RevokedCount != 0 {
		t.Errorf("Expected 0 revoked certs, got %d", result.RevokedCount)
	}
}
