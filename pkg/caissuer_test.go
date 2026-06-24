package pkg

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSelfSignedCACert(t *testing.T) {
	tmpDir := t.TempDir()

	// First generate a root CA
	req := CertificateRequest{
		CommonName:     "Test Root CA",
		Organization:   "Test Org",
		Country:        "US",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   3650,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "root-ca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "root-ca-key.pem"),
	}

	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	if result.CertificatePath != req.OutputCertPath {
		t.Errorf("Expected cert path %s, got %s", req.OutputCertPath, result.CertificatePath)
	}

	// Verify the generated CA cert
	certData, err := os.ReadFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("Failed to decode CA cert PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}

	if !caCert.IsCA {
		t.Error("Generated CA cert should have IsCA=true")
	}

	if caCert.Subject.CommonName != "Test Root CA" {
		t.Errorf("Expected CN 'Test Root CA', got '%s'", caCert.Subject.CommonName)
	}
}

func TestSignCertificateWithCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate root CA
	caReq := CertificateRequest{
		CommonName:     "Test Root CA",
		Organization:   "Test Org",
		Country:        "US",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   3650,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "root-ca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "root-ca-key.pem"),
	}

	_, err := GenerateSelfSignedCert(caReq)
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// Sign a server certificate
	signReq := SignCertRequest{
		CACertPath:     filepath.Join(tmpDir, "root-ca.pem"),
		CAKeyPath:      filepath.Join(tmpDir, "root-ca-key.pem"),
		CommonName:     "server.example.com",
		DNSNames:       []string{"server.example.com", "www.example.com"},
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		KeyUsage:       "server",
		OutputCertPath: filepath.Join(tmpDir, "server.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "server-key.pem"),
	}

	result, err := SignCertificate(signReq)
	if err != nil {
		t.Fatalf("Failed to sign certificate: %v", err)
	}

	if result.CASubject == "" {
		t.Error("CA subject should not be empty")
	}

	if result.IssuedSubject == "" {
		t.Error("Issued subject should not be empty")
	}

	if result.SerialNumber == "" {
		t.Error("Serial number should not be empty")
	}

	// Verify the signed cert
	certData, err := os.ReadFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("Failed to read signed cert: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("Failed to decode signed cert PEM")
	}

	signedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse signed cert: %v", err)
	}

	if signedCert.Subject.CommonName != "server.example.com" {
		t.Errorf("Expected CN 'server.example.com', got '%s'", signedCert.Subject.CommonName)
	}

	if signedCert.Issuer.CommonName != "Test Root CA" {
		t.Errorf("Expected issuer CN 'Test Root CA', got '%s'", signedCert.Issuer.CommonName)
	}

	if signedCert.IsCA {
		t.Error("Signed cert should not be a CA")
	}

	// Verify key usage
	foundServerAuth := false
	for _, eku := range signedCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			foundServerAuth = true
		}
	}
	if !foundServerAuth {
		t.Error("Server cert should have ServerAuth extended key usage")
	}
}

func TestSignClientCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate root CA
	caReq := CertificateRequest{
		CommonName:     "Test CA",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "ca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ca-key.pem"),
	}
	GenerateSelfSignedCert(caReq)

	signReq := SignCertRequest{
		CACertPath:     filepath.Join(tmpDir, "ca.pem"),
		CAKeyPath:      filepath.Join(tmpDir, "ca-key.pem"),
		CommonName:     "client.example.com",
		KeyUsage:       "client",
		KeyType:        "ecdsa",
		KeySize:        256,
		ValidityDays:   365,
		OutputCertPath: filepath.Join(tmpDir, "client.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "client-key.pem"),
	}

	result, err := SignCertificate(signReq)
	if err != nil {
		t.Fatalf("Failed to sign client cert: %v", err)
	}

	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	signedCert, _ := x509.ParseCertificate(block.Bytes)

	foundClientAuth := false
	for _, eku := range signedCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			foundClientAuth = true
		}
	}
	if !foundClientAuth {
		t.Error("Client cert should have ClientAuth extended key usage")
	}
}

func TestSignCertificateInvalidCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a non-CA cert
	nonCAReq := CertificateRequest{
		CommonName:     "Not a CA",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		IsCA:           false,
		OutputCertPath: filepath.Join(tmpDir, "nonca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "nonca-key.pem"),
	}
	GenerateSelfSignedCert(nonCAReq)

	signReq := SignCertRequest{
		CACertPath:     filepath.Join(tmpDir, "nonca.pem"),
		CAKeyPath:      filepath.Join(tmpDir, "nonca-key.pem"),
		CommonName:     "test",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		OutputCertPath: filepath.Join(tmpDir, "test.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "test-key.pem"),
	}

	_, err := SignCertificate(signReq)
	if err == nil {
		t.Error("Should fail when signing with a non-CA certificate")
	}
}

func TestGenerateIntermediateCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate root CA
	rootReq := CertificateRequest{
		CommonName:     "Root CA",
		Organization:   "Test Org",
		Country:        "US",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   3650,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "root.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "root-key.pem"),
	}
	GenerateSelfSignedCert(rootReq)

	// Generate intermediate CA
	intReq := IntermediateCARequest{
		ParentCertPath:    filepath.Join(tmpDir, "root.pem"),
		ParentKeyPath:     filepath.Join(tmpDir, "root-key.pem"),
		CommonName:        "Intermediate CA",
		KeyType:           "rsa",
		KeySize:           2048,
		ValidityDays:      1825,
		PathLenConstraint: 0,
		OutputCertPath:    filepath.Join(tmpDir, "intermediate.pem"),
		OutputKeyPath:     filepath.Join(tmpDir, "intermediate-key.pem"),
	}

	result, err := GenerateIntermediateCA(intReq)
	if err != nil {
		t.Fatalf("Failed to generate intermediate CA: %v", err)
	}

	if result.CASubject == "" {
		t.Error("CA subject should not be empty")
	}

	// Verify intermediate CA cert
	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	intCert, _ := x509.ParseCertificate(block.Bytes)

	if !intCert.IsCA {
		t.Error("Intermediate cert should be a CA")
	}

	if intCert.Issuer.CommonName != "Root CA" {
		t.Errorf("Expected issuer 'Root CA', got '%s'", intCert.Issuer.CommonName)
	}

	if intCert.MaxPathLen != 0 {
		t.Errorf("Expected MaxPathLen=0, got %d", intCert.MaxPathLen)
	}

	if !intCert.MaxPathLenZero {
		t.Error("MaxPathLenZero should be true")
	}
}

func TestSignCertWithIntermediateCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate root CA
	rootReq := CertificateRequest{
		CommonName:     "Root CA",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   3650,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "root.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "root-key.pem"),
	}
	GenerateSelfSignedCert(rootReq)

	// Generate intermediate CA
	intReq := IntermediateCARequest{
		ParentCertPath:    filepath.Join(tmpDir, "root.pem"),
		ParentKeyPath:     filepath.Join(tmpDir, "root-key.pem"),
		CommonName:        "Intermediate CA",
		KeyType:           "rsa",
		KeySize:           2048,
		ValidityDays:      1825,
		PathLenConstraint: 0,
		OutputCertPath:    filepath.Join(tmpDir, "intermediate.pem"),
		OutputKeyPath:     filepath.Join(tmpDir, "intermediate-key.pem"),
	}
	GenerateIntermediateCA(intReq)

	// Sign a leaf cert with intermediate CA
	signReq := SignCertRequest{
		CACertPath:     filepath.Join(tmpDir, "intermediate.pem"),
		CAKeyPath:      filepath.Join(tmpDir, "intermediate-key.pem"),
		CommonName:     "leaf.example.com",
		KeyType:        "rsa",
		KeySize:        2048,
		ValidityDays:   365,
		OutputCertPath: filepath.Join(tmpDir, "leaf.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "leaf-key.pem"),
	}

	result, err := SignCertificate(signReq)
	if err != nil {
		t.Fatalf("Failed to sign with intermediate CA: %v", err)
	}

	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	leafCert, _ := x509.ParseCertificate(block.Bytes)

	if leafCert.Issuer.CommonName != "Intermediate CA" {
		t.Errorf("Expected issuer 'Intermediate CA', got '%s'", leafCert.Issuer.CommonName)
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"My CA", "My_CA"},
		{"test.pem", "test.pem"},
		{"hello world", "hello_world"},
		{"ca/cert", "ca_cert"},
		{"", "cert"},
		{"simple", "simple"},
		{"example.com:8443", "example.com_8443"},
	}

	for _, tc := range tests {
		result := sanitizeFilename(tc.input)
		if result != tc.expected {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestNonEmptySlice(t *testing.T) {
	tests := []struct {
		val      string
		fallback []string
		expected []string
	}{
		{"", []string{"fallback"}, []string{"fallback"}},
		{"value", []string{"fallback"}, []string{"value"}},
		{"", nil, nil},
	}

	for _, tc := range tests {
		result := nonEmptySlice(tc.val, tc.fallback)
		if len(result) != len(tc.expected) {
			t.Errorf("nonEmptySlice(%q, %v) length = %d, want %d", tc.val, tc.fallback, len(result), len(tc.expected))
			continue
		}
		for i := range result {
			if result[i] != tc.expected[i] {
				t.Errorf("nonEmptySlice(%q, %v)[%d] = %q, want %q", tc.val, tc.fallback, i, result[i], tc.expected[i])
			}
		}
	}
}

func TestSignCertificateWithEd25519(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate root CA with Ed25519
	caReq := CertificateRequest{
		CommonName:     "Ed25519 CA",
		KeyType:        "ed25519",
		ValidityDays:   365,
		IsCA:           true,
		OutputCertPath: filepath.Join(tmpDir, "ed25519-ca.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ed25519-ca-key.pem"),
	}
	GenerateSelfSignedCert(caReq)

	signReq := SignCertRequest{
		CACertPath:     filepath.Join(tmpDir, "ed25519-ca.pem"),
		CAKeyPath:      filepath.Join(tmpDir, "ed25519-ca-key.pem"),
		CommonName:     "ed25519-server.example.com",
		KeyType:        "ed25519",
		ValidityDays:   365,
		OutputCertPath: filepath.Join(tmpDir, "ed25519-server.pem"),
		OutputKeyPath:  filepath.Join(tmpDir, "ed25519-server-key.pem"),
	}

	result, err := SignCertificate(signReq)
	if err != nil {
		t.Fatalf("Failed to sign Ed25519 cert: %v", err)
	}

	certData, _ := os.ReadFile(result.CertificatePath)
	block, _ := pem.Decode(certData)
	signedCert, _ := x509.ParseCertificate(block.Bytes)

	if signedCert.PublicKeyAlgorithm.String() != "Ed25519" {
		t.Errorf("Expected Ed25519, got %s", signedCert.PublicKeyAlgorithm)
	}
}
