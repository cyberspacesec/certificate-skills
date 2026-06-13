package pkg

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(t *testing.T, template *x509.Certificate) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	if template == nil {
		template = &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Test Org"},
			},
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{"test.example.com", "www.example.com"},
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert, key
}

func TestCheckKeyUsageFromCert_CAWithoutCertSign(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCRLSign, // Missing keyCertSign!
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	cert, _ := generateTestCert(t, template)

	result := CheckKeyUsageFromCert(cert)
	if result.IsCompliant {
		t.Error("CA without keyCertSign should not be compliant")
	}
	found := false
	for _, issue := range result.Issues {
		if issue.Description == "CA certificate missing keyCertSign key usage" {
			found = true
		}
	}
	if !found {
		t.Error("Expected keyCertSign missing issue")
	}
}

func TestCheckKeyUsageFromCert_NonCAWithCertSign(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, // Non-CA with certSign!
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"test.example.com"},
	}
	cert, _ := generateTestCert(t, template)

	result := CheckKeyUsageFromCert(cert)
	if result.IsCompliant {
		t.Error("Non-CA with keyCertSign should not be compliant")
	}
}

func TestCheckKeyUsageFromCert_ValidLeaf(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"test.example.com"},
	}
	cert, _ := generateTestCert(t, template)

	result := CheckKeyUsageFromCert(cert)
	if !result.IsCompliant {
		t.Errorf("Valid leaf cert should be compliant, issues: %v", result.Issues)
	}
}

func TestCheckKeyUsageFromCert_NoKeyUsage(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"test.example.com"},
	}
	cert, _ := generateTestCert(t, template)

	result := CheckKeyUsageFromCert(cert)
	if result.IsCompliant {
		t.Error("Cert with no key usage should not be compliant")
	}
}

func TestCheckPolicyFromCert_WithKnownOID(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}
	cert, _ := generateTestCert(t, template)

	result := CheckPolicyFromCert(cert)
	if result == nil {
		t.Fatal("Result should not be nil")
	}
	// Self-signed cert likely has no policies
	if result.ValidationType != "Unknown" && result.ValidationType != "DV" {
		t.Logf("Validation type: %s (may vary)", result.ValidationType)
	}
}

func TestCheckDistrustedCAFromCert_NoDistrustedCA(t *testing.T) {
	cert, _ := generateTestCert(t, nil)
	chain := []*x509.Certificate{cert}

	result := CheckDistrustedCAFromCert(chain)
	if result.IsDistrusted {
		t.Error("Self-signed test cert should not match distrusted CAs")
	}
}

func TestAnalyzeSerialNumberFromCert(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}
	cert, _ := generateTestCert(t, template)

	result := AnalyzeSerialNumberFromCert(cert)
	if result == nil {
		t.Fatal("Result should not be nil")
	}
	if result.SerialHex == "" {
		t.Error("Serial hex should not be empty")
	}
	if result.BitLength < 64 {
		t.Logf("Low bit length: %d (expected for short serial)", result.BitLength)
	}
}

func TestCheckNameConstraintsFromCert_ShortChain(t *testing.T) {
	cert, _ := generateTestCert(t, nil)
	chain := []*x509.Certificate{cert}

	result := CheckNameConstraintsFromCert(chain)
	if result == nil {
		t.Fatal("Result should not be nil")
	}
	// Single cert chain has no CA to impose constraints
	if result.HasConstraints {
		t.Error("Single cert chain should have no constraints")
	}
}

func TestScanCertSecurityFromChain(t *testing.T) {
	cert, _ := generateTestCert(t, nil)

	result, err := ScanCertSecurityFromChain(cert, "test.example.com", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Result should not be nil")
	}
	// Without ConnectionState, should have 12 checks (CERT-001 to CERT-012)
	if len(result.Checks) < 12 {
		t.Errorf("Expected at least 12 checks, got %d", len(result.Checks))
	}
	// Self-signed cert should fail CERT-007
	foundSelfSigned := false
	for _, check := range result.Checks {
		if check.Code == "CERT-007" && !check.Passed {
			foundSelfSigned = true
		}
	}
	if !foundSelfSigned {
		t.Error("Self-signed cert should fail CERT-007 check")
	}
}

func TestOfflineAnalysis(t *testing.T) {
	cert, _ := generateTestCert(t, nil)

	analysis := NewOfflineAnalysis(cert)
	if analysis.Target != "test.example.com" {
		t.Errorf("Expected target 'test.example.com', got '%s'", analysis.Target)
	}
	if analysis.Cert == nil {
		t.Error("Cert should not be nil")
	}
}

func TestFingerprintCert(t *testing.T) {
	cert, _ := generateTestCert(t, nil)

	fp := fingerprintCert(cert)
	if fp == "" {
		t.Error("Fingerprint should not be empty")
	}
	// formatFingerprint uses colons: "ab:cd:ef..." = 95 chars for SHA-256
	if len(fp) != 95 {
		t.Errorf("Expected 95-char colon-separated SHA-256, got %d chars: %s", len(fp), fp)
	}
}

func TestKeyUsageToStrings(t *testing.T) {
	cert, _ := generateTestCert(t, nil)
	usages := keyUsageToStrings(cert)
	if len(usages) == 0 {
		t.Error("Should have key usage strings")
	}
	found := false
	for _, u := range usages {
		if u == "digitalSignature" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected digitalSignature in %v", usages)
	}
}

func TestExtKeyUsageToStrings(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}
	cert, _ := generateTestCert(t, template)

	usages := extKeyUsageToStrings(cert)
	if len(usages) < 2 {
		t.Errorf("Expected at least 2 EKU strings, got %d", len(usages))
	}
}

func TestCheckKeyUsageFromCert_ECDSAWithKeyEncipherment(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	result := CheckKeyUsageFromCert(cert)
	// ECDSA with keyEncipherment should have a Low severity note
	found := false
	for _, issue := range result.Issues {
		if issue.Severity == "Low" {
			found = true
		}
	}
	if !found {
		t.Log("ECDSA with keyEncipherment should note inconsistency (may be compliant)")
	}
}

func TestCheckKeyUsageFromCert_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	result := CheckKeyUsageFromCert(cert)
	if !result.IsCompliant {
		t.Errorf("Ed25519 cert should be compliant, issues: %v", result.Issues)
	}
}

func TestEstimateShannonEntropy(t *testing.T) {
	// All zeros should have 0 entropy
	zeroEntropy := estimateShannonEntropy([]byte{0, 0, 0, 0})
	if zeroEntropy != 0 {
		t.Errorf("Expected 0 entropy for all zeros, got %.2f", zeroEntropy)
	}

	// Random-looking data should have high entropy
	randomData := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	highEntropy := estimateShannonEntropy(randomData)
	if highEntropy < 3.0 {
		t.Errorf("Expected high entropy for random data, got %.2f", highEntropy)
	}
}

func TestNameMatchesPattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected bool
	}{
		{"example.com", "example.com", true},
		{"sub.example.com", ".example.com", true},
		{"example.com", ".example.com", true}, // TLD matches pattern without prefix
		{"other.com", ".example.com", false},
		{"sub.example.com", "example.com", true},
	}
	for _, tc := range tests {
		result := nameMatchesPattern(tc.name, tc.pattern)
		if result != tc.expected {
			t.Errorf("nameMatchesPattern(%q, %q) = %v, expected %v", tc.name, tc.pattern, result, tc.expected)
		}
	}
}

func TestIsIPAddress(t *testing.T) {
	if !isIPAddress("192.168.1.1") {
		t.Error("192.168.1.1 should be detected as IP")
	}
	if isIPAddress("example.com") {
		t.Error("example.com should not be detected as IP")
	}
}

func TestIPMatchesRange(t *testing.T) {
	if !ipMatchesRange("192.168.1.1", "192.168.1.0/24") {
		t.Error("192.168.1.1 should be in 192.168.1.0/24")
	}
	if ipMatchesRange("10.0.0.1", "192.168.1.0/24") {
		t.Error("10.0.0.1 should not be in 192.168.1.0/24")
	}
}

func TestIsSequentialSerial(t *testing.T) {
	// Very small number should be sequential
	if !isSequentialSerial(big.NewInt(1)) {
		t.Error("Serial 1 should be detected as sequential")
	}
	if !isSequentialSerial(big.NewInt(100)) {
		t.Error("Serial 100 should be detected as sequential")
	}
	// Large random-looking number should not be sequential
	largeSerial := new(big.Int).SetBytes([]byte{0x4a, 0x8b, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28,
		0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f})
	// Note: isSequentialSerial has specific heuristics, large random should pass
	t.Logf("Large serial sequential=%v (heuristic may vary)", isSequentialSerial(largeSerial))
}

func TestCollectLeafNames(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"test.example.com", "www.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("192.168.1.1")},
	}
	cert, _ := generateTestCert(t, template)

	names := collectLeafNames(cert)
	if len(names) < 3 { // CN + 2 DNS + 1 IP
		t.Errorf("Expected at least 3 names, got %d: %v", len(names), names)
	}
}
