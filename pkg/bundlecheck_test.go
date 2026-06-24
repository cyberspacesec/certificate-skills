package pkg

import (
	"encoding/pem"
	"os"
	"testing"
)

func TestCheckBundleCompletenessLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}
	result, err := CheckBundleCompleteness("google.com:443")
	if err != nil {
		t.Fatalf("CheckBundleCompleteness failed: %v", err)
	}
	if result.Target != "google.com:443" {
		t.Errorf("Expected target 'google.com:443', got '%s'", result.Target)
	}
	t.Logf("Chain complete=%v length=%d", result.ChainComplete, result.ChainLength)
}

func TestParseCertFromPEM(t *testing.T) {
	cert, _ := generateTestCert(t, nil)

	// Encode to PEM
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if pemData == nil {
		t.Fatal("Failed to encode certificate to PEM")
	}

	parsed, err := parseCertFromPEM(pemData)
	if err != nil {
		t.Fatalf("parseCertFromPEM failed: %v", err)
	}
	if parsed.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CN 'test.example.com', got '%s'", parsed.Subject.CommonName)
	}
}

func TestParseCertFromPEM_InvalidData(t *testing.T) {
	_, err := parseCertFromPEM([]byte("not a PEM block"))
	if err == nil {
		t.Error("Expected error for invalid PEM data")
	}
}

func TestParseCertFromPEM_InvalidDER(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid DER data"),
	})
	_, err := parseCertFromPEM(pemData)
	if err == nil {
		t.Error("Expected error for invalid DER in PEM")
	}
}

func TestFetchIntermediateFromAIA_InvalidURL(t *testing.T) {
	_, err := fetchIntermediateFromAIA("http://localhost:1/nonexistent")
	if err == nil {
		t.Error("Expected error for invalid AIA URL")
	}
}

func TestBundleCheckResult_Fields(t *testing.T) {
	result := &BundleCheckResult{
		Target:        "example.com",
		ChainComplete: true,
		ChainLength:   3,
		CanAIAFill:    false,
	}

	if result.Target != "example.com" {
		t.Error("Target field mismatch")
	}
	if !result.ChainComplete {
		t.Error("ChainComplete should be true")
	}
	if result.ChainLength != 3 {
		t.Error("ChainLength should be 3")
	}
}

func TestMissingIntermediate_Fields(t *testing.T) {
	mi := MissingIntermediate{
		Subject:      "Test Issuer",
		Issuer:       "Test Issuer",
		AIAIssuerURL: "http://example.com/ca.crt",
		FetchStatus:  "available",
	}
	if mi.FetchStatus != "available" {
		t.Error("FetchStatus mismatch")
	}
}

func TestCheckBundleCompleteness_WithLocalCert(t *testing.T) {
	// Generate a cert and save it
	req := CertificateRequest{
		CommonName:   "bundle-test",
		KeyType:      "rsa",
		KeySize:      2048,
		ValidityDays: 365,
		DNSNames:     []string{"bundle-test.local"},
	}
	result, err := GenerateSelfSignedCert(req)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	defer os.Remove(result.CertificatePath)
	defer os.Remove(result.PrivateKeyPath)

	// Verify the cert file was created
	if _, err := os.Stat(result.CertificatePath); os.IsNotExist(err) {
		t.Fatal("Certificate file was not created")
	}

	// Read it back and verify PEM parsing works
	data, err := os.ReadFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("Expected PEM type CERTIFICATE, got %s", block.Type)
	}
}
