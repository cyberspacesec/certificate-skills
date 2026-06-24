package pkg

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestKeyUsageToStrings_All(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageEncipherOnly |
			x509.KeyUsageDecipherOnly,
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}
	cert, _ := generateTestCert(t, template)

	usages := keyUsageToStrings(cert)
	expected := []string{
		"digitalSignature", "contentCommitment", "keyEncipherment",
		"dataEncipherment", "keyAgreement", "keyCertSign",
		"cRLSign", "encipherOnly", "decipherOnly",
	}
	if len(usages) != len(expected) {
		t.Errorf("Expected %d key usage strings, got %d: %v", len(expected), len(usages), usages)
	}
	for _, e := range expected {
		found := false
		for _, u := range usages {
			if u == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected key usage '%s' not found in %v", e, usages)
		}
	}
}

func TestExtKeyUsageToStrings_All(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageTimeStamping,
			x509.ExtKeyUsageOCSPSigning,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}
	cert, _ := generateTestCert(t, template)

	usages := extKeyUsageToStrings(cert)
	if len(usages) != 6 {
		t.Errorf("Expected 6 EKU strings, got %d: %v", len(usages), usages)
	}

	// Verify known EKU strings
	expectedEKUs := []string{"serverAuth", "clientAuth", "codeSigning",
		"emailProtection", "timeStamping", "ocspSigning"}
	for _, e := range expectedEKUs {
		found := false
		for _, u := range usages {
			if u == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected EKU '%s' in %v", e, usages)
		}
	}
}

func TestExtKeyUsageToStrings_Unknown(t *testing.T) {
	// Test the unknown EKU path directly via the function
	// (x509.CreateCertificate rejects unknown EKU values)
	cert := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsage(9999)},
	}
	usages := extKeyUsageToStrings(cert)
	if len(usages) != 1 {
		t.Fatalf("Expected 1 EKU, got %d", len(usages))
	}
	if usages[0] != "unknown(9999)" {
		t.Errorf("Expected 'unknown(9999)', got '%s'", usages[0])
	}
}

func TestCheckKeyUsageComplianceLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckKeyUsageCompliance("google.com:443")
	if err != nil {
		t.Fatalf("CheckKeyUsageCompliance failed: %v", err)
	}
	t.Logf("Compliant=%v IsCA=%v KeyUsage=%v ExtKeyUsage=%v",
		result.IsCompliant, result.IsCA, result.KeyUsage, result.ExtKeyUsage)
}
