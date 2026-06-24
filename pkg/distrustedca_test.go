package pkg

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestMatchDistrustedCA_DigiNotar(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "DigiNotar Root CA",
			Organization: []string{"DigiNotar"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	cert, _ := generateTestCert(t, template)

	result := matchDistrustedCA(cert)
	if result == nil {
		t.Error("Expected DigiNotar to be detected as distrusted")
	} else {
		if result.Name != "DigiNotar" {
			t.Errorf("Expected name 'DigiNotar', got '%s'", result.Name)
		}
		if result.Severity != "Critical" {
			t.Errorf("Expected severity 'Critical', got '%s'", result.Severity)
		}
	}
}

func TestMatchDistrustedCA_CleanCert(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Legitimate Corp"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}
	cert, _ := generateTestCert(t, template)

	result := matchDistrustedCA(cert)
	if result != nil {
		t.Error("Legitimate cert should not match distrusted CA")
	}
}

func TestMatchDistrustedCA_CNNIC(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "CNNIC ROOT",
			Organization: []string{"China Internet Network Information Center"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	cert, _ := generateTestCert(t, template)

	result := matchDistrustedCA(cert)
	if result == nil {
		t.Error("Expected CNNIC to be detected as distrusted")
	} else if result.Severity != "Critical" {
		t.Errorf("Expected CNNIC severity 'Critical', got '%s'", result.Severity)
	}
}

func TestMatchDistrustedCA_Symantec(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Symantec Class 3 Secure Server CA",
			Organization: []string{"Symantec Corporation"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	cert, _ := generateTestCert(t, template)

	result := matchDistrustedCA(cert)
	if result == nil {
		t.Error("Expected Symantec to be detected as distrusted")
	}
}

func TestDistrustedCAResult_Fields(t *testing.T) {
	result := &DistrustedCAResult{
		Target:       "example.com",
		IsDistrusted: true,
		DistrustedCAs: []DistrustedCA{
			{Name: "DigiNotar", Severity: "Critical", Reason: "CA compromise"},
		},
	}
	if !result.IsDistrusted {
		t.Error("Should be distrusted")
	}
	if len(result.DistrustedCAs) != 1 {
		t.Error("Expected 1 distrusted CA")
	}
}

func TestCheckDistrustedCALive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckDistrustedCA("google.com:443")
	if err != nil {
		t.Fatalf("CheckDistrustedCA failed: %v", err)
	}
	if result.IsDistrusted {
		t.Error("google.com should not have distrusted CAs")
	}
	t.Logf("Distrusted=%v ChainPosition count=%d", result.IsDistrusted, len(result.ChainPosition))
}
