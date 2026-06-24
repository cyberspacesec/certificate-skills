package pkg

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestCompareCerts_IdenticalCerts(t *testing.T) {
	cert, _ := generateTestCert(t, nil)

	comparison := CompareCerts(cert, cert)

	if !comparison.Match {
		t.Error("comparing a cert with itself should match")
	}
	if !comparison.MatchDetails.SHA256Match {
		t.Error("SHA256 should match for identical certs")
	}
	if !comparison.MatchDetails.SubjectMatch {
		t.Error("Subject should match for identical certs")
	}
	if !comparison.MatchDetails.IssuerMatch {
		t.Error("Issuer should match for identical certs")
	}
	if !comparison.MatchDetails.PublicKeyMatch {
		t.Error("PublicKey should match for identical certs")
	}
	if len(comparison.Differences) > 0 {
		t.Errorf("expected no differences, got %d", len(comparison.Differences))
	}
}

func TestCompareCerts_DifferentCerts(t *testing.T) {
	template1 := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{"example.com"},
	}
	cert1, _ := generateTestCert(t, template1)

	template2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "other.com"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{"other.com"},
	}
	cert2, _ := generateTestCert(t, template2)

	comparison := CompareCerts(cert1, cert2)

	if comparison.Match {
		t.Error("different certs should not match")
	}
	if comparison.MatchDetails.SHA256Match {
		t.Error("SHA256 should not match for different certs")
	}
	if comparison.MatchDetails.SubjectMatch {
		t.Error("Subject should not match for different certs")
	}
	if len(comparison.Differences) == 0 {
		t.Error("expected differences for different certs")
	}
}

func TestCompareCerts_SameSubjectDifferentKey(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{"example.com"},
	}
	// Two certs with same subject but generated independently (different keys)
	cert1, _ := generateTestCert(t, template)
	cert2, _ := generateTestCert(t, template)

	comparison := CompareCerts(cert1, cert2)

	if comparison.Match {
		t.Error("certs with different keys should not match")
	}
	if !comparison.MatchDetails.SubjectMatch {
		t.Error("Subject should match when common name is the same")
	}
	if comparison.MatchDetails.PublicKeyMatch {
		t.Error("PublicKey should not match for different keys")
	}
}
