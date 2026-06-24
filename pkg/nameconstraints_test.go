package pkg

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestCollectLeafNames_NC(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:      time.Now().Add(-24 * time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		DNSNames:       []string{"test.example.com", "www.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1")},
		EmailAddresses: []string{"admin@example.com"},
	}
	cert, _ := generateTestCert(t, template)

	names := collectLeafNames(cert)
	// CN + 2 DNS + 1 IP + 1 Email = 5
	if len(names) < 4 {
		t.Errorf("Expected at least 4 names, got %d: %v", len(names), names)
	}
}

func TestExtractCAConstraint_NoConstraints(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	cert, _ := generateTestCert(t, template)

	result := extractCAConstraint(cert, 1)
	if result != nil {
		t.Error("Cert without constraints should return nil")
	}
}

func TestViolatesExcluded(t *testing.T) {
	constraint := &CAConstraint{
		ExcludedDNS: []string{".evil.com", "bad.org"},
		ExcludedIPs: []string{"10.0.0.0/8"},
	}

	tests := []struct {
		name     string
		expected bool
	}{
		{"www.evil.com", true}, // matches .evil.com
		{"evil.com", true},     // matches .evil.com (TLD match)
		{"safe.example.com", false},
		{"bad.org", true},      // exact match
		{"10.1.2.3", true},     // in excluded IP range
		{"192.168.1.1", false}, // not in excluded IP range
	}

	for _, tc := range tests {
		result := violatesExcluded(tc.name, constraint)
		if result != tc.expected {
			t.Errorf("violatesExcluded(%q) = %v, want %v", tc.name, result, tc.expected)
		}
	}
}

func TestViolatesNotPermitted(t *testing.T) {
	constraint := &CAConstraint{
		PermittedDNS: []string{".example.com"},
		PermittedIPs: []string{"192.168.1.0/24"},
	}

	tests := []struct {
		name     string
		expected bool
	}{
		{"www.example.com", false}, // matches permitted
		{"other.com", true},        // not in permitted DNS
		{"192.168.1.1", false},     // in permitted IP range
		{"10.0.0.1", true},         // IP not in permitted range
	}

	for _, tc := range tests {
		result := violatesNotPermitted(tc.name, constraint)
		if result != tc.expected {
			t.Errorf("violatesNotPermitted(%q) = %v, want %v", tc.name, result, tc.expected)
		}
	}
}

func TestViolatesNotPermitted_NoPermitted(t *testing.T) {
	// When no permitted names are set, everything is permitted
	constraint := &CAConstraint{}
	if violatesNotPermitted("anything.com", constraint) {
		t.Error("With no permitted names, everything should be permitted")
	}
}

func TestFormatConstraint(t *testing.T) {
	c := &CAConstraint{
		PermittedDNS: []string{".example.com"},
		ExcludedDNS:  []string{".evil.com"},
	}
	result := formatConstraint(c)
	if result == "" {
		t.Error("formatConstraint should not return empty string")
	}
}

func TestNameMatchesPattern_NC(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		expected bool
	}{
		{"www.example.com", ".example.com", true},
		{"example.com", ".example.com", true}, // TLD matches pattern without prefix
		{"other.com", ".example.com", false},
		{"sub.example.com", "example.com", true}, // subdomain of pattern
		{"example.com", "example.com", true},     // exact match
		{"other.com", "example.com", false},
	}

	for _, tc := range tests {
		result := nameMatchesPattern(tc.name, tc.pattern)
		if result != tc.expected {
			t.Errorf("nameMatchesPattern(%q, %q) = %v, want %v", tc.name, tc.pattern, result, tc.expected)
		}
	}
}

func TestCheckNameConstraintsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckNameConstraints("google.com:443")
	if err != nil {
		t.Fatalf("CheckNameConstraints failed: %v", err)
	}
	t.Logf("HasConstraints=%v IsCompliant=%v", result.HasConstraints, result.IsCompliant)
}
