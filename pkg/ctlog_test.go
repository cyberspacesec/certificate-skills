package pkg

import (
	"testing"
)

func TestCleanIssuerName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"O=DigiCert Inc, CN=DigiCert CA", "O=DigiCert Inc, CN=DigiCert CA"},
		{"O=DigiCert Inc,  CN=DigiCert CA", "O=DigiCert Inc, CN=DigiCert CA"}, // double space
		{"  O=Test  ,  CN=Test CA  ", "O=Test, CN=Test CA"},                   // leading/trailing
		{"", ""}, // empty
	}

	for _, tc := range tests {
		result := cleanIssuerName(tc.input)
		if result != tc.expected {
			t.Errorf("cleanIssuerName(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestCTSearchResult_Fields(t *testing.T) {
	result := &CTSearchResult{
		Target:     "example.com",
		TotalCount: 10,
		Certificates: []CTCert{
			{CommonName: "example.com", Issuer: "Test CA"},
		},
	}

	if result.Target != "example.com" {
		t.Error("Target mismatch")
	}
	if result.TotalCount != 10 {
		t.Error("TotalCount mismatch")
	}
	if len(result.Certificates) != 1 {
		t.Error("Expected 1 certificate")
	}
}

func TestCTCert_Fields(t *testing.T) {
	cert := CTCert{
		Issuer:            "Test CA",
		CommonName:        "example.com",
		NameValue:         "example.com\nwww.example.com",
		NotBefore:         "2024-01-01",
		NotAfter:          "2025-01-01",
		SerialNumber:      "123456",
		FingerprintSHA256: "abc123",
		IssuerCAID:        100,
		IssuerName:        "Test CA",
	}

	if cert.CommonName != "example.com" {
		t.Error("CommonName mismatch")
	}
	if cert.IssuerCAID != 100 {
		t.Error("IssuerCAID mismatch")
	}
}

func TestCTSearchLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CTSearch("google.com")
	if err != nil {
		t.Fatalf("CTSearch failed: %v", err)
	}
	if result.Target != "google.com" {
		t.Errorf("Expected target 'google.com', got '%s'", result.Target)
	}
	t.Logf("Total=%d", result.TotalCount)
}

func TestCTSearchByFingerprintLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	// Use a known Google certificate fingerprint (may not return results depending on crt.sh)
	result, err := CTSearchByFingerprint("aabbccdd")
	if err != nil {
		t.Fatalf("CTSearchByFingerprint failed: %v", err)
	}
	t.Logf("Search by fingerprint: Total=%d", result.TotalCount)
}
