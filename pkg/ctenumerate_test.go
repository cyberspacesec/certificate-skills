package pkg

import (
	"testing"
)

func TestExtractCTOrganization(t *testing.T) {
	tests := []struct {
		issuer   string
		expected string
	}{
		{"O=DigiCert Inc, CN=DigiCert SHA2 Extended Validation Server CA", "DigiCert Inc"},
		{"CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US", "Let's Encrypt"},
		{"O=GlobalSign, CN=GlobalSign", "GlobalSign"},
		{"CN=No Org CA", ""}, // No O= field
		{"", ""},             // Empty string
	}

	for _, tc := range tests {
		result := extractCTOrganization(tc.issuer)
		if result != tc.expected {
			t.Errorf("extractCTOrganization(%q) = %q, want %q", tc.issuer, result, tc.expected)
		}
	}
}

func TestCTEnumerationResult_Fields(t *testing.T) {
	result := &CTEnumerationResult{
		Target:         "example.com",
		TotalCerts:     100,
		SubdomainCount: 50,
		ActiveCerts:    80,
		ExpiredCerts:   20,
		ByIssuer:       map[string][]string{"Test CA": {"sub.example.com"}},
		ByCA:           map[string]int{"Test CA": 10},
		Organizations:  []string{"Test CA"},
	}

	if result.Target != "example.com" {
		t.Error("Target mismatch")
	}
	if result.TotalCerts != 100 {
		t.Error("TotalCerts mismatch")
	}
	if result.SubdomainCount != 50 {
		t.Error("SubdomainCount mismatch")
	}
	if result.ActiveCerts+result.ExpiredCerts != result.TotalCerts {
		t.Error("Active + Expired should equal Total")
	}
}

func TestCTEnumerateSubdomainsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CTEnumerateSubdomains("google.com")
	if err != nil {
		t.Fatalf("CTEnumerateSubdomains failed: %v", err)
	}
	if result.Target != "google.com" {
		t.Errorf("Expected target 'google.com', got '%s'", result.Target)
	}
	t.Logf("Total=%d Subdomains=%d Wildcards=%d",
		result.TotalCerts, result.SubdomainCount, len(result.WildcardDomains))
}
