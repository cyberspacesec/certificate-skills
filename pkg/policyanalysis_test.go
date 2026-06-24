package pkg

import (
	"testing"
)

func TestDetermineValidationType(t *testing.T) {
	tests := []struct {
		name     string
		policies []PolicyOID
		expected string
	}{
		{"EV policy", []PolicyOID{{Type: "EV"}}, "EV"},
		{"OV policy", []PolicyOID{{Type: "OV"}}, "OV"},
		{"DV policy", []PolicyOID{{Type: "DV"}}, "DV"},
		{"EV+OV", []PolicyOID{{Type: "EV"}, {Type: "OV"}}, "EV"}, // EV takes precedence
		{"OV+DV", []PolicyOID{{Type: "OV"}, {Type: "DV"}}, "OV"}, // OV takes precedence
		{"Unknown", []PolicyOID{{Type: "Unknown"}}, "Unknown"},
		{"Empty", []PolicyOID{}, "Unknown"},
	}

	for _, tc := range tests {
		result := determineValidationType(tc.policies)
		if result != tc.expected {
			t.Errorf("determineValidationType(%s) = %q, want %q", tc.name, result, tc.expected)
		}
	}
}

func TestKnownPolicyOIDs(t *testing.T) {
	// Verify some well-known OIDs are present
	knownOIDs := []string{
		"2.23.140.1.2.1",        // Domain Validated (CA/B Forum)
		"2.23.140.1.2.2",        // Organization Validated (CA/B Forum)
		"2.23.140.1.1",          // Extended Validation (CA/B Forum)
		"2.16.840.1.114412.1.1", // DigiCert DV
		"2.16.840.1.114412.1.2", // DigiCert OV
		"2.16.840.1.114412.1.3", // DigiCert EV
	}

	for _, oid := range knownOIDs {
		if _, ok := knownPolicyOIDs[oid]; !ok {
			t.Errorf("Expected known OID %s in knownPolicyOIDs", oid)
		}
	}
}

func TestPolicyAnalysisResult_Fields(t *testing.T) {
	result := &PolicyAnalysisResult{
		Target:         "example.com",
		ValidationType: "DV",
		PolicyOIDs:     []PolicyOID{{OID: "2.23.140.1.2.1", Description: "Domain Validated", Type: "DV"}},
		HasPolicies:    true,
		IsCompliant:    true,
	}
	if result.ValidationType != "DV" {
		t.Error("ValidationType mismatch")
	}
	if !result.HasPolicies {
		t.Error("HasPolicies should be true")
	}
}

func TestCheckPolicyAnalysisLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckPolicyAnalysis("google.com:443")
	if err != nil {
		t.Fatalf("CheckPolicyAnalysis failed: %v", err)
	}
	t.Logf("ValidationType=%s HasPolicies=%v OIDs=%d",
		result.ValidationType, result.HasPolicies, len(result.PolicyOIDs))
}
