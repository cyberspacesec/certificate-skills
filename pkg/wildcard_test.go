package pkg

import (
	"testing"
)

func TestClassifySANEntry(t *testing.T) {
	tests := []struct {
		sanType     string
		value       string
		isWildcard  bool
		wildcardLvl int
		baseDomain  string
	}{
		{"DNS", "example.com", false, 0, ""},
		{"DNS", "*.example.com", true, 1, "example.com"},
		{"DNS", "*.sub.example.com", true, 1, "sub.example.com"},
		{"IP", "192.168.1.1", false, 0, ""},
	}

	for _, tc := range tests {
		entry := classifySANEntry(tc.sanType, tc.value)
		if entry.IsWildcard != tc.isWildcard {
			t.Errorf("classifySANEntry(%q, %q).IsWildcard = %v, want %v", tc.sanType, tc.value, entry.IsWildcard, tc.isWildcard)
		}
		if entry.WildcardLevel != tc.wildcardLvl {
			t.Errorf("classifySANEntry(%q, %q).WildcardLevel = %d, want %d", tc.sanType, tc.value, entry.WildcardLevel, tc.wildcardLvl)
		}
		if entry.BaseDomain != tc.baseDomain {
			t.Errorf("classifySANEntry(%q, %q).BaseDomain = %q, want %q", tc.sanType, tc.value, entry.BaseDomain, tc.baseDomain)
		}
	}
}

func TestAssessWildcardRisk(t *testing.T) {
	tests := []struct {
		name      string
		result    *WildcardResult
		wantLevel string
	}{
		{
			name:      "no wildcard",
			result:    &WildcardResult{IsWildcard: false},
			wantLevel: "None",
		},
		{
			name:      "single wildcard one domain",
			result:    &WildcardResult{IsWildcard: true, WildcardLevel: 1, CoveredDomains: []string{"example.com"}, ExactNames: []string{"a", "b"}},
			wantLevel: "Low",
		},
		{
			name:      "wildcard many domains",
			result:    &WildcardResult{IsWildcard: true, WildcardLevel: 1, CoveredDomains: []string{"a.com", "b.com", "c.com", "d.com"}, ExactNames: []string{"x"}},
			wantLevel: "High",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			level, _ := assessWildcardRisk(tc.result)
			if level != tc.wantLevel {
				t.Errorf("assessWildcardRisk() = %q, want %q", level, tc.wantLevel)
			}
		})
	}
}

func TestExtractCN(t *testing.T) {
	tests := []struct {
		subject string
		want    string
	}{
		{"CN=example.com,O=Org", "example.com"},
		{"O=Org,CN=test.com", "test.com"},
		{"O=Org", ""},
		{"", ""},
	}

	for _, tc := range tests {
		got := extractCN(tc.subject)
		if got != tc.want {
			t.Errorf("extractCN(%q) = %q, want %q", tc.subject, got, tc.want)
		}
	}
}

func TestUniqueStrings(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b"}
	result := uniqueStrings(input)
	if len(result) != 3 {
		t.Errorf("Expected 3 unique strings, got %d", len(result))
	}
}

func TestCheckWildcardLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := CheckWildcard("google.com:443")
	if err != nil {
		t.Fatalf("CheckWildcard failed: %v", err)
	}
	if result.Error != "" {
		t.Logf("Wildcard check error (may be network-related): %s", result.Error)
		return
	}
	t.Logf("IsWildcard=%v RiskLevel=%s", result.IsWildcard, result.RiskLevel)
}
