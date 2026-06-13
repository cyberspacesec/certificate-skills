package pkg

import (
	"testing"
)

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		pattern  string
		hostname string
		match    bool
	}{
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "deep.sub.example.com", false},
		{"*.example.com", "test.example.com", true},
		{"example.com", "example.com", true},
		{"example.com", "other.com", false},
		{"*", "anything", false},
		{"", "anything", false},
	}

	for _, tc := range tests {
		got := matchWildcard(tc.pattern, tc.hostname)
		if got != tc.match {
			t.Errorf("matchWildcard(%q, %q) = %v, want %v", tc.pattern, tc.hostname, got, tc.match)
		}
	}
}

func TestDomainSimilarity(t *testing.T) {
	tests := []struct {
		a   string
		b   string
		min int // minimum expected score
	}{
		{"www.example.com", "api.example.com", 2},
		{"example.com", "other.com", 1},
		{"a.b.c.com", "x.y.c.com", 1},
		{"test.org", "prod.net", 0},
	}

	for _, tc := range tests {
		score := domainSimilarity(tc.a, tc.b)
		if score < tc.min {
			t.Errorf("domainSimilarity(%q, %q) = %d, want >= %d", tc.a, tc.b, score, tc.min)
		}
	}
}

func TestVerifyHostnameLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	result, err := VerifyHostname("google.com:443")
	if err != nil {
		t.Fatalf("VerifyHostname failed: %v", err)
	}
	if result.Error != "" {
		t.Logf("Hostname verify error (network): %s", result.Error)
		return
	}
	if !result.IsValid {
		t.Errorf("Expected google.com hostname to be valid")
	}
	if result.MatchType != "exact" && result.MatchType != "wildcard" {
		t.Errorf("Expected match type exact or wildcard, got %s", result.MatchType)
	}
}
