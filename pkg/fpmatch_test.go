package pkg

import (
	"encoding/json"
	"testing"
)

func TestMatchHash_BuiltinDB(t *testing.T) {
	matches := matchHash("jarm", "29d29d15d29d29d21c29d29d29d29dea0f89a2e5e6f1eadc8e8d8e8d8e8d05")
	if len(matches) == 0 {
		t.Error("expected to find Cloudflare JARM match")
	}
	if matches[0].Category != "cdn" {
		t.Errorf("expected category 'cdn', got %q", matches[0].Category)
	}
}

func TestMatchHash_NoMatch(t *testing.T) {
	matches := matchHash("jarm", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if len(matches) != 0 {
		t.Error("expected no matches for unknown hash")
	}
}

func TestMatchHash_WithColons(t *testing.T) {
	// Test that colons in the hash are normalized
	matches := matchHash("jarm", "29:d2:9d:15:d2:9d:29:d2:1c:29:d2:9d:29:d2:9d:ea:0f:89:a2:e5:e6:f1:ea:dc:8e:8d:8e:8d:8e:8d:05")
	if len(matches) == 0 {
		t.Error("expected match even with colon-separated hash")
	}
}

func TestMatchFingerprintByHash(t *testing.T) {
	matches := MatchFingerprintByHash("jarm", "29d29d15d29d29d21c29d29d29d29dea0f89a2e5e6f1eadc8e8d8e8d8e8d05")
	if len(matches) == 0 {
		t.Error("MatchFingerprintByHash should find matches")
	}
}

func TestLoadFingerprintDB(t *testing.T) {
	initialLen := len(fingerprintDB)

	customDB := []FingerprintMatch{
		{Type: "jarm", Hash: "customhash123", Label: "Test Service", Category: "other", Confidence: 0.9, Source: "test"},
	}
	data, err := json.Marshal(customDB)
	if err != nil {
		t.Fatal(err)
	}

	err = LoadFingerprintDB(data)
	if err != nil {
		t.Fatalf("LoadFingerprintDB failed: %v", err)
	}

	if len(fingerprintDB) != initialLen+1 {
		t.Errorf("expected %d entries after loading, got %d", initialLen+1, len(fingerprintDB))
	}

	// Verify the custom entry can be matched
	matches := matchHash("jarm", "customhash123")
	if len(matches) == 0 {
		t.Error("custom entry should be matched after loading")
	}
	if matches[0].Source != "custom" {
		t.Errorf("source should be 'custom', got %q", matches[0].Source)
	}

	// Clean up - remove the custom entry
	fingerprintDB = fingerprintDB[:initialLen]
}

func TestLoadFingerprintDB_InvalidJSON(t *testing.T) {
	err := LoadFingerprintDB([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestListFingerprintDB(t *testing.T) {
	entries := ListFingerprintDB()
	if len(entries) == 0 {
		t.Error("fingerprint database should not be empty")
	}
}

func TestMatchFingerprintsByCategory(t *testing.T) {
	matches := MatchFingerprintsByCategory("cdn")
	if len(matches) == 0 {
		t.Error("expected at least one CDN match")
	}
	for _, m := range matches {
		if m.Category != "cdn" {
			t.Errorf("expected category 'cdn', got %q", m.Category)
		}
	}
}

func TestComputeCertSPKIHash(t *testing.T) {
	cert, _ := generateTestCert(t, nil)
	hash := ComputeCertSPKIHash(cert)
	if hash == "" {
		t.Error("SPKI hash should not be empty")
	}
	if len(hash) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("SPKI hash should be 64 hex chars, got %d", len(hash))
	}
}
